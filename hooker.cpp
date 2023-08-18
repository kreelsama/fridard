#include "hooker.h"
#include <iostream>

extern logger_t logger;

static void  on_detached_wrapper(
    FridaSession* session,
    FridaSessionDetachReason reason,
    FridaCrash* crash,
    gpointer user_data)
{
    auto injector = reinterpret_cast<Injector*>(user_data);
    injector->on_session_detach(session, reason, crash);
}

static void on_message_wrapper(FridaScript* script,
    const gchar* message,
    GBytes* data,
    gpointer user_data) {
    auto injector = reinterpret_cast<Injector*>(user_data);
    injector->on_message(script, message, data);
}

int Injector::init() {
    FridaDeviceList* devices = nullptr;
    GError* error = nullptr;

    frida_init();

    device_manager = frida_device_manager_new();

    devices = frida_device_manager_enumerate_devices_sync(device_manager, nullptr, &error);
    if (error) {
        LOGE("Fail to open device manager: {}", error->message);
        g_error_free(error);
        return NO_LOCAL_DEVICE;
    }

    auto num_devices = frida_device_list_size(devices);
    for (decltype(num_devices) i = 0; i < num_devices && !local_device; i++)
    {
        FridaDevice* device = frida_device_list_get(devices, i);
        if (frida_device_get_dtype(device) == FRIDA_DEVICE_TYPE_LOCAL) {
            local_device = g_object_ref(device);
        }
        g_object_unref(device);
    }
    frida_unref(devices);

    options = frida_script_options_new();
    frida_script_options_set_name(options, "default");
    frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS);

    loop = g_main_loop_new(nullptr, true);
    
	if (local_device)
        return SUCCESS;
    else
        return NO_LOCAL_DEVICE;
}

void Injector::append(const pid_t pid, const string& ts)
{
    list_lock.lock();
    // to be injected
    if (!query(pid)) {
        injectors.push_back({ pid, ts, nullptr, nullptr, false});
    }
    list_lock.unlock();
}

void Injector::attach()
{
    GError* error;
    decltype(injectors) reattach_processes;
    list_lock.lock();
    for (auto&& injector = injectors.begin(); injector != injectors.end(); /*increment inside*/) 
    {
        // reason for incrementing inside:
        // erasing a list node while iterating may cause undefined behavior
        // such that:
        //      x = list.begin();
        //      list.erase(x);
        //      x++ /*undefined behavior, because x is now already invalidated*/
        // The correct way:
        //      x = list.begin;
        //      x = list.erase(x); /*erase will return spawn next iter on return*/
        // No more x++ needed;
        error = nullptr;
        const pid_t target_pid = injector->pid;
        string& ts = injector->ts;

        if (injector->to_reattach)
        {
            goto attach_failed;
        }

        if (injector->session) 
        {
            ++ injector;
            continue;
        }
        LOGD("tring to attach PID={}", target_pid);

        injector->session = frida_device_attach_sync(local_device, target_pid, nullptr, nullptr, &error);
        if(error) 
            goto attach_failed;
        
        injector->script = frida_session_create_script_sync(injector->session, ts.c_str(), options, nullptr, &error);
        if(error)
            goto attach_failed;
        g_signal_connect(injector->script, "message", G_CALLBACK(on_message_wrapper), this);

        frida_script_load_sync(injector->script, nullptr, &error);
        if (error)
            goto attach_failed;

        
        g_signal_connect(injector->session, "detached", G_CALLBACK(on_detached_wrapper), this);

        LOGI("PID={} attached", target_pid);

        ++injector;
        continue;

	attach_failed:
        if (!injector->to_reattach) 
        {
            LOGW("Failed to attach PID={} : {}", target_pid, error->message);
            g_error_free(error);
            // cleanup will be automatically performed
            injector = injectors.erase(injector);
        }
    	else
        {
            LOGI("Reattaching process PID={}", target_pid);
            // NOT incrementing the iter on purpose, letting it to inject again
            injector->detach();
            injector->to_reattach = false;
        }
    }
    list_lock.unlock();
}

int Injector::query(const pid_t pid)
{
    for (const auto& injector : injectors)
    {
        if (injector.pid == pid) {
            return true;
        }
    }
    return false;
}

void Injector::event_loop() const
{
    if (g_main_loop_is_running(loop))
        g_main_loop_run(loop);
}

Injector::~Injector() {
    GError* error = nullptr;
    frida_unref(local_device);
    frida_device_manager_close_sync(device_manager, nullptr, &error);
    frida_unref(device_manager);
    if (error) {
        LOGE("Fail to close device manager: {}", error->message);
        g_error_free(error);
    }
    if(options)
	    g_clear_object(&options);
    LOGI("Injector shutting down...");
    frida_shutdown();
}

void Injector::update()
{
    if (!need_update) {
    	return;
    }
	// Here we assume new pid/ts has been placed in injector list
    attach();
    need_update = false;
}

void Injector::reattach(const pid_t pid, const string& ts)
{
    list_lock.lock();
    if (!query(pid)) {
        LOGW("Process with PID={} has no injection instance, attaching now.", pid);
        injectors.push_back( {pid, ts, nullptr, nullptr, false} );
    }
    else
    {
        for (auto&& injector = injectors.begin(); injector != injectors.end(); ++injector)
        {
	        if(injector->pid == pid)
	        {
                injector->to_reattach = true;
                break;
	        }
        }
    }
    list_lock.unlock();
}

int Injector::remove_injector_by_session(const FridaSession* session)
{
    list_lock.lock();
    for (auto injector = injectors.begin(); injector != injectors.end(); ++injector)
    {
	    if (injector->session == session)
	    {
            LOGI("Injector for PID={} detached", injector->pid);
            injectors.erase(injector);
            list_lock.unlock();
            return true;
	    }
    }
    list_lock.unlock();
    return false;
}

void Injector::on_session_detach(const FridaSession* session, const FridaSessionDetachReason reason, FridaCrash* crash)
{
	gchar* reason_str = g_enum_to_string(FRIDA_TYPE_SESSION_DETACH_REASON, reason);
    LOGI("on_detached: reason = {}", reason_str);
    g_free(reason_str);

    // only remain attached normal program quitting
    if(reason != FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED)
		remove_injector_by_session(session);
}

void Injector::on_message(FridaScript* script,
    const gchar* message,
    GBytes* data)
{
	JsonParser* parser = json_parser_new();
    json_parser_load_from_data(parser, message, -1, nullptr);
    JsonObject* root = json_node_get_object(json_parser_get_root(parser));

    const gchar* type = json_object_get_string_member(root, "type");
    if (strcmp(type, "log") == 0)
    {
	    const gchar* log_message = json_object_get_string_member(root, "payload");
        g_print("%s\n", log_message);
    }
    else
    {
        g_print("on_message: %s\n", message);
    }

    g_object_unref(parser);
}

void Injector::terminate()
{
    if (g_main_loop_is_running(loop))
        g_main_loop_quit(loop);
    list_lock.lock();
    for (auto injector = injectors.begin(); injector != injectors.end(); injector = injectors.erase(injector));
    list_lock.unlock();
}