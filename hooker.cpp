#include "hooker.h"

extern logger_t logger;

FridaDevice* device;

FridaDevice* get_current_device()
{
    return device;
}

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

static void on_child_added_wrapper(FridaDevice* device, FridaChild* child_process, gpointer user_data)
{
    LOGD("Enter child created");
    auto injector = reinterpret_cast<Injector*>(user_data);
    injector->on_child_created(device, child_process);
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

    if (local_device) {
        LOGI("Found local device");
        g_signal_connect(local_device, "child-added", GCallback(on_child_added_wrapper), this);
        device = local_device;
    	return SUCCESS;
    }
    else
        return NO_LOCAL_DEVICE;
}

void Injector::append(const pid_t pid, const string& js, bool suspended)
{
    std::lock_guard<std::mutex> lk(access_lock);
    // to be injected
    if (!query(pid)) {
        injectors.push_back({ pid, js, nullptr, nullptr, false, suspended});
    }
}

void Injector::attach()
{
    GError* error;
    decltype(injectors) reattach_processes;
    std::lock_guard<std::mutex> lk(access_lock);
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
            LOGI("Reattaching process PID={}", target_pid);
            // NOT incrementing the iter on purpose, letting it to inject again
            injector->detach();
            injector->to_reattach = false;
            continue;
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

        frida_session_enable_child_gating(injector->session, nullptr, nullptr, nullptr);
        
        injector->script = frida_session_create_script_sync(injector->session, ts.c_str(), options, nullptr, &error);
        if(error)
            goto attach_failed;

        g_signal_connect(injector->script, "message", G_CALLBACK(on_message_wrapper), this);

        frida_script_load_sync(injector->script, nullptr, &error);
        if (error)
            goto attach_failed;

        
        g_signal_connect(injector->session, "detached", G_CALLBACK(on_detached_wrapper), this);

        LOGI("PID={} attached", target_pid);

        if(injector->suspended)
        {   // resume execution
            frida_device_resume(local_device, target_pid, nullptr, nullptr, nullptr);
            injector->suspended = false;
        }

        ++injector;
        continue;

	attach_failed:
        LOGW("Failed to attach PID={} : {}", target_pid, error->message);
        g_error_free(error);
        // cleanup will be automatically performed
        injector = injectors.erase(injector);
    }
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
    device = nullptr;
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
    LOGD("updating injector list");
	// Here we assume new pid/ts has been placed in injector list
    attach();
    need_update = false;
}

void Injector::reattach(const pid_t pid, const string& ts)
{
    std::lock_guard<std::mutex> lk(access_lock);
    if (!query(pid)) {
        LOGW("Process with PID={} has no injection instance, attaching now.", pid);
        injectors.push_back( {pid, ts, nullptr, nullptr, false, false} );
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
}

int Injector::remove_injector_by_session(const FridaSession* session)
{
    std::lock_guard<std::mutex> lk(access_lock);
    for (auto&& injector = injectors.begin(); injector != injectors.end(); ++injector)
    {
	    if (injector->session == session)
	    {
            injectors.erase(injector);
            LOGI("Injector for PID={} detached", injector->pid);
            return true;
	    }
    }
    return false;
}

void Injector::on_child_created(FridaDevice* device, FridaChild* child)
{
    const pid_t pid = frida_child_get_pid(child);
    const pid_t ppid = frida_child_get_parent_pid(child);
    gint argc;
    gchar** argv = frida_child_get_argv(child, &argc);
    const gchar* path = frida_child_get_path(child);

    auto desc = new_pid_desc(pid, ppid, argc, (const char**) argv, path);

    string js = get_rule_from_pid_desc(desc);

    if(js.empty())
    {
        LOGW("Rules for pid={} is empty. Not performing injection", pid);
        frida_device_resume(local_device, pid, nullptr, nullptr, nullptr);
        return;
    }
    LOGD("attaching child pid={}", pid);
    append(pid, js, true);
    need_update = true;
    update();
    LOGD("child attach finished");
}

void Injector::on_session_detach(const FridaSession* session, FridaSessionDetachReason reason, FridaCrash* crash)
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
    else // receive on Error
    {
        LOGE("received error from script: {}", message);
    }

    g_object_unref(parser);
}

void Injector::terminate()
{
    if (g_main_loop_is_running(loop))
        g_main_loop_quit(loop);
    std::lock_guard<std::mutex> lk(access_lock);
    injectors.clear();
    // for (auto injector = injectors.begin(); injector != injectors.end(); injector = injectors.erase(injector));
}