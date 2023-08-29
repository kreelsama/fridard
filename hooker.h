#pragma once
#include "mfrida.h"
#include <string>
#include <atomic>
#include <list>
#include <mutex>

using std::string;
using std::list;

typedef struct {
	pid_t pid;
	string ts;
} rule;

FridaDevice* get_current_device();

struct injection_instance
{
	pid_t pid;
	string ts;
	FridaSession* session = nullptr;
	FridaScript* script	  = nullptr;
	bool to_reattach	  = false;
	bool suspended		  = false;
	void detach()
	{
		if (script && !frida_script_is_destroyed(script))
		{
			frida_script_unload_sync(script, nullptr, nullptr);
			frida_unref(script);
		}

		if (session && !frida_session_is_detached(session))
		{
			frida_session_detach_sync(session, nullptr, nullptr);
			frida_unref(session);
		}
		script = nullptr;
		session = nullptr;
	}

	~injection_instance()
	{
		if (suspended)
		{
			const auto logger = get_current_logger();
			FridaDevice* device = get_current_device();
			LOGW("Resuming suspended process with pid={}.", pid);
			if (device)
				frida_device_resume(device, pid, nullptr, nullptr, nullptr);
		}
		detach();
	}
};

class Injector
{
public:
	std::atomic<bool> need_update;

	Injector() { need_update = false; } // do nothing

	int init();
	void append(const pid_t pid, const string& ts, bool suspended = false);
	void attach();
	int query(const pid_t pid);

	void event_loop() const;
	~Injector();

	void on_session_detach(const FridaSession* session, FridaSessionDetachReason reason, FridaCrash* crash);
	void on_message(FridaScript* script, const gchar* message, GBytes* data);
	void on_child_created(FridaDevice* device, FridaChild* child);

	void terminate();
	void update();

	void reattach(const pid_t pid, const string& ts);

private:
	FridaDevice* local_device = nullptr;
	FridaDeviceManager* device_manager = nullptr;
	GMainLoop* loop = nullptr;
	FridaScriptOptions* options = nullptr;

	std::mutex access_lock;
	list<injection_instance> injectors;
	int remove_injector_by_session(const FridaSession* session);
};