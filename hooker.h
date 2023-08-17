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

struct injection_instance
{
	pid_t pid;
	string ts;
	FridaSession* session = nullptr;
	FridaScript* script = nullptr;
	~injection_instance()
	{
		if (script) 
		{
			frida_script_unload_sync(script, nullptr, nullptr);
			frida_unref(script);
		}

		if (session)
		{
			frida_session_detach_sync(session, nullptr, nullptr);
			frida_unref(session);
		}
		script = nullptr;
		session = nullptr;
	}
};

class Injector
{
public:
	std::atomic<bool> need_update;

	Injector() { need_update = false; } // do nothing

	int init();
	void append(const pid_t pid, const string& ts);
	void attach();
	int query(const pid_t pid);

	void event_loop() const;
	~Injector();

	void on_session_detach(
		FridaSession* session,
		FridaSessionDetachReason reason,
		FridaCrash* crash
	);
	void on_message(FridaScript* script, const gchar* message, GBytes* data);
	void terminate();
	void update();

private:
	FridaDevice* local_device = nullptr;
	FridaDeviceManager* device_manager = nullptr;
	GMainLoop* loop = nullptr;
	FridaScriptOptions* options = nullptr;

	std::mutex list_lock;
	list<injection_instance> injectors;
	int remove_injector_by_session(FridaSession* session);
};