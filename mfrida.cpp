// Multithreaded frida test

#include "mfrida.h"
#include "hooker.h"

#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <vector>

using std::cout;
using std::cerr;
using std::endl;

extern logger_t logger;
Injector injector;
int signaled_to = 0;

static std::string load_ts();

void sigint_handler(int signo)
{
    // to ensure the subsequent SIGINT gets proper handling
    if (signaled_to == ELSE)
    {
        // allow for forcibly terminating
        injector.terminate();
    }
    else if (signaled_to == INJECTOR) {
        signal(SIGINT, sigint_handler);
        injector.update();
    }
    else {
        LOGW("Got ambiguous signal, ignoring");
    }
    signaled_to = ELSE;
}

void sigabort_handler(int signo)
{
    exit(-1);
}


void injection_begin(const Injector& injector)
{
    injector.event_loop();
}

int main(int argc, char *argv[])
{
    std::vector<pid_t> pids;
    std::string ts;

	logger_init();

    for (int i = 1; i < argc; i++) {
        pid_t pid = atoi(argv[i]);
        if (pid) {
            pids.push_back(pid);
        }
        else {
            LOGE("ignoring invalid pid: {}", fmt::ptr(argv[i]));
        }
    }

	if (pids.empty()) {
        LOGE("No pid provided.");
        LOGE("Usage: {} pid1 pid2 pid3 ... ", argv[0]);
        return WRONG_PARAM;
    }

    ts = load_ts();
    if(ts.empty())
    {
        LOGE("Unable to open typescript (or empty file content) located in {}", INSTRUMENT_TEMPLATE_PATH);
        return WRONG_PARAM;
    }
    
    signal(SIGINT, sigint_handler);

    if(injector.init())
    {
        return NO_LOCAL_DEVICE;
    }

    injector.attach();

    std::thread injecting(injection_begin, std::ref(injector));

    // perform injecting multiple processes
    for (auto&& pid : pids)
    {
        // Injecting with multi-threading
	    // std::this_thread::sleep_for(std::chrono::seconds(2));

        injector.append(pid, ts);
        injector.need_update = true;

        signaled_to = INJECTOR;
        raise(SIGINT);
    }

    // perform reattaching all processes
    //for (auto&& pid : pids)
    //{
    //    // Injecting with multi-threading
    //    std::this_thread::sleep_for(std::chrono::seconds(2));

    //    injector.reattach(pid, ts);
    //    injector.need_update = true;

    //    signaled_to = INJECTOR;
    //    raise(SIGINT);
    //}

    if(injecting.joinable())
	    injecting.join();
    LOGI("quitting main program");

    //signal(sigabrt, sigabort_handler);
    //std::thread killer([]() {
    //    std::this_thread::sleep_for(std::chrono::seconds(5));
    //    execve("taskmgr");
    //    });

	return SUCCESS;
}

static std::string load_ts() {
    std::ifstream t(INSTRUMENT_TEMPLATE_PATH);
    std::string str;

    if(!t.is_open())
    {
        return str;
    }

    t.seekg(0, std::ios::end);
    str.reserve(t.tellg());
    t.seekg(0, std::ios::beg);

    str.assign((std::istreambuf_iterator<char>(t)),
    std::istreambuf_iterator<char>());
    return str;
}