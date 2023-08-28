#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include "frida-core.h"
#include "spdlog/spdlog.h"

#define INSTRUMENT_TEMPLATE_PATH  "main.js"

#define USE_CONSOLE_LOGGER
// #define USE_FILE_LOGGER

using pid_t = unsigned int;
using logger_t = std::shared_ptr<spdlog::logger>;

#define LOG_FILE	              "mfrida.log"
#define LOGI(...) logger->info(__VA_ARGS__)  // level: INFO
#define LOGW(...) logger->warn(__VA_ARGS__)  // level: WARNING
#define LOGE(...) logger->error(__VA_ARGS__) // level: ERROR
#define LOGD(...) logger->debug(__VA_ARGS__) // level: DEBUG
// debug info is enabled by default
int logger_init();
logger_t get_current_logger();

enum ERROR_TYPE {
	SUCCESS,
	WRONG_PARAM = -0xff,
	NO_LOCAL_DEVICE,
	INVALID_TS_SYNTAX,
	NO_SUCH_PROCESS,

	NEGLIGIBLE_ERROR = -1,
};

enum SIGNAL_TO
{
	INJECTOR,
	ELSE
};

struct pid_desc
{
	pid_t pid;
	pid_t ppid;
	int argc;
	std::vector<std::string> argv;
	std::string path;
};

pid_desc new_pid_desc(const pid_t pid, const pid_t ppid, const int argc, const char** argv, const char* path);

void sigint_handler(int signo);
std::string get_rule_from_pid_desc(const pid_desc& desc);