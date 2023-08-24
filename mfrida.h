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