#include "mfrida.h"

#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/basic_file_sink.h"

logger_t logger;

int logger_init()
{
	try {
#ifdef USE_CONSOLE_LOGGER
		logger = spdlog::stderr_color_mt("stderr");
#else
		logger = spdlog::basic_logger_mt("basic_logger", LOG_FILE);
#endif
	}
	catch (const spdlog::spdlog_ex& ex) {
		logger = spdlog::stderr_color_mt("stderr");
		LOGE("Log init failed: {}; falling back to stderr", ex.what());
		return false;
	}
	spdlog::set_level(spdlog::level::debug);
	LOGD("debugging info enabled");
	return true;
}