#pragma once

#ifdef RICOCHET_REFRESH_LOGGING

#define LOG_ERROR(msg) tego::log_error(msg)
#define LOG_INFO(msg) tego::log_info(msg)
#define LOG_TRACE(msg) tego::log_trace(msg, __FUNCTION__, __FILE__, static_cast<size_t>(__LINE__))

namespace tego {
    inline void log_error(std::string msg) {
        tego_log_error(msg.data(), msg.size());
    }
    inline void log_info(std::string msg) {
        tego_log_info(msg.data(), msg.size());
    }
    inline void log_trace(std::string msg, const char* function_name, const char* file_name, const size_t line) {
        tego_log_trace(msg.data(), msg.size(), function_name, strlen(function_name), file_name, strlen(file_name), line);
    }
}

#else

#define LOG_ERROR(_msg)
#define LOG_INFO(_msg)
#define LOG_TRACE(_msg)

#endif // RICOCHET_REFRESH_LOGGING
