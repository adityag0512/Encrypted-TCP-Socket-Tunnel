#pragma once
#include <iostream>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <mutex>


static std::mutex log_mutex;


inline std::string current_time() {
    std::time_t now = std::time(nullptr);
    std::tm* tm_info = std::localtime(&now);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << tm_info->tm_hour << ":"
        << std::setw(2) << tm_info->tm_min  << ":"
        << std::setw(2) << tm_info->tm_sec;
    return oss.str();
}



inline void log_info(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << "[" << current_time() << "] [INFO]  " << msg << "\n";
}

inline void log_error(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cerr << "[" << current_time() << "] [ERROR] " << msg << "\n";
}

inline void log_debug(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << "[" << current_time() << "] [DEBUG] " << msg << "\n";
}

inline void log_warn(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << "[" << current_time() << "] [WARN]  " << msg << "\n";
}