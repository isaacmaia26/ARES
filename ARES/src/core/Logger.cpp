#include "Logger.h"

Logger::Logger() {}
Logger::~Logger() {}

void Logger::Log(const std::string& msg, const std::string& level)
{
    logs.push_back("[" + level + "] " + msg);
}

const std::vector<std::string>& Logger::GetLogs() const
{
    return logs;
}
