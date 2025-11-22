#include "Logger.h"
#include <ctime>

Logger::Logger(const std::string& txtFile, const std::string& jsonFile)
{
    txt.open(txtFile, std::ios::app);
    json.open(jsonFile, std::ios::app);
}

void Logger::Log(const std::string& msg, const std::string& type)
{
    time_t now = time(nullptr);
    char buffer[64];
    ctime_s(buffer, sizeof(buffer), &now);

    txt << "[" << type << "] " << buffer << ": " << msg << "\n";

    json << "{ \"type\": \"" << type
        << "\", \"timestamp\": \"" << buffer
        << "\", \"msg\": \"" << msg << "\" },\n";
}
