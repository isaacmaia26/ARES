#pragma once
#include <string>
#include <fstream>

class Logger {
private:
    std::ofstream txt;
    std::ofstream json;

public:
    Logger(const std::string& txtFile, const std::string& jsonFile);
    void Log(const std::string& msg, const std::string& type = "info");
};
