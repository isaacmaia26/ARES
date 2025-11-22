#pragma once
#include <string>
#include <vector>

class Logger
{
public:
    Logger();
    ~Logger();

    void Log(const std::string& msg, const std::string& level);
    const std::vector<std::string>& GetLogs() const;

private:
    std::vector<std::string> logs;
};
