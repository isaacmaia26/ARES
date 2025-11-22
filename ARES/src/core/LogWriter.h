#pragma once
#include <string>

class LogWriter {
public:
    LogWriter();
    ~LogWriter();
    bool WriteText(const std::wstring& path, const std::wstring& content);
    bool WriteJson(const std::wstring& path, const std::wstring& content);
};
