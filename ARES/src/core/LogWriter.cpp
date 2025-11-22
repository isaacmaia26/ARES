#include "LogWriter.h"
#include <fstream>

LogWriter::LogWriter() {}
LogWriter::~LogWriter() {}

bool LogWriter::WriteText(const std::wstring& path, const std::wstring& content)
{
    std::wofstream f(path);
    if (!f.is_open()) return false;
    f << content;
    f.close();
    return true;
}

bool LogWriter::WriteJson(const std::wstring& path, const std::wstring& content)
{
    std::wofstream f(path);
    if (!f.is_open()) return false;
    f << content;
    f.close();
    return true;
}
