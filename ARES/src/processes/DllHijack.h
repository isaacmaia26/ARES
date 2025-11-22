#pragma once
#include <windows.h>
#include <string>
#include "../core/Logger.h"

class DLL_HIJACK_DETECTOR {
public:
    DLL_HIJACK_DETECTOR();
    ~DLL_HIJACK_DETECTOR();
    void ScanForHijack(DWORD pid, Logger& logger);

private:
    bool IsPathSuspicious(const std::wstring& path);
    bool IsFileSigned(const std::wstring& filepath);
    std::string WideToUtf8(const std::wstring& w);
};
