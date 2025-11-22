#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "../core/Logger.h"

struct RUNTIMEBROKER_RESULT {
    bool isFake;
    bool badParent;
    bool unsignedImage;
    bool wrongPath;
    bool injectedThreads;
    std::vector<std::wstring> suspiciousDlls;
};

class RuntimeBrokerAnalyzer {
public:
    RuntimeBrokerAnalyzer();
    ~RuntimeBrokerAnalyzer();
    RUNTIMEBROKER_RESULT Analyze(DWORD pid, Logger& logger);

private:
    bool IsLegitPath(const std::wstring& path);
    bool IsSigned(const std::wstring& file);
    DWORD GetParentProcess(DWORD pid);
    bool HasInjectedThreads(DWORD pid);
    std::vector<std::wstring> GetSuspiciousDlls(DWORD pid);
    std::wstring GetProcessPath(DWORD pid);
};
