#pragma once
#include <windows.h>
#include <string>
#include "../core/Logger.h"

class HOLLOW_DETECTOR {
public:
    HOLLOW_DETECTOR();
    ~HOLLOW_DETECTOR();
    void AnalyzeProcess(DWORD pid, Logger& logger);

private:
    bool CheckImagePathMismatch(HANDLE hProcess, DWORD pid, Logger& logger);
    bool CheckRWXRegions(HANDLE hProcess, DWORD pid, Logger& logger);
    bool CheckInMemoryPE(HANDLE hProcess, DWORD pid, Logger& logger);
    bool CheckModuleEntropyVsDisk(HANDLE hProcess, DWORD pid, Logger& logger);
    bool CheckSectionConsistency(HANDLE hProcess, DWORD pid, Logger& logger);
    bool CheckThreadStartAddresses(HANDLE hProcess, DWORD pid, Logger& logger);

    std::string WideToUtf8(const std::wstring& w);
    bool ReadRemoteMemory(HANDLE hProcess, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outRead = nullptr);
};
