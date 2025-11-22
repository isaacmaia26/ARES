#pragma once
#include <windows.h>
#include <string>
#include "../core/Logger.h"

class MEMORY_SCANNER {
public:
    MEMORY_SCANNER();
    ~MEMORY_SCANNER();
    void ScanProcessMemory(DWORD pid, Logger& logger);

private:
    bool IsExecutableProtect(DWORD protect);
    bool ContainsSyscallSignature(const unsigned char* buf, SIZE_T len);
    bool IsPEHeader(const unsigned char* buf, SIZE_T len);
    double SampleEntropy(const unsigned char* buf, SIZE_T len);
    bool DumpRegionIfShellcode(DWORD pid, SIZE_T base, const unsigned char* buf, SIZE_T len, Logger& logger);
    bool ReadRemote(HANDLE hProc, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outRead = nullptr);
    std::string MakeDumpPath(DWORD pid, SIZE_T base);
};
