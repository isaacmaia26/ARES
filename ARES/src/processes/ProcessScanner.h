#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "../core/Logger.h"

struct PROCESS_INFO {
    DWORD pid;
    DWORD ppid;
    std::wstring name;
    std::wstring path;
    bool suspiciousPath;
};

class PROCESS_SCANNER {
public:
    PROCESS_SCANNER();
    ~PROCESS_SCANNER();
    std::vector<PROCESS_INFO> ScanAll(Logger& logger);
};
