#include "ProcessScanner.h"
#include "../core/Utils.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <sstream>

#pragma comment(lib, "psapi.lib")

PROCESS_SCANNER::PROCESS_SCANNER() {}
PROCESS_SCANNER::~PROCESS_SCANNER() {}

std::vector<PROCESS_INFO> PROCESS_SCANNER::ScanAll(Logger& logger)
{
    std::vector<PROCESS_INFO> out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        logger.Log("ProcessScanner: CreateToolhelp32Snapshot failed", "warning");
        return out;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        logger.Log("ProcessScanner: Process32FirstW failed", "warning");
        return out;
    }

    do {
        PROCESS_INFO info;
        info.pid = pe.th32ProcessID;
        info.ppid = pe.th32ParentProcessID;
        info.name = pe.szExeFile;
        info.path.clear();
        info.suspiciousPath = false;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
        if (hProc) {
            WCHAR buf[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, buf, &size)) {
                info.path = buf;
            }
            else {
                if (GetModuleFileNameExW(hProc, NULL, buf, MAX_PATH)) {
                    info.path = buf;
                }
            }
            CloseHandle(hProc);
        }

        if (!info.path.empty()) {
            info.suspiciousPath = Utils::IsSuspiciousPath(info.path);
        }

        if (info.suspiciousPath) {
            std::ostringstream ss;
            ss << "Process suspicious path pid=" << info.pid;
            logger.Log(ss.str(), "suspicious");
        }

        out.push_back(info);
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);

    std::ostringstream ss;
    ss << "ProcessScanner: scanned " << out.size() << " processes";
    logger.Log(ss.str(), "info");

    return out;
}
