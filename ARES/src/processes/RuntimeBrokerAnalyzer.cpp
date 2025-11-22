#include "RuntimeBrokerAnalyzer.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

RuntimeBrokerAnalyzer::RuntimeBrokerAnalyzer() {}
RuntimeBrokerAnalyzer::~RuntimeBrokerAnalyzer() {}

std::wstring RuntimeBrokerAnalyzer::GetProcessPath(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return L"";
    WCHAR buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(h, 0, buf, &size))
        buf[0] = 0;
    CloseHandle(h);
    return buf;
}

DWORD RuntimeBrokerAnalyzer::GetParentProcess(DWORD pid)
{
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return ppid;
}

bool RuntimeBrokerAnalyzer::IsLegitPath(const std::wstring& path)
{
    if (path.empty()) return false;
    if (path.find(L"\\System32\\RuntimeBroker.exe") != std::wstring::npos) return true;
    if (path.find(L"\\SysWOW64\\RuntimeBroker.exe") != std::wstring::npos) return true;
    return false;
}

bool RuntimeBrokerAnalyzer::IsSigned(const std::wstring& file)
{
    WINTRUST_FILE_INFO fi = {};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = file.c_str();

    WINTRUST_DATA wd = {};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE;

    GUID x = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG s = WinVerifyTrust(NULL, &x, &wd);
    return s == ERROR_SUCCESS;
}

bool RuntimeBrokerAnalyzer::HasInjectedThreads(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te = { sizeof(te) };
    bool injected = false;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    injected = true;
                    CloseHandle(hThread);
                    break;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return injected;
}

std::vector<std::wstring> RuntimeBrokerAnalyzer::GetSuspiciousDlls(DWORD pid)
{
    std::vector<std::wstring> out;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return out;

    HMODULE mods[512];
    DWORD needed = 0;
    if (EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
        size_t count = needed / sizeof(HMODULE);
        for (size_t i = 0; i < count; i++) {
            WCHAR path[MAX_PATH];
            if (GetModuleFileNameExW(hProc, mods[i], path, MAX_PATH)) {
                std::wstring p = path;
                if (p.find(L"AppData") != std::wstring::npos || p.find(L"Temp") != std::wstring::npos)
                    out.push_back(p);
            }
        }
    }
    CloseHandle(hProc);
    return out;
}

RUNTIMEBROKER_RESULT RuntimeBrokerAnalyzer::Analyze(DWORD pid, Logger& logger)
{
    RUNTIMEBROKER_RESULT r = {};
    std::wstring path = GetProcessPath(pid);

    r.wrongPath = !IsLegitPath(path);
    r.unsignedImage = !IsSigned(path);

    DWORD ppid = GetParentProcess(pid);
    HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ppid);
    WCHAR buf[MAX_PATH] = {};
    if (hParent) {
        DWORD size = MAX_PATH;
        QueryFullProcessImageNameW(hParent, 0, buf, &size);
        CloseHandle(hParent);
    }

    std::wstring parent = buf;
    r.badParent = parent.find(L"explorer.exe") == std::wstring::npos;

    r.injectedThreads = HasInjectedThreads(pid);
    r.suspiciousDlls = GetSuspiciousDlls(pid);

    r.isFake = r.wrongPath || r.badParent || r.unsignedImage || r.injectedThreads || !r.suspiciousDlls.empty();

    if (r.isFake)
        logger.Log("RuntimeBrokerAnalyzer: runtimebroker.exe FALSE detected", "suspicious");
    else
        logger.Log("RuntimeBrokerAnalyzer: runtimebroker.exe is legit", "info");

    return r;
}
