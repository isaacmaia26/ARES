#include "DllHijack.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

DLL_HIJACK_DETECTOR::DLL_HIJACK_DETECTOR() {}
DLL_HIJACK_DETECTOR::~DLL_HIJACK_DETECTOR() {}

std::string DLL_HIJACK_DETECTOR::WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

bool DLL_HIJACK_DETECTOR::IsPathSuspicious(const std::wstring& path)
{
    if (path.find(L"\\AppData\\") != std::wstring::npos) return true;
    if (path.find(L"\\Temp\\") != std::wstring::npos) return true;
    if (path.find(L"\\Local\\") != std::wstring::npos && path.find(L"\\Temp") != std::wstring::npos) return true;
    if (path.find(L"\\Program Files (x86)\\") == std::wstring::npos &&
        path.find(L"\\Windows\\System32\\") == std::wstring::npos &&
        path.find(L"\\Windows\\SysWOW64\\") == std::wstring::npos &&
        path.find(L"\\Program Files\\") == std::wstring::npos) {
        return true;
    }
    return false;
}

bool DLL_HIJACK_DETECTOR::IsFileSigned(const std::wstring& filepath)
{
    LONG status;
    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filepath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID wvtPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData;
    memset(&winTrustData, 0, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = 0;
    winTrustData.hWVTStateData = NULL;
    winTrustData.pwszURLReference = NULL;
    winTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    winTrustData.dwUIContext = 0;

    status = WinVerifyTrust(NULL, &wvtPolicyGUID, &winTrustData);
    return (status == ERROR_SUCCESS);
}

void DLL_HIJACK_DETECTOR::ScanForHijack(DWORD pid, Logger& logger)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        logger.Log("DllHijack: OpenProcess failed for PID " + std::to_string(pid), "warning");
        return;
    }

    HMODULE mods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded)) {
        logger.Log("DllHijack: EnumProcessModules failed for PID " + std::to_string(pid), "warning");
        CloseHandle(hProc);
        return;
    }

    size_t count = cbNeeded / sizeof(HMODULE);
    for (size_t i = 0; i < count; ++i) {
        WCHAR modPathW[MAX_PATH];
        if (!GetModuleFileNameExW(hProc, mods[i], modPathW, MAX_PATH)) continue;
        std::wstring wpath(modPathW);
        std::string pathUtf = WideToUtf8(wpath);

        bool suspiciousPath = IsPathSuspicious(wpath);
        bool signedOk = IsFileSigned(wpath);

        std::ostringstream ss;
        ss << "Module loaded: " << pathUtf << " signed=" << (signedOk ? "yes" : "no") << " suspiciousPath=" << (suspiciousPath ? "yes" : "no");
        if (suspiciousPath || !signedOk) {
            logger.Log(ss.str(), "suspicious");
        }
        else {
            logger.Log(ss.str(), "info");
        }
    }

    CloseHandle(hProc);
}
