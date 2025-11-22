#include "ArtefactCollector.h"
#include <shlobj.h>
#include <shlwapi.h>
#include <winsvc.h>
#include <winreg.h>
#include <sstream>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

ArtefactCollector::ArtefactCollector() {}
ArtefactCollector::~ArtefactCollector() {}

void ArtefactCollector::CollectPrefetch(ARTEFACT_DATA& out, Logger& logger)
{
    WCHAR windir[MAX_PATH];
    if (!GetWindowsDirectoryW(windir, MAX_PATH)) {
        logger.Log("ArtefactCollector: GetWindowsDirectoryW failed", "warning");
        return;
    }
    std::wstring prefetchDir = std::wstring(windir) + L"\\Prefetch\\*.*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(prefetchDir.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        logger.Log("ArtefactCollector: no prefetch dir or access denied", "warning");
        return;
    }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            out.prefetchFiles.push_back(std::wstring(windir) + L"\\Prefetch\\" + fd.cFileName);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::ostringstream ss;
    ss << "ArtefactCollector: collected " << out.prefetchFiles.size() << " prefetch files";
    logger.Log(ss.str(), "info");
}

void ArtefactCollector::CollectRecentFiles(ARTEFACT_DATA& out, Logger& logger)
{
    PWSTR path = nullptr;
    if (SHGetKnownFolderPath(FOLDERID_Recent, 0, NULL, &path) != S_OK) {
        logger.Log("ArtefactCollector: SHGetKnownFolderPath(FOLDERID_Recent) failed", "warning");
        return;
    }
    std::wstring recentDir = std::wstring(path) + L"\\*.*";
    CoTaskMemFree(path);

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(recentDir.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        logger.Log("ArtefactCollector: no Recent dir or access denied", "warning");
        return;
    }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            out.recentFiles.push_back(std::wstring(recentDir.begin(), recentDir.end() - 3) + fd.cFileName);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    std::ostringstream ss;
    ss << "ArtefactCollector: collected " << out.recentFiles.size() << " recent files";
    logger.Log(ss.str(), "info");
}

void ArtefactCollector::CollectUsbHistory(ARTEFACT_DATA& out, Logger& logger)
{
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        logger.Log("ArtefactCollector: RegOpenKeyExW USBSTOR failed", "warning");
        return;
    }
    DWORD index = 0;
    WCHAR name[256];
    DWORD nameLen = 256;
    while (RegEnumKeyExW(hKey, index, name, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        out.usbHistory.push_back(name);
        index++;
        nameLen = 256;
    }
    RegCloseKey(hKey);
    std::ostringstream ss;
    ss << "ArtefactCollector: collected " << out.usbHistory.size() << " USB history entries";
    logger.Log(ss.str(), "info");
}

void ArtefactCollector::CollectRecycleBin(ARTEFACT_DATA& out, Logger& logger)
{
    DWORD len = GetLogicalDriveStringsW(0, NULL);
    if (len == 0) {
        logger.Log("ArtefactCollector: GetLogicalDriveStringsW failed", "warning");
        return;
    }
    std::vector<wchar_t> buf(len + 1);
    GetLogicalDriveStringsW(len + 1, buf.data());
    wchar_t* cur = buf.data();
    while (*cur) {
        std::wstring root(cur);
        std::wstring binPath = root + L"$Recycle.Bin\\*.*";
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(binPath.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    out.recycleBinItems.push_back(root + L"$Recycle.Bin\\" + fd.cFileName);
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        cur += wcslen(cur) + 1;
    }
    std::ostringstream ss;
    ss << "ArtefactCollector: collected " << out.recycleBinItems.size() << " recycle bin items";
    logger.Log(ss.str(), "info");
}

void ArtefactCollector::CollectStoppedServices(ARTEFACT_DATA& out, Logger& logger)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, GENERIC_READ);
    if (!scm) {
        logger.Log("ArtefactCollector: OpenSCManagerW failed", "warning");
        return;
    }

    DWORD bytesNeeded = 0;
    DWORD count = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &bytesNeeded, &count, NULL, NULL);
    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(scm);
        logger.Log("ArtefactCollector: EnumServicesStatusExW pre-call failed", "warning");
        return;
    }

    std::vector<BYTE> buffer(bytesNeeded);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        buffer.data(), bytesNeeded, &bytesNeeded, &count, NULL, NULL)) {
        CloseServiceHandle(scm);
        logger.Log("ArtefactCollector: EnumServicesStatusExW real call failed", "warning");
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSW* services = (ENUM_SERVICE_STATUS_PROCESSW*)buffer.data();
    for (DWORD i = 0; i < count; ++i) {
        if (services[i].ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED) {
            out.stoppedServices.push_back(services[i].lpServiceName);
        }
    }

    CloseServiceHandle(scm);

    std::ostringstream ss;
    ss << "ArtefactCollector: collected " << out.stoppedServices.size() << " stopped services";
    logger.Log(ss.str(), "info");
}

void ArtefactCollector::CollectEventLogs(ARTEFACT_DATA& out, Logger& logger)
{
    HANDLE hLog = OpenEventLogW(NULL, L"System");
    if (!hLog) {
        logger.Log("ArtefactCollector: OpenEventLogW(System) failed", "warning");
        return;
    }

    const DWORD bufSize = 64 * 1024;
    std::vector<BYTE> buffer(bufSize);
    DWORD bytesRead = 0;
    DWORD minNeeded = 0;
    DWORD flags = EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ;
    int limit = 128;
    while (limit-- > 0 && ReadEventLogW(hLog, flags, 0, buffer.data(), bufSize, &bytesRead, &minNeeded)) {
        DWORD offset = 0;
        while (offset < bytesRead) {
            EVENTLOGRECORD* rec = (EVENTLOGRECORD*)(buffer.data() + offset);
            WORD id = (WORD)(rec->EventID & 0xFFFF);
            if (id == 600 || id == 7036 || id == 4688) {
                std::wstringstream ws;
                ws << L"EventID=" << id << L" SourceOffset=" << rec->StringOffset;
                out.eventLogEntries.push_back(ws.str());
            }
            offset += rec->Length;
        }
    }
    CloseEventLog(hLog);

    std::ostringstream ss;
    ss << "ArtefactCollector: collected " << out.eventLogEntries.size() << " event log entries";
    logger.Log(ss.str(), "info");
}

ARTEFACT_DATA ArtefactCollector::Collect(Logger& logger)
{
    ARTEFACT_DATA data;
    CollectPrefetch(data, logger);
    CollectRecentFiles(data, logger);
    CollectUsbHistory(data, logger);
    CollectRecycleBin(data, logger);
    CollectStoppedServices(data, logger);
    CollectEventLogs(data, logger);
    return data;
}
