#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "Logger.h"

struct ARTEFACT_DATA {
    std::vector<std::wstring> prefetchFiles;
    std::vector<std::wstring> recentFiles;
    std::vector<std::wstring> usbHistory;
    std::vector<std::wstring> recycleBinItems;
    std::vector<std::wstring> stoppedServices;
    std::vector<std::wstring> eventLogEntries;
};

class ArtefactCollector {
public:
    ArtefactCollector();
    ~ArtefactCollector();
    ARTEFACT_DATA Collect(Logger& logger);
private:
    void CollectPrefetch(ARTEFACT_DATA& out, Logger& logger);
    void CollectRecentFiles(ARTEFACT_DATA& out, Logger& logger);
    void CollectUsbHistory(ARTEFACT_DATA& out, Logger& logger);
    void CollectRecycleBin(ARTEFACT_DATA& out, Logger& logger);
    void CollectStoppedServices(ARTEFACT_DATA& out, Logger& logger);
    void CollectEventLogs(ARTEFACT_DATA& out, Logger& logger);
};
