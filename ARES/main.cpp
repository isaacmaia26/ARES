#include <windows.h>
#include <iostream>
#include "core/Logger.h"
#include "core/Privileges.h"
#include "core/Utils.h"
#include "processes/HollowDetection.h"
#include "processes/DllHijack.h"
#include "memory/MemoryScanner.h"
#include "uefi/UefiScanner.h"

int main()
{
    Logger logger("logs/ares_log.txt", "logs/ares_log.json");
    logger.Log("=== ARES FORENSICS SCANNER STARTED ===");

    if (!EnableSeDebugPrivilege()) {
        logger.Log("SeDebugPrivilege failed to enable", "error");
        std::cout << "Failed to enable debug privilege.\n";
        return 1;
    }

    logger.Log("SeDebugPrivilege enabled", "info");

    logger.Log("Scanning processes...", "section");

    auto pids = Utils::GetAllPIDs();

    MEMORY_SCANNER memscan;
    HOLLOW_DETECTOR hol;
    DLL_HIJACK_DETECTOR hij;

    for (auto pid : pids)
    {
        logger.Log("Analyzing PID: " + std::to_string(pid), "info");

        hol.AnalyzeProcess(pid, logger);
        hij.ScanForHijack(pid, logger);
        memscan.ScanProcessMemory(pid, logger);
    }

    logger.Log("Scanning UEFI environment...", "section");

    UEFI_SCANNER uefi;
    uefi.Scan(logger);

    logger.Log("=== SCAN COMPLETE ===");
    return 0;
}
#include "gui/GuiCore.h"

int main()
{
    GuiCore gui;
    gui.Run();
    return 0;
}
