#include <windows.h>
#include "gui/GuiCore.h"
#include "core/Privileges.h"
#include "processes/ProcessScanner.h"
#include "processes/RuntimeBrokerAnalyzer.h"
#include "core/ArtefactCollector.h"
#include "core/Logger.h"

int main()
{
    EnableDebugPrivilege();

    Logger logger;

    ProcessScanner pscan;
    RuntimeBrokerAnalyzer rbscan;
    ArtefactCollector ac;

    auto processes = pscan.ScanAll(logger);
    auto rb = rbscan.Analyze(0, logger);
    auto artefacts = ac.Collect(logger);

    GuiCore gui;
    gui.SetInitialData(processes, rb, artefacts);
    gui.Run();

    return 0;
}
