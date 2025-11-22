#pragma once
#include <windows.h>
#include <vector>
#include "../processes/ProcessScanner.h"
#include "../processes/RuntimeBrokerAnalyzer.h"
#include "../core/ArtefactCollector.h"
#include "../core/ReportBuilder.h"
#include "../core/LogWriter.h"

class GuiActionsPanel {
public:
    GuiActionsPanel();
    ~GuiActionsPanel();
    void Draw(
        std::vector<PROCESS_INFO>& processes,
        RUNTIMEBROKER_RESULT& rb,
        ARTEFACT_DATA& artefacts
    );
};
