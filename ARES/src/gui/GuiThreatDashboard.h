#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "../processes/ProcessScanner.h"
#include "../processes/RuntimeBrokerAnalyzer.h"
#include "../core/ArtefactCollector.h"

class GuiThreatDashboard {
public:
    GuiThreatDashboard();
    ~GuiThreatDashboard();
    void Draw(const std::vector<PROCESS_INFO>& processes,
        const RUNTIMEBROKER_RESULT& rb,
        const ARTEFACT_DATA& artefacts);
private:
    float ComputeProcessScore(const std::vector<PROCESS_INFO>& processes);
    float ComputeRuntimeScore(const RUNTIMEBROKER_RESULT& rb);
    float ComputeArtefactScore(const ARTEFACT_DATA& artefacts);
};
