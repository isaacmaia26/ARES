#include "GuiActionsPanel.h"
#include "imgui/imgui.h"

GuiActionsPanel::GuiActionsPanel() {}
GuiActionsPanel::~GuiActionsPanel() {}

void GuiActionsPanel::Draw(
    std::vector<PROCESS_INFO>& processes,
    RUNTIMEBROKER_RESULT& rb,
    ARTEFACT_DATA& artefacts
)
{
    ImGui::Begin("Actions");

    if (ImGui::Button("Scan System"))
    {
        Logger logger;
        ProcessScanner ps;
        RuntimeBrokerAnalyzer rbScan;
        ArtefactCollector ac;

        processes = ps.ScanAll(logger);
        rb = rbScan.Analyze(0, logger);
        artefacts = ac.Collect(logger);
    }

    if (ImGui::Button("Refresh Processes"))
    {
        Logger logger;
        ProcessScanner ps;
        processes = ps.ScanAll(logger);
    }

    if (ImGui::Button("Export Report JSON"))
    {
        ReportBuilder rbld;
        std::wstring json = rbld.BuildJson(processes, rb, artefacts);
        LogWriter lw;
        lw.WriteJson(L"ares_report.json", json);
    }

    ImGui::End();
}
