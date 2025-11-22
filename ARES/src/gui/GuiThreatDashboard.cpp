#include "GuiThreatDashboard.h"
#include "imgui/imgui.h"
#include <algorithm>

GuiThreatDashboard::GuiThreatDashboard() {}
GuiThreatDashboard::~GuiThreatDashboard() {}

float GuiThreatDashboard::ComputeProcessScore(const std::vector<PROCESS_INFO>& processes)
{
    int suspicious = 0;
    for (auto& p : processes)
        if (p.suspiciousPath)
            suspicious++;
    if (processes.empty()) return 0.0f;
    float ratio = (float)suspicious / (float)processes.size();
    float score = ratio * 40.0f;
    if (score > 40.0f) score = 40.0f;
    return score;
}

float GuiThreatDashboard::ComputeRuntimeScore(const RUNTIMEBROKER_RESULT& rb)
{
    float score = 0.0f;
    if (rb.isFake) score += 40.0f;
    else {
        if (rb.badParent) score += 10.0f;
        if (rb.wrongPath) score += 10.0f;
        if (rb.unsignedImage) score += 10.0f;
        if (rb.injectedThreads) score += 10.0f;
        if (!rb.suspiciousDlls.empty()) score += 10.0f;
        if (score > 30.0f) score = 30.0f;
    }
    return score;
}

float GuiThreatDashboard::ComputeArtefactScore(const ARTEFACT_DATA& a)
{
    int signals = 0;
    if (!a.prefetchFiles.empty()) signals++;
    if (!a.recentFiles.empty()) signals++;
    if (!a.usbHistory.empty()) signals++;
    if (!a.recycleBinItems.empty()) signals++;
    if (!a.stoppedServices.empty()) signals++;
    if (!a.eventLogEntries.empty()) signals++;
    float score = (float)signals * 5.0f;
    if (score > 30.0f) score = 30.0f;
    return score;
}

void GuiThreatDashboard::Draw(const std::vector<PROCESS_INFO>& processes,
    const RUNTIMEBROKER_RESULT& rb,
    const ARTEFACT_DATA& artefacts)
{
    float ps = ComputeProcessScore(processes);
    float rs = ComputeRuntimeScore(rb);
    float as = ComputeArtefactScore(artefacts);
    float total = ps + rs + as;
    if (total > 100.0f) total = 100.0f;

    ImVec4 color;
    if (total < 30.0f) color = ImVec4(0.0f, 0.8f, 0.0f, 1.0f);
    else if (total < 70.0f) color = ImVec4(0.9f, 0.9f, 0.0f, 1.0f);
    else color = ImVec4(0.9f, 0.0f, 0.0f, 1.0f);

    ImGui::Begin("Threat Dashboard");

    ImGui::Text("Threat Score");
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::ProgressBar(total / 100.0f, ImVec2(300, 30));
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::Text(" %.1f / 100", total);

    ImGui::Separator();
    ImGui::Text("Breakdown");
    ImGui::Text("Processes: %.1f / 40", ps);
    ImGui::Text("RuntimeBroker: %.1f / 40", rs);
    ImGui::Text("Artefacts: %.1f / 30", as);

    ImGui::Separator();
    ImGui::Text("Status:");
    if (total < 30.0f)
        ImGui::TextColored(color, "LOW RISK");
    else if (total < 70.0f)
        ImGui::TextColored(color, "MEDIUM RISK");
    else
        ImGui::TextColored(color, "HIGH RISK");

    ImGui::End();
}
