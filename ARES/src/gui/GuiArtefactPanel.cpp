#include "GuiArtefactPanel.h"
#include "imgui/imgui.h"

GuiArtefactPanel::GuiArtefactPanel() {}
GuiArtefactPanel::~GuiArtefactPanel() {}

void GuiArtefactPanel::Draw(const ARTEFACT_DATA& a)
{
    ImGui::Begin("Forensic Artefacts");

    if (ImGui::CollapsingHeader("Prefetch"))
        for (auto& x : a.prefetchFiles)
            ImGui::Text("%ls", x.c_str());

    if (ImGui::CollapsingHeader("Recent Files"))
        for (auto& x : a.recentFiles)
            ImGui::Text("%ls", x.c_str());

    if (ImGui::CollapsingHeader("USB History"))
        for (auto& x : a.usbHistory)
            ImGui::Text("%ls", x.c_str());

    if (ImGui::CollapsingHeader("Recycle Bin"))
        for (auto& x : a.recycleBinItems)
            ImGui::Text("%ls", x.c_str());

    if (ImGui::CollapsingHeader("Stopped Services"))
        for (auto& x : a.stoppedServices)
            ImGui::Text("%ls", x.c_str());

    if (ImGui::CollapsingHeader("Event Logs"))
        for (auto& x : a.eventLogEntries)
            ImGui::Text("%ls", x.c_str());

    ImGui::End();
}
