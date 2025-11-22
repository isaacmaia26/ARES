#include "GuiRuntimeBrokerPanel.h"
#include "imgui/imgui.h"

GuiRuntimeBrokerPanel::GuiRuntimeBrokerPanel() {}
GuiRuntimeBrokerPanel::~GuiRuntimeBrokerPanel() {}

void GuiRuntimeBrokerPanel::Draw(const RUNTIMEBROKER_RESULT& r)
{
    ImGui::Begin("RuntimeBroker Analysis");

    ImGui::Text("RuntimeBroker Status:");
    ImGui::Separator();

    if (r.isFake) {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "FAKE / COMPROMISED");
    }
    else {
        ImGui::TextColored(ImVec4(0, 1, 0, 1), "Legitimate");
    }

    ImGui::Spacing();

    ImGui::Text("Parent:");
    ImGui::SameLine();
    ImGui::Text(r.badParent ? "INVALID" : "OK");

    ImGui::Text("Path:");
    ImGui::SameLine();
    ImGui::Text(r.wrongPath ? "INVALID" : "OK");

    ImGui::Text("Signature:");
    ImGui::SameLine();
    ImGui::Text(r.unsignedImage ? "UNSIGNED" : "OK");

    ImGui::Text("Injected Threads:");
    ImGui::SameLine();
    ImGui::Text(r.injectedThreads ? "YES" : "NO");

    ImGui::Spacing();
    ImGui::Separator();

    ImGui::Text("Suspicious DLLs:");
    for (auto& dll : r.suspiciousDlls) {
        ImGui::Text("%ls", dll.c_str());
    }

    ImGui::End();
}
