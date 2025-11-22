#include "GuiProcessPanel.h"
#include "imgui/imgui.h"

GuiProcessPanel::GuiProcessPanel() {}
GuiProcessPanel::~GuiProcessPanel() {}

void GuiProcessPanel::Draw(const std::vector<PROCESS_INFO>& list)
{
    ImGui::Begin("Processes");
    ImGui::Columns(4);

    ImGui::Text("PID"); ImGui::NextColumn();
    ImGui::Text("PPID"); ImGui::NextColumn();
    ImGui::Text("Name"); ImGui::NextColumn();
    ImGui::Text("Path"); ImGui::NextColumn();
    ImGui::Separator();

    for (auto& p : list)
    {
        ImGui::Text("%lu", p.pid); ImGui::NextColumn();
        ImGui::Text("%lu", p.ppid); ImGui::NextColumn();
        ImGui::Text("%ls", p.name.c_str()); ImGui::NextColumn();
        ImGui::Text("%ls", p.path.c_str()); ImGui::NextColumn();
    }

    ImGui::Columns(1);
    ImGui::End();
}
