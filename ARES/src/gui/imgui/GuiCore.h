#pragma once
#include <windows.h>
#include <d3d11.h>
#include <vector>
#include <string>

#include "../processes/ProcessScanner.h"
#include "../processes/RuntimeBrokerAnalyzer.h"
#include "../core/ArtefactCollector.h"

class GuiCore
{
public:
    GuiCore();
    ~GuiCore();
    void Run();

    void SetInitialData(const std::vector<PROCESS_INFO>& p,
        const RUNTIMEBROKER_RESULT& rb,
        const ARTEFACT_DATA& art);

private:
    bool InitWindow();
    bool InitD3D();
    bool InitImGui();
    void Render();
    void Shutdown();

    void DrawMenu();
    void DrawProcessTable();
    void DrawLogs();
    void DrawMemoryPanel();

    HWND hwnd;
    ID3D11Device* device;
    ID3D11DeviceContext* context;
    IDXGISwapChain* swapchain;
    ID3D11RenderTargetView* rtv;

    bool showProcesses;
    bool showLogs;
    bool showMemory;
    bool showRuntime;
    bool showArtefacts;
    bool showActions;
    bool showDashboard;

    std::vector<std::string> logs;

    std::vector<PROCESS_INFO> initialProcesses;
    RUNTIMEBROKER_RESULT initialRuntime;
    ARTEFACT_DATA initialArtefacts;
};
