#pragma once
#include <windows.h>
#include <d3d11.h>
#include <vector>
#include <string>

class GuiCore
{
public:
    GuiCore();
    ~GuiCore();
    void Run();

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

    std::vector<std::string> logs;
};
