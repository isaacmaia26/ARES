#include "GuiCore.h"
#include "imgui/imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"
#include "GuiRuntimeBrokerPanel.h"
#include "GuiProcessPanel.h"
#include "GuiArtefactPanel.h"
#include "GuiActionsPanel.h"
#include "GuiThreatDashboard.h"

static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM w, LPARAM l)
{
    if (ImGui_ImplWin32_WndProcHandler(h, msg, w, l))
        return 1;
    return DefWindowProc(h, msg, w, l);
}

GuiCore::GuiCore()
{
    hwnd = nullptr;
    device = nullptr;
    context = nullptr;
    swapchain = nullptr;
    rtv = nullptr;

    showProcesses = true;
    showLogs = true;
    showMemory = true;
    showRuntime = true;
    showArtefacts = true;
    showActions = true;
    showDashboard = true;

    initialProcesses.clear();
}

GuiCore::~GuiCore()
{
    Shutdown();
}

void GuiCore::SetInitialData(const std::vector<PROCESS_INFO>& p,
    const RUNTIMEBROKER_RESULT& rb,
    const ARTEFACT_DATA& art)
{
    initialProcesses = p;
    initialRuntime = rb;
    initialArtefacts = art;
}

bool GuiCore::InitWindow()
{
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SCAN_GUI";
    RegisterClass(&wc);

    hwnd = CreateWindowEx(0, L"SCAN_GUI", L"Forensic Scanner", WS_OVERLAPPEDWINDOW,
        200, 200, 1200, 700, nullptr, nullptr, wc.hInstance, nullptr);

    if (!hwnd) return false;

    ShowWindow(hwnd, SW_SHOW);
    return true;
}

bool GuiCore::InitD3D()
{
    DXGI_SWAP_CHAIN_DESC sc = {};
    sc.BufferCount = 1;
    sc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sc.OutputWindow = hwnd;
    sc.SampleDesc.Count = 1;
    sc.Windowed = TRUE;

    D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION,
        &sc, &swapchain, &device, nullptr, &context);

    ID3D11Texture2D* backbuf;
    swapchain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&backbuf);
    device->CreateRenderTargetView(backbuf, nullptr, &rtv);
    backbuf->Release();

    return true;
}

bool GuiCore::InitImGui()
{
    ImGui::CreateContext();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(device, context);
    return true;
}

void GuiCore::DrawMenu()
{
    ImGui::Begin("Menu");
    if (ImGui::Button("Dashboard")) showDashboard = !showDashboard;
    if (ImGui::Button("Processos")) showProcesses = !showProcesses;
    if (ImGui::Button("RuntimeBroker")) showRuntime = !showRuntime;
    if (ImGui::Button("Artefactos")) showArtefacts = !showArtefacts;
    if (ImGui::Button("Ações")) showActions = !showActions;
    if (ImGui::Button("Logs")) showLogs = !showLogs;
    if (ImGui::Button("Memory")) showMemory = !showMemory;
    ImGui::End();
}

void GuiCore::Render()
{
    static GuiProcessPanel procPanel;
    static GuiRuntimeBrokerPanel rbPanel;
    static GuiArtefactPanel artePanel;
    static GuiActionsPanel actPanel;
    static GuiThreatDashboard dashPanel;

    static std::vector<PROCESS_INFO> processList = initialProcesses;
    static RUNTIMEBROKER_RESULT rbResult = initialRuntime;
    static ARTEFACT_DATA arteData = initialArtefacts;

    FLOAT c[4] = { 0.05f, 0.05f, 0.05f, 1.0f };
    context->ClearRenderTargetView(rtv, c);

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    DrawMenu();

    if (showDashboard)
        dashPanel.Draw(processList, rbResult, arteData);

    if (showProcesses)
        procPanel.Draw(processList);

    if (showRuntime)
        rbPanel.Draw(rbResult);

    if (showArtefacts)
        artePanel.Draw(arteData);

    if (showActions)
        actPanel.Draw(processList, rbResult, arteData);

    if (showMemory)
        DrawMemoryPanel();

    if (showLogs)
        DrawLogs();

    ImGui::Render();
    context->OMSetRenderTargets(1, &rtv, nullptr);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    swapchain->Present(1, 0);
}

void GuiCore::Run()
{
    InitWindow();
    InitD3D();
    InitImGui();

    MSG msg = {};
    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }
        Render();
    }
}

void GuiCore::Shutdown()
{
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    if (rtv) rtv->Release();
    if (swapchain) swapchain->Release();
    if (context) context->Release();
    if (device) device->Release();
}
