#pragma once
#include <vector>
#include <string>
#include <windows.h>
#include "../processes/ProcessScanner.h"
#include "../core/Logger.h"

class GuiProcessPanel {
public:
    GuiProcessPanel();
    ~GuiProcessPanel();
    void Draw(const std::vector<PROCESS_INFO>& list);
};
