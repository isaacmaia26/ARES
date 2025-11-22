#pragma once
#include <windows.h>
#include <string>
#include "../processes/RuntimeBrokerAnalyzer.h"

class GuiRuntimeBrokerPanel {
public:
    GuiRuntimeBrokerPanel();
    ~GuiRuntimeBrokerPanel();
    void Draw(const RUNTIMEBROKER_RESULT& r);
};
