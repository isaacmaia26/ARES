#pragma once
#include <vector>
#include <string>
#include <windows.h>
#include "../core/ArtefactCollector.h"

class GuiArtefactPanel {
public:
    GuiArtefactPanel();
    ~GuiArtefactPanel();
    void Draw(const ARTEFACT_DATA& a);
};
