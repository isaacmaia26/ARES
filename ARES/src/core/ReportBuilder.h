#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include "../processes/ProcessScanner.h"
#include "../processes/RuntimeBrokerAnalyzer.h"
#include "ArtefactCollector.h"

class ReportBuilder {
public:
    ReportBuilder();
    ~ReportBuilder();
    std::wstring BuildJson(
        const std::vector<PROCESS_INFO>& processes,
        const RUNTIMEBROKER_RESULT& rb,
        const ARTEFACT_DATA& artefacts
    );
private:
    std::wstring Escape(const std::wstring& in);
    std::wstring ArrayString(const std::vector<std::wstring>& v);
};
