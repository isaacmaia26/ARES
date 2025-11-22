#include "ReportBuilder.h"
#include <sstream>

ReportBuilder::ReportBuilder() {}
ReportBuilder::~ReportBuilder() {}

std::wstring ReportBuilder::Escape(const std::wstring& in)
{
    std::wstring out;
    for (wchar_t c : in) {
        if (c == L'\"') out += L"\\\"";
        else out += c;
    }
    return out;
}

std::wstring ReportBuilder::ArrayString(const std::vector<std::wstring>& v)
{
    std::wstringstream ss;
    ss << L"[";
    for (size_t i = 0; i < v.size(); i++) {
        ss << L"\"" << Escape(v[i]) << L"\"";
        if (i + 1 < v.size()) ss << L",";
    }
    ss << L"]";
    return ss.str();
}

std::wstring ReportBuilder::BuildJson(
    const std::vector<PROCESS_INFO>& processes,
    const RUNTIMEBROKER_RESULT& rb,
    const ARTEFACT_DATA& artefacts
)
{
    std::wstringstream ss;
    ss << L"{";

    ss << L"\"processes\":[";
    for (size_t i = 0; i < processes.size(); i++) {
        ss << L"{";
        ss << L"\"pid\":" << processes[i].pid << L",";
        ss << L"\"ppid\":" << processes[i].ppid << L",";
        ss << L"\"name\":\"" << Escape(processes[i].name) << L"\",";
        ss << L"\"path\":\"" << Escape(processes[i].path) << L"\",";
        ss << L"\"suspiciousPath\":" << (processes[i].suspiciousPath ? L"true" : L"false");
        ss << L"}";
        if (i + 1 < processes.size()) ss << L",";
    }
    ss << L"],";

    ss << L"\"runtimebroker\":{";
    ss << L"\"isFake\":" << (rb.isFake ? L"true" : L"false") << L",";
    ss << L"\"badParent\":" << (rb.badParent ? L"true" : L"false") << L",";
    ss << L"\"unsignedImage\":" << (rb.unsignedImage ? L"true" : L"false") << L",";
    ss << L"\"wrongPath\":" << (rb.wrongPath ? L"true" : L"false") << L",";
    ss << L"\"injectedThreads\":" << (rb.injectedThreads ? L"true" : L"false") << L",";
    ss << L"\"suspiciousDlls\":" << ArrayString(rb.suspiciousDlls);
    ss << L"},";

    ss << L"\"artefacts\":{";
    ss << L"\"prefetch\":" << ArrayString(artefacts.prefetchFiles) << L",";
    ss << L"\"recent\":" << ArrayString(artefacts.recentFiles) << L",";
    ss << L"\"usb\":" << ArrayString(artefacts.usbHistory) << L",";
    ss << L"\"recycle\":" << ArrayString(artefacts.recycleBinItems) << L",";
    ss << L"\"stoppedServices\":" << ArrayString(artefacts.stoppedServices) << L",";
    ss << L"\"eventLogs\":" << ArrayString(artefacts.eventLogEntries);
    ss << L"}";

    ss << L"}";
    return ss.str();
}
