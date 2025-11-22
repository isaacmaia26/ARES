#include "Utils.h"
#include <tlhelp32.h>
#include <math.h>

std::vector<DWORD> Utils::GetAllPIDs()
{
    std::vector<DWORD> pids;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (Process32First(snap, &entry))
    {
        do {
            pids.push_back(entry.th32ProcessID);
        } while (Process32Next(snap, &entry));
    }

    CloseHandle(snap);
    return pids;
}

double Utils::Entropy(const unsigned char* data, size_t size)
{
    int freq[256] = { 0 };

    for (size_t i = 0; i < size; i++)
        freq[data[i]]++;

    double entropy = 0.0;

    for (int i = 0; i < 256; i++)
    {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / size;
        entropy -= p * log2(p);
    }

    return entropy;
}

bool Utils::IsSuspiciousPath(const std::wstring& path)
{
    if (path.find(L"AppData") != std::wstring::npos) return true;
    if (path.find(L"Temp") != std::wstring::npos) return true;
    if (path.find(L"Roaming") != std::wstring::npos) return true;

    return false;
}
