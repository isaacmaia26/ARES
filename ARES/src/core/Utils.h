#pragma once
#include <vector>
#include <windows.h>

namespace Utils {
    std::vector<DWORD> GetAllPIDs();
    double Entropy(const unsigned char* data, size_t size);
    bool IsSuspiciousPath(const std::wstring& path);
}
