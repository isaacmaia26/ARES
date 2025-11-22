#pragma once
#include <windows.h>
#include <string>
#include "../core/Logger.h"

class UEFI_SCANNER {
public:
    UEFI_SCANNER();
    ~UEFI_SCANNER();
    void Scan(Logger& logger);

private:
    bool DriveHasEfiRoot(const std::wstring& root);
    bool HashFileSHA256(const std::wstring& filepath, std::string& outHex);
    std::string WideToUtf8(const std::wstring& w);
};
