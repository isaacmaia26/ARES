#include "UefiScanner.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <fileapi.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <sys/types.h>
#include <sys/stat.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

UEFI_SCANNER::UEFI_SCANNER() {}
UEFI_SCANNER::~UEFI_SCANNER() {}

std::string UEFI_SCANNER::WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

bool UEFI_SCANNER::DriveHasEfiRoot(const std::wstring& root)
{
    std::wstring efiPath = root + L"EFI\\";
    DWORD attrs = GetFileAttributesW(efiPath.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES) && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool UEFI_SCANNER::HashFileSHA256(const std::wstring& filepath, std::string& outHex)
{
    HANDLE hFile = CreateFileW(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return false;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return false;
    }

    const DWORD bufSize = 1 << 12;
    std::vector<BYTE> buffer(bufSize);
    DWORD read = 0;
    BOOL ok = FALSE;
    while (ReadFile(hFile, buffer.data(), bufSize, &read, NULL) && read > 0) {
        ok = CryptHashData(hHash, buffer.data(), read, 0);
        if (!ok) break;
    }

    BYTE hash[32];
    DWORD hashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return false;
    }

    std::ostringstream ss;
    for (DWORD i = 0; i < hashLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    outHex = ss.str();

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return true;
}

void UEFI_SCANNER::Scan(Logger& logger)
{
    DWORD len = GetLogicalDriveStringsW(0, NULL);
    if (len == 0) {
        logger.Log("UEFI: GetLogicalDriveStringsW failed", "warning");
        return;
    }
    std::vector<wchar_t> buf(len + 1);
    GetLogicalDriveStringsW(len + 1, buf.data());

    wchar_t* cur = buf.data();
    bool anyEfiFound = false;
    while (*cur) {
        std::wstring root(cur);
        if (DriveHasEfiRoot(root)) {
            anyEfiFound = true;
            std::wstring searchPath = root + L"EFI\\*";
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)) continue;
                    std::wstring sub = root + L"EFI\\" + fd.cFileName + L"\\";
                    std::wstring fileSearch = sub + L"*.*";
                    WIN32_FIND_DATAW fd2;
                    HANDLE hFind2 = FindFirstFileW(fileSearch.c_str(), &fd2);
                    if (hFind2 != INVALID_HANDLE_VALUE) {
                        do {
                            if (!(fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                                std::wstring filePath = sub + fd2.cFileName;
                                std::wstring ext = PathFindExtensionW(filePath.c_str());
                                if (_wcsicmp(ext.c_str(), L".efi") == 0) {
                                    std::string hex;
                                    if (HashFileSHA256(filePath, hex)) {
                                        std::ostringstream ss;
                                        ss << "UEFI file: " << WideToUtf8(filePath) << " sha256=" << hex;
                                        logger.Log(ss.str(), "info");
                                    }
                                    else {
                                        logger.Log("UEFI: Failed to hash file " + WideToUtf8(filePath), "warning");
                                    }
                                }
                            }
                        } while (FindNextFileW(hFind2, &fd2));
                        FindClose(hFind2);
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
        cur += wcslen(cur) + 1;
    }

    if (!anyEfiFound) {
        logger.Log("UEFI: No EFI root found on mounted drives", "info");
    }
}
