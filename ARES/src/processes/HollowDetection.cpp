#include "HollowDetection.h"
#include "../core/Utils.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <fstream>
#include <sstream>

#pragma comment(lib, "psapi.lib")

HOLLOW_DETECTOR::HOLLOW_DETECTOR() {}
HOLLOW_DETECTOR::~HOLLOW_DETECTOR() {}

std::string HOLLOW_DETECTOR::WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

bool HOLLOW_DETECTOR::ReadRemoteMemory(HANDLE hProcess, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outRead)
{
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(hProcess, addr, buffer, size, &read);
    if (outRead) *outRead = read;
    return ok == TRUE;
}

void HOLLOW_DETECTOR::AnalyzeProcess(DWORD pid, Logger& logger)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProc) {
        logger.Log("HollowDetection: Cannot open PID " + std::to_string(pid) + " (OpenProcess failed).", "warning");
        return;
    }

    bool suspicious = false;
    std::ostringstream summary;
    summary << "PID " << pid << " analysis:";

    if (CheckImagePathMismatch(hProc, pid, logger)) {
        suspicious = true;
        summary << " [ImagePathMismatch]";
    }

    if (CheckRWXRegions(hProc, pid, logger)) {
        suspicious = true;
        summary << " [RWXRegions]";
    }

    if (CheckInMemoryPE(hProc, pid, logger)) {
        suspicious = true;
        summary << " [InMemoryPE]";
    }

    if (CheckModuleEntropyVsDisk(hProc, pid, logger)) {
        suspicious = true;
        summary << " [ModuleEntropyMismatch]";
    }

    if (CheckSectionConsistency(hProc, pid, logger)) {
        suspicious = true;
        summary << " [SectionInconsistency]";
    }

    if (CheckThreadStartAddresses(hProc, pid, logger)) {
        suspicious = true;
        summary << " [ThreadStartSuspicious]";
    }

    if (suspicious) {
        logger.Log(summary.str(), "suspicious");
    }
    else {
        logger.Log("PID " + std::to_string(pid) + " - no hollowing indicators found.", "info");
    }

    CloseHandle(hProc);
}

bool HOLLOW_DETECTOR::CheckImagePathMismatch(HANDLE hProcess, DWORD pid, Logger& logger)
{
    WCHAR procPath[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, procPath, &size)) {
        logger.Log("CheckImagePathMismatch: QueryFullProcessImageNameW failed for PID " + std::to_string(pid), "warning");
        return false;
    }
    std::wstring wProcPath(procPath);
    std::string procPathUtf = WideToUtf8(wProcPath);

    HMODULE mods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &cbNeeded)) {
        logger.Log("CheckImagePathMismatch: EnumProcessModules failed for PID " + std::to_string(pid), "warning");
        return false;
    }
    if (cbNeeded < sizeof(HMODULE)) {
        logger.Log("CheckImagePathMismatch: No modules found for PID " + std::to_string(pid), "info");
        return false;
    }

    WCHAR modPath[MAX_PATH];
    if (!GetModuleFileNameExW(hProcess, mods[0], modPath, MAX_PATH)) {
        logger.Log("CheckImagePathMismatch: GetModuleFileNameExW failed for PID " + std::to_string(pid), "warning");
        return false;
    }
    std::wstring wModPath(modPath);
    std::string modPathUtf = WideToUtf8(wModPath);

    if (_wcsicmp(wProcPath.c_str(), wModPath.c_str()) != 0) {
        logger.Log("ImagePathMismatch: ProcessImageName='" + procPathUtf + "' mainModule='" + modPathUtf + "'", "suspicious");
        return true;
    }

    DWORD dwAttr = GetFileAttributesW(wModPath.c_str());
    if (dwAttr == INVALID_FILE_ATTRIBUTES) {
        logger.Log("ImagePathMismatch: Main module path not found on disk: " + modPathUtf, "suspicious");
        return true;
    }

    return false;
}

bool HOLLOW_DETECTOR::CheckRWXRegions(HANDLE hProcess, DWORD pid, Logger& logger)
{
    SIZE_T offset = 0;
    MEMORY_BASIC_INFORMATION mbi;
    bool found = false;
    while (VirtualQueryEx(hProcess, (LPCVOID)offset, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            DWORD prot = mbi.Protect & 0xFF;
            if (prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY) {
                std::ostringstream ss;
                ss << "RWX region at " << mbi.BaseAddress << " size=" << mbi.RegionSize;
                logger.Log(ss.str(), "suspicious");
                found = true;
            }
        }
        offset = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!found) {
        logger.Log("No RWX regions found for PID " + std::to_string(pid), "info");
    }
    return found;
}

bool HOLLOW_DETECTOR::CheckInMemoryPE(HANDLE hProcess, DWORD pid, Logger& logger)
{
    std::vector<HMODULE> modules(1024);
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProcess, modules.data(), (DWORD)(modules.size() * sizeof(HMODULE)), &cbNeeded)) {
        logger.Log("CheckInMemoryPE: EnumProcessModules failed for PID " + std::to_string(pid), "warning");
        return false;
    }
    size_t moduleCount = cbNeeded / sizeof(HMODULE);
    modules.resize(moduleCount);

    SIZE_T offset = 0;
    MEMORY_BASIC_INFORMATION mbi;
    bool foundPEinUnmapped = false;
    while (VirtualQueryEx(hProcess, (LPCVOID)offset, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) == 0) {
            bool isModuleRange = false;
            for (auto& m : modules) {
                if ((SIZE_T)m == (SIZE_T)mbi.AllocationBase) {
                    isModuleRange = true; break;
                }
            }
            if (!isModuleRange && mbi.RegionSize >= 0x1000) {
                unsigned char buf[2] = { 0 };
                SIZE_T read = 0;
                if (ReadRemoteMemory(hProcess, mbi.BaseAddress, buf, 2, &read) && read == 2) {
                    if (buf[0] == 'M' && buf[1] == 'Z') {
                        std::ostringstream ss;
                        ss << "PE header found in non-module region at " << mbi.BaseAddress << " size=" << mbi.RegionSize;
                        logger.Log(ss.str(), "suspicious");
                        foundPEinUnmapped = true;
                    }
                }
            }
        }
        offset = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!foundPEinUnmapped) {
        logger.Log("No in-memory PE found outside modules for PID " + std::to_string(pid), "info");
    }
    return foundPEinUnmapped;
}

bool HOLLOW_DETECTOR::CheckModuleEntropyVsDisk(HANDLE hProcess, DWORD pid, Logger& logger)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        logger.Log("CheckModuleEntropyVsDisk: EnumProcessModules failed for PID " + std::to_string(pid), "warning");
        return false;
    }

    bool flagged = false;
    size_t modCount = cbNeeded / sizeof(HMODULE);
    for (size_t i = 0; i < modCount; ++i)
    {
        WCHAR modName[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) continue;
        std::wstring wmod(modName);
        std::string modPathUtf = WideToUtf8(wmod);

        const SIZE_T sampleSize = 64 * 1024;
        std::vector<unsigned char> memSample(sampleSize);
        SIZE_T read = 0;
        if (!ReadRemoteMemory(hProcess, (LPCVOID)hMods[i], memSample.data(), sampleSize, &read) || read < 1024) {
            continue;
        }

        double memEntropy = Utils::Entropy(memSample.data(), read);

        std::ifstream ifs(modPathUtf, std::ios::binary);
        if (!ifs) {
            continue;
        }
        std::vector<unsigned char> fileSample(read);
        ifs.read((char*)fileSample.data(), read);
        SIZE_T fileRead = (SIZE_T)ifs.gcount();
        if (fileRead < 256) continue;

        double fileEntropy = Utils::Entropy(fileSample.data(), fileRead);

        double diff = fabs(memEntropy - fileEntropy);

        if (diff > 1.5) {
            std::ostringstream ss;
            ss << "Module entropy mismatch for '" << modPathUtf << "' memEntropy=" << memEntropy
                << " fileEntropy=" << fileEntropy << " diff=" << diff;
            logger.Log(ss.str(), "suspicious");
            flagged = true;
        }
    }

    if (!flagged) {
        logger.Log("Module entropy comparison: no major discrepancies for PID " + std::to_string(pid), "info");
    }
    return flagged;
}

bool HOLLOW_DETECTOR::CheckSectionConsistency(HANDLE hProcess, DWORD pid, Logger& logger)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        logger.Log("CheckSectionConsistency: EnumProcessModules failed for PID " + std::to_string(pid), "warning");
        return false;
    }

    bool anyInconsistency = false;
    size_t modCount = cbNeeded / sizeof(HMODULE);
    for (size_t i = 0; i < modCount; ++i)
    {
        IMAGE_DOS_HEADER dos = { 0 };
        SIZE_T read = 0;
        if (!ReadRemoteMemory(hProcess, (LPCVOID)hMods[i], &dos, sizeof(dos), &read) || read != sizeof(dos)) continue;
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) continue;

        DWORD ntSign = 0;
        LPVOID ntHeaderAddr = (LPBYTE)hMods[i] + dos.e_lfanew;
        if (!ReadRemoteMemory(hProcess, ntHeaderAddr, &ntSign, sizeof(ntSign), &read) || read != sizeof(ntSign)) continue;
        if (ntSign != IMAGE_NT_SIGNATURE) continue;

        IMAGE_FILE_HEADER fh = { 0 };
        if (!ReadRemoteMemory(hProcess, (LPBYTE)ntHeaderAddr + sizeof(DWORD), &fh, sizeof(fh), &read) || read != sizeof(fh)) continue;

        WCHAR modName[MAX_PATH];
        if (!GetModuleFileNameExW(hProcess, hMods[i], modName, MAX_PATH)) continue;
        std::wstring wmod(modName);
        std::string modPathUtf = WideToUtf8(wmod);
        std::ifstream ifs(modPathUtf, std::ios::binary);
        if (!ifs) continue;

        IMAGE_DOS_HEADER dos_disk;
        ifs.read((char*)&dos_disk, sizeof(dos_disk));
        if (ifs.gcount() != sizeof(dos_disk)) continue;
        if (dos_disk.e_magic != IMAGE_DOS_SIGNATURE) continue;

        ifs.seekg(dos_disk.e_lfanew, std::ios::beg);
        DWORD ntSignDisk = 0;
        ifs.read((char*)&ntSignDisk, sizeof(ntSignDisk));
        if (ifs.gcount() != sizeof(ntSignDisk)) continue;
        if (ntSignDisk != IMAGE_NT_SIGNATURE) continue;

        IMAGE_FILE_HEADER fh_disk;
        ifs.read((char*)&fh_disk, sizeof(fh_disk));
        if (ifs.gcount() != sizeof(fh_disk)) continue;

        if (fh.NumberOfSections != fh_disk.NumberOfSections || fh.TimeDateStamp != fh_disk.TimeDateStamp) {
            std::ostringstream ss;
            ss << "Section/header mismatch for '" << modPathUtf << "' MemSections=" << fh.NumberOfSections
                << " DiskSections=" << fh_disk.NumberOfSections << " MemTime=" << fh.TimeDateStamp
                << " DiskTime=" << fh_disk.TimeDateStamp;
            logger.Log(ss.str(), "suspicious");
            anyInconsistency = true;
        }
    }

    if (!anyInconsistency) {
        logger.Log("Section consistency: no major inconsistencies for PID " + std::to_string(pid), "info");
    }
    return anyInconsistency;
}

bool HOLLOW_DETECTOR::CheckThreadStartAddresses(HANDLE hProcess, DWORD pid, Logger& logger)
{
    bool suspicious = false;

    std::vector<std::pair<SIZE_T, SIZE_T>> rwxRegions;
    SIZE_T offset = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(hProcess, (LPCVOID)offset, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            DWORD prot = mbi.Protect & 0xFF;
            if (prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY || prot == PAGE_EXECUTE_READ) {
                rwxRegions.push_back({ (SIZE_T)mbi.BaseAddress, (SIZE_T)mbi.BaseAddress + mbi.RegionSize });
            }
        }
        offset = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        logger.Log("CheckThreadStartAddresses: CreateToolhelp32Snapshot failed", "warning");
        return false;
    }

    THREADENTRY32 te; te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;
            std::ostringstream s;
            s << "Thread detected TID=" << te.th32ThreadID << " (owner PID=" << te.th32OwnerProcessID << ") - start address heuristics unavailable (requires undocumented query).";
            logger.Log(s.str(), "info");
            CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);

    logger.Log("Thread start address check: limited heuristic (no direct start addresses) - consider enabling NtQueryInformationThread for stronger detection.", "info");

    return suspicious;
}
