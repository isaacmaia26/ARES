#include "MemoryScanner.h"
#include "../core/Utils.h"
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>

MEMORY_SCANNER::MEMORY_SCANNER() {}
MEMORY_SCANNER::~MEMORY_SCANNER() {}

bool MEMORY_SCANNER::ReadRemote(HANDLE hProc, LPCVOID addr, LPVOID buffer, SIZE_T size, SIZE_T* outRead)
{
    SIZE_T read = 0;
    BOOL ok = ReadProcessMemory(hProc, addr, buffer, size, &read);
    if (outRead) *outRead = read;
    return ok == TRUE;
}

bool MEMORY_SCANNER::IsExecutableProtect(DWORD protect)
{
    protect &= 0xFF;
    return (protect == PAGE_EXECUTE_READ) || (protect == PAGE_EXECUTE_READWRITE) || (protect == PAGE_EXECUTE_WRITECOPY) || (protect == PAGE_EXECUTE);
}

bool MEMORY_SCANNER::ContainsSyscallSignature(const unsigned char* buf, SIZE_T len)
{
    for (SIZE_T i = 0; i + 1 < len; ++i) {
        if (buf[i] == 0x0F && buf[i + 1] == 0x05) return true;
        if (buf[i] == 0x0F && buf[i + 1] == 0x34) return true;
    }
    return false;
}

bool MEMORY_SCANNER::IsPEHeader(const unsigned char* buf, SIZE_T len)
{
    if (len < 2) return false;
    return (buf[0] == 'M' && buf[1] == 'Z');
}

double MEMORY_SCANNER::SampleEntropy(const unsigned char* buf, SIZE_T len)
{
    return Utils::Entropy(buf, len);
}

std::string MEMORY_SCANNER::MakeDumpPath(DWORD pid, SIZE_T base)
{
    std::ostringstream ss;
    ss << "logs\\dumps";
    CreateDirectoryA("logs", NULL);
    CreateDirectoryA("logs\\dumps", NULL);
    ss << "\\pid_" << pid << "_0x" << std::hex << base << ".bin";
    return ss.str();
}

bool MEMORY_SCANNER::DumpRegionIfShellcode(DWORD pid, SIZE_T base, const unsigned char* buf, SIZE_T len, Logger& logger)
{
    double ent = SampleEntropy(buf, len);
    bool hasSys = ContainsSyscallSignature(buf, len);
    if (hasSys || ent >= 7.5) {
        std::string path = MakeDumpPath(pid, base);
        std::ofstream ofs(path, std::ios::binary);
        if (ofs) {
            ofs.write((const char*)buf, len);
            ofs.close();
            std::ostringstream ss;
            ss << "Dumped suspicious region pid=" << pid << " base=0x" << std::hex << base << " size=" << std::dec << len << " entropy=" << ent << " syscall=" << (hasSys ? "yes" : "no");
            logger.Log(ss.str(), "suspicious");
            return true;
        }
        else {
            logger.Log("Failed to write dump file: " + path, "warning");
        }
    }
    return false;
}

void MEMORY_SCANNER::ScanProcessMemory(DWORD pid, Logger& logger)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        logger.Log("MemoryScanner: OpenProcess failed for PID " + std::to_string(pid), "warning");
        return;
    }

    SIZE_T addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    const SIZE_T CHUNK = 1024 * 1024;
    while (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            bool exec = IsExecutableProtect((DWORD)mbi.Protect);
            bool rwx = ((mbi.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) || ((mbi.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY);
            SIZE_T regionSize = mbi.RegionSize;
            SIZE_T baseAddr = (SIZE_T)mbi.BaseAddress;
            std::vector<unsigned char> buffer;
            buffer.resize(regionSize > CHUNK ? CHUNK : regionSize);
            SIZE_T offset = 0;
            bool regionFlagged = false;
            while (offset < regionSize) {
                SIZE_T toRead = (regionSize - offset) > buffer.size() ? buffer.size() : (regionSize - offset);
                SIZE_T actuallyRead = 0;
                if (!ReadRemote(hProc, (LPCVOID)(baseAddr + offset), buffer.data(), toRead, &actuallyRead) || actuallyRead == 0) break;
                if (exec || rwx) {
                    double ent = SampleEntropy(buffer.data(), actuallyRead);
                    bool hasPE = IsPEHeader(buffer.data(), actuallyRead);
                    bool hasSys = ContainsSyscallSignature(buffer.data(), actuallyRead);
                    if (rwx) {
                        std::ostringstream ss;
                        ss << "RWX chunk pid=" << pid << " base=0x" << std::hex << (baseAddr + offset) << " size=" << std::dec << actuallyRead << " entropy=" << ent;
                        logger.Log(ss.str(), "suspicious");
                        regionFlagged = true;
                    }
                    else if (exec) {
                        if (hasPE) {
                            std::ostringstream ss;
                            ss << "PE header in executable region pid=" << pid << " addr=0x" << std::hex << (baseAddr + offset);
                            logger.Log(ss.str(), "suspicious");
                            regionFlagged = true;
                        }
                        if (hasSys) {
                            std::ostringstream ss;
                            ss << "Syscall signature found pid=" << pid << " addr=0x" << std::hex << (baseAddr + offset);
                            logger.Log(ss.str(), "suspicious");
                            regionFlagged = true;
                        }
                        if (ent >= 7.5) {
                            std::ostringstream ss;
                            ss << "High entropy in exec region pid=" << pid << " addr=0x" << std::hex << (baseAddr + offset) << " entropy=" << ent;
                            logger.Log(ss.str(), "suspicious");
                            regionFlagged = true;
                        }
                    }
                    if (regionFlagged && DumpRegionIfShellcode(pid, baseAddr + offset, buffer.data(), actuallyRead, logger)) {
                        // dumped
                    }
                }
                else {
                    double ent = SampleEntropy(buffer.data(), actuallyRead);
                    if (ent >= 7.9) {
                        std::ostringstream ss;
                        ss << "High entropy non-exec region pid=" << pid << " addr=0x" << std::hex << (baseAddr + offset) << " entropy=" << ent;
                        logger.Log(ss.str(), "suspicious");
                        regionFlagged = true;
                        if (DumpRegionIfShellcode(pid, baseAddr + offset, buffer.data(), actuallyRead, logger)) {
                        }
                    }
                }
                offset += actuallyRead;
            }
            if (!regionFlagged) {
                std::ostringstream ss;
                ss << "Memory region benign pid=" << pid << " base=0x" << std::hex << baseAddr << " size=" << std::dec << regionSize;
                logger.Log(ss.str(), "info");
            }
        }
        addr = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProc);
}
