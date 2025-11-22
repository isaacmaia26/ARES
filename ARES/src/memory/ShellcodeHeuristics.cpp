#include "ShellcodeHeuristics.h"
#include "../core/Utils.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

SHELLCODE_HEURISTICS::SHELLCODE_HEURISTICS() {}
SHELLCODE_HEURISTICS::~SHELLCODE_HEURISTICS() {}

bool SHELLCODE_HEURISTICS::ContainsSyscall(const unsigned char* buf, SIZE_T len)
{
    for (SIZE_T i = 0; i + 1 < len; ++i) {
        if (buf[i] == 0x0F && buf[i + 1] == 0x05) return true;
        if (buf[i] == 0x0F && buf[i + 1] == 0x34) return true;
    }
    return false;
}

double SHELLCODE_HEURISTICS::EntropySample(const unsigned char* buf, SIZE_T len)
{
    return Utils::Entropy(buf, len);
}

double SHELLCODE_HEURISTICS::RetDensity(const unsigned char* buf, SIZE_T len)
{
    if (len == 0) return 0.0;
    SIZE_T count = 0;
    for (SIZE_T i = 0; i < len; ++i) if (buf[i] == 0xC3 || buf[i] == 0xC2) ++count;
    return (double)count / (double)len;
}

double SHELLCODE_HEURISTICS::PrintableRatio(const unsigned char* buf, SIZE_T len)
{
    if (len == 0) return 0.0;
    SIZE_T printable = 0;
    for (SIZE_T i = 0; i < len; ++i) {
        unsigned char c = buf[i];
        if (c >= 0x20 && c <= 0x7E) ++printable;
    }
    return (double)printable / (double)len;
}

double SHELLCODE_HEURISTICS::ConsecutiveZerosRatio(const unsigned char* buf, SIZE_T len)
{
    if (len == 0) return 0.0;
    SIZE_T maxZeros = 0;
    SIZE_T cur = 0;
    for (SIZE_T i = 0; i < len; ++i) {
        if (buf[i] == 0x00) {
            ++cur;
            if (cur > maxZeros) maxZeros = cur;
        }
        else cur = 0;
    }
    return (double)maxZeros / (double)len;
}

double SHELLCODE_HEURISTICS::AnalyzeBufferScore(const unsigned char* buf, SIZE_T len)
{
    double score = 0.0;
    double ent = EntropySample(buf, len);
    double retd = RetDensity(buf, len);
    double pr = PrintableRatio(buf, len);
    double zratio = ConsecutiveZerosRatio(buf, len);
    bool syscall = ContainsSyscall(buf, len);

    if (ent >= 7.5) score += 3.0;
    else if (ent >= 6.5) score += 1.0;

    if (syscall) score += 3.0;
    if (retd >= 0.005) score += 1.0;
    if (retd >= 0.02) score += 2.0;
    if (pr < 0.25) score += 1.0;
    if (zratio > 0.25) score -= 1.0;
    if (len < 512) score += 1.0;
    if (len >= 4096) score += 0.5;
    if (ent >= 7.9) score += 1.0;

    return score;
}

bool SHELLCODE_HEURISTICS::IsLikelyShellcode(const unsigned char* buf, SIZE_T len, double threshold)
{
    double s = AnalyzeBufferScore(buf, len);
    return s >= threshold;
}

std::string SHELLCODE_HEURISTICS::ExplainScore(const unsigned char* buf, SIZE_T len)
{
    std::ostringstream ss;
    double ent = EntropySample(buf, len);
    double retd = RetDensity(buf, len);
    double pr = PrintableRatio(buf, len);
    double zratio = ConsecutiveZerosRatio(buf, len);
    bool syscall = ContainsSyscall(buf, len);
    double score = AnalyzeBufferScore(buf, len);

    ss << std::fixed << std::setprecision(2);
    ss << "score=" << score << " entropy=" << ent << " retDensity=" << retd
        << " printableRatio=" << pr << " maxZeroRunRatio=" << zratio
        << " syscall=" << (syscall ? "yes" : "no");
    return ss.str();
}
