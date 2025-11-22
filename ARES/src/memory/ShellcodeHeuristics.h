#pragma once
#include <windows.h>
#include <string>
#include "../core/Logger.h"

class SHELLCODE_HEURISTICS {
public:
    SHELLCODE_HEURISTICS();
    ~SHELLCODE_HEURISTICS();
    double AnalyzeBufferScore(const unsigned char* buf, SIZE_T len);
    bool IsLikelyShellcode(const unsigned char* buf, SIZE_T len, double threshold = 7.0);
    std::string ExplainScore(const unsigned char* buf, SIZE_T len);
private:
    bool ContainsSyscall(const unsigned char* buf, SIZE_T len);
    double EntropySample(const unsigned char* buf, SIZE_T len);
    double RetDensity(const unsigned char* buf, SIZE_T len);
    double PrintableRatio(const unsigned char* buf, SIZE_T len);
    double ConsecutiveZerosRatio(const unsigned char* buf, SIZE_T len);
};
