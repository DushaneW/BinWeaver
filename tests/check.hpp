#pragma once
// Minimal test harness. Unlike assert(), CHECK stays active in Release
// builds (the previous test suite compiled to nothing under NDEBUG).
#include <cstdlib>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace bwtest {

struct Case {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

inline int& failures() {
    static int n = 0;
    return n;
}

struct Register {
    Register(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

inline void fail(const char* file, int line, const std::string& what) {
    ++failures();
    std::cerr << file << ':' << line << ": CHECK failed: " << what << '\n';
}

inline int run_all(int argc, char** argv) {
    const std::string filter = argc > 1 ? argv[1] : "";
    int ran = 0;
    for (const auto& c : registry()) {
        if (!filter.empty() && std::string(c.name).find(filter) == std::string::npos) continue;
        const int before = failures();
        try {
            c.fn();
        } catch (const std::exception& e) {
            fail(c.name, 0, std::string("unexpected exception: ") + e.what());
        }
        ++ran;
        std::cout << (failures() == before ? "[ ok ] " : "[FAIL] ") << c.name << '\n';
    }
    std::cout << ran << " test cases, " << failures() << " failed checks\n";
    return failures() == 0 && ran > 0 ? 0 : 1;
}

} // namespace bwtest

#define BW_CONCAT2(a, b) a##b
#define BW_CONCAT(a, b) BW_CONCAT2(a, b)
#define TEST_CASE(name)                                                                     \
    static void BW_CONCAT(bw_test_fn_, __LINE__)();                                         \
    static const bwtest::Register BW_CONCAT(bw_test_reg_, __LINE__)(name, BW_CONCAT(bw_test_fn_, __LINE__)); \
    static void BW_CONCAT(bw_test_fn_, __LINE__)()

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) bwtest::fail(__FILE__, __LINE__, #expr);           \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        const auto bw_a_ = (a);                                                           \
        const auto bw_b_ = (b);                                                           \
        if (!(bw_a_ == bw_b_)) {                                                           \
            std::ostringstream bw_s_;                                                      \
            bw_s_ << #a << " == " << #b << " (" << bw_a_ << " vs " << bw_b_ << ")";       \
            bwtest::fail(__FILE__, __LINE__, bw_s_.str());                                 \
        }                                                                                  \
    } while (0)

#define REQUIRE(expr)                                                   \
    do {                                                                \
        if (!(expr)) {                                                  \
            bwtest::fail(__FILE__, __LINE__, #expr);                    \
            return;                                                     \
        }                                                               \
    } while (0)
