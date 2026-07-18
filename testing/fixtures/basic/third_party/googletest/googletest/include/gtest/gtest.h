// Google Test — stub header for demo fixture.
// Real library: https://github.com/google/googletest  (BSD-3-Clause)
// This stub provides the macro surface used by the demo tests.
#pragma once
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>

namespace testing {

/* ── Result accumulator ──────────────────────────────────────────── */
struct TestResult {
    bool passed = true;
    std::string failure_msg;
};

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void()> body;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}
inline int& failure_count() { static int n = 0; return n; }
inline TestResult& current_result() { static TestResult r; return r; }

inline void record_failure(const char* file, int line, const std::string& msg) {
    failure_count()++;
    current_result().passed = false;
    std::fprintf(stderr, "%s:%d: FAILED\n  %s\n", file, line, msg.c_str());
}

/* ── Public API ──────────────────────────────────────────────────── */
inline void InitGoogleTest(int* /*argc*/, char** /*argv*/) {}

inline int RUN_ALL_TESTS() {
    int passed = 0, failed = 0;
    for (auto& tc : registry()) {
        current_result() = {};
        std::printf("[ RUN      ] %s.%s\n", tc.suite.c_str(), tc.name.c_str());
        try {
            tc.body();
        } catch (const std::exception& e) {
            record_failure(__FILE__, 0, std::string("unexpected exception: ") + e.what());
        }
        if (current_result().passed) {
            std::printf("[       OK ] %s.%s\n", tc.suite.c_str(), tc.name.c_str());
            ++passed;
        } else {
            std::printf("[  FAILED  ] %s.%s\n", tc.suite.c_str(), tc.name.c_str());
            ++failed;
        }
    }
    std::printf("\n[==========] %d test(s) run.\n", passed + failed);
    std::printf("[  PASSED  ] %d test(s).\n", passed);
    if (failed) std::printf("[  FAILED  ] %d test(s).\n", failed);
    return failed > 0 ? 1 : 0;
}

/* ── Registrar helper ────────────────────────────────────────────── */
struct Registrar {
    Registrar(const char* suite, const char* name, std::function<void()> fn) {
        registry().push_back({suite, name, std::move(fn)});
    }
};

} // namespace testing

/* ── Assertion macros ────────────────────────────────────────────── */
#define EXPECT_TRUE(cond) \
    do { if (!(cond)) testing::record_failure(__FILE__, __LINE__, \
        "Expected true: " #cond); } while (0)

#define EXPECT_FALSE(cond) \
    do { if ((cond)) testing::record_failure(__FILE__, __LINE__, \
        "Expected false: " #cond); } while (0)

#define EXPECT_EQ(a, b) \
    do { if (!((a) == (b))) { \
        std::ostringstream _os; _os << "Expected " #a " == " #b \
            ": " << (a) << " vs " << (b); \
        testing::record_failure(__FILE__, __LINE__, _os.str()); } } while (0)

#define EXPECT_NE(a, b) \
    do { if (!((a) != (b))) testing::record_failure(__FILE__, __LINE__, \
        "Expected " #a " != " #b); } while (0)

#define EXPECT_LT(a, b) \
    do { if (!((a) < (b))) testing::record_failure(__FILE__, __LINE__, \
        "Expected " #a " < " #b); } while (0)

#define EXPECT_LE(a, b) \
    do { if (!((a) <= (b))) testing::record_failure(__FILE__, __LINE__, \
        "Expected " #a " <= " #b); } while (0)

#define EXPECT_GT(a, b) \
    do { if (!((a) > (b))) testing::record_failure(__FILE__, __LINE__, \
        "Expected " #a " > " #b); } while (0)

#define EXPECT_GE(a, b) \
    do { if (!((a) >= (b))) testing::record_failure(__FILE__, __LINE__, \
        "Expected " #a " >= " #b); } while (0)

#define EXPECT_NEAR(a, b, tol) \
    do { auto _d = (a) - (b); if (_d < -(tol) || _d > (tol)) { \
        std::ostringstream _os; _os << #a " ≈ " #b " (tol=" << (tol) << ")"; \
        testing::record_failure(__FILE__, __LINE__, _os.str()); } } while (0)

#define EXPECT_DOUBLE_EQ(a, b) EXPECT_NEAR(a, b, 1e-9)

#define EXPECT_THROW(expr, exc_type) \
    do { bool _caught = false; \
        try { (expr); } catch (const exc_type&) { _caught = true; } \
        if (!_caught) testing::record_failure(__FILE__, __LINE__, \
            "Expected " #exc_type " from: " #expr); } while (0)

#define ASSERT_EQ(a, b) \
    do { if (!((a) == (b))) { \
        std::ostringstream _os; _os << "ASSERT " #a " == " #b \
            ": " << (a) << " vs " << (b); \
        testing::record_failure(__FILE__, __LINE__, _os.str()); \
        return; } } while (0)

/* ── TEST macro ──────────────────────────────────────────────────── */
#define TEST(Suite, Name) \
    static void _test_##Suite##_##Name(); \
    static testing::Registrar _reg_##Suite##_##Name(#Suite, #Name, \
        _test_##Suite##_##Name); \
    static void _test_##Suite##_##Name()
