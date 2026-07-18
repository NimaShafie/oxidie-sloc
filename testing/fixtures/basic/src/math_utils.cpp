#include "math_utils.h"
#include <stdexcept>

namespace math {

int add(int a, int b) {
    return a + b;
}

int subtract(int a, int b) {
    return a - b;
}

int multiply(int a, int b) {
    return a * b;
}

double divide(int a, int b) {
    if (b == 0) {
        throw std::domain_error("division by zero");
    }
    return static_cast<double>(a) / static_cast<double>(b);
}

long long power(int base, unsigned int exp) {
    long long result = 1;
    long long b = base;
    /* Binary exponentiation: O(log exp) multiplications */
    while (exp > 0) {
        if (exp & 1u) {
            result *= b;
        }
        b *= b;
        exp >>= 1u;
    }
    return result;
}

long long factorial(unsigned int n) {
    if (n > 20u) {
        throw std::overflow_error("factorial: argument exceeds 20 (int64 overflow)");
    }
    long long result = 1;
    for (unsigned int i = 2u; i <= n; ++i) {
        result *= static_cast<long long>(i);
    }
    return result;
}

int clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

unsigned int gcd(unsigned int a, unsigned int b) {
    /* Euclidean algorithm */
    while (b != 0u) {
        unsigned int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

bool is_prime(unsigned int n) {
    if (n < 2u) return false;
    if (n == 2u) return true;
    if (n % 2u == 0u) return false;
    for (unsigned int i = 3u; i * i <= n; i += 2u) {
        if (n % i == 0u) return false;
    }
    return true;
}

} // namespace math
