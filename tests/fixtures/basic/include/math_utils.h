#pragma once
#include <stdexcept>
#include <cstdint>

/**
 * @brief Mathematical utility functions for numeric operations.
 *
 * Provides a collection of arithmetic and numeric helpers that form
 * the computational core of the demo project.  All functions are
 * pure (no side-effects) and thread-safe.
 */
namespace math {

/// Adds two integers and returns the result.
int add(int a, int b);

/// Subtracts b from a.
int subtract(int a, int b);

/// Multiplies two integers.
int multiply(int a, int b);

/**
 * @brief Divides a by b as a floating-point value.
 * @throws std::domain_error if b is zero.
 */
double divide(int a, int b);

/// Computes base raised to exp using binary exponentiation.
long long power(int base, unsigned int exp);

/**
 * @brief Returns the factorial of n.
 * @throws std::overflow_error for n > 20 (would overflow int64).
 */
long long factorial(unsigned int n);

/// Clamps v to the closed interval [lo, hi].
int clamp(int v, int lo, int hi);

/// Returns the greatest common divisor of a and b (Euclidean algorithm).
unsigned int gcd(unsigned int a, unsigned int b);

/// Returns true when n is prime (trial-division, suitable for small n).
bool is_prime(unsigned int n);

} // namespace math
