#include <gtest/gtest.h>
#include <stdexcept>
#include "math_utils.h"

/* ── add ──────────────────────────────────────────────────────────── */

TEST(MathAdd, PositiveNumbers) {
    EXPECT_EQ(math::add(2, 3), 5);
    EXPECT_EQ(math::add(100, 200), 300);
    EXPECT_EQ(math::add(1, 1), 2);
}

TEST(MathAdd, NegativeNumbers) {
    EXPECT_EQ(math::add(-1, -2), -3);
    EXPECT_EQ(math::add(-5, 5), 0);
}

TEST(MathAdd, IdentityZero) {
    EXPECT_EQ(math::add(0, 0), 0);
    EXPECT_EQ(math::add(42, 0), 42);
    EXPECT_EQ(math::add(0, 99), 99);
}

/* ── subtract ─────────────────────────────────────────────────────── */

TEST(MathSubtract, Basic) {
    EXPECT_EQ(math::subtract(10, 3), 7);
    EXPECT_EQ(math::subtract(0, 5), -5);
    EXPECT_EQ(math::subtract(7, 7), 0);
}

/* ── multiply ─────────────────────────────────────────────────────── */

TEST(MathMultiply, Positive) {
    EXPECT_EQ(math::multiply(3, 4), 12);
    EXPECT_EQ(math::multiply(7, 8), 56);
}

TEST(MathMultiply, NegativeResult) {
    EXPECT_EQ(math::multiply(-2, 6), -12);
    EXPECT_EQ(math::multiply(5, -3), -15);
}

TEST(MathMultiply, ByZero) {
    EXPECT_EQ(math::multiply(99, 0), 0);
    EXPECT_EQ(math::multiply(0, 99), 0);
}

/* ── divide ───────────────────────────────────────────────────────── */

TEST(MathDivide, ExactDivision) {
    EXPECT_DOUBLE_EQ(math::divide(10, 2), 5.0);
    EXPECT_DOUBLE_EQ(math::divide(-6, 3), -2.0);
}

TEST(MathDivide, FractionalResult) {
    EXPECT_NEAR(math::divide(1, 3), 0.333333, 1e-5);
    EXPECT_NEAR(math::divide(22, 7), 3.142857, 1e-5);
}

TEST(MathDivide, DivisionByZeroThrows) {
    EXPECT_THROW(math::divide(1, 0), std::domain_error);
    EXPECT_THROW(math::divide(-99, 0), std::domain_error);
}

/* ── power ────────────────────────────────────────────────────────── */

TEST(MathPower, ZeroExponent) {
    EXPECT_EQ(math::power(2, 0), 1);
    EXPECT_EQ(math::power(0, 0), 1);  // convention
    EXPECT_EQ(math::power(-5, 0), 1);
}

TEST(MathPower, PositiveBase) {
    EXPECT_EQ(math::power(2, 10), 1024);
    EXPECT_EQ(math::power(3, 3), 27);
    EXPECT_EQ(math::power(10, 5), 100000);
}

TEST(MathPower, NegativeBase) {
    EXPECT_EQ(math::power(-2, 3), -8);
    EXPECT_EQ(math::power(-2, 4), 16);
}

/* ── factorial ────────────────────────────────────────────────────── */

TEST(MathFactorial, BaseAndSmall) {
    EXPECT_EQ(math::factorial(0), 1);
    EXPECT_EQ(math::factorial(1), 1);
    EXPECT_EQ(math::factorial(2), 2);
}

TEST(MathFactorial, LargerValues) {
    EXPECT_EQ(math::factorial(5), 120);
    EXPECT_EQ(math::factorial(10), 3628800LL);
    EXPECT_EQ(math::factorial(20), 2432902008176640000LL);
}

TEST(MathFactorial, OverflowThrows) {
    EXPECT_THROW(math::factorial(21), std::overflow_error);
}

/* ── clamp ────────────────────────────────────────────────────────── */

TEST(MathClamp, WithinRange) {
    EXPECT_EQ(math::clamp(50, 0, 100), 50);
    EXPECT_EQ(math::clamp(0, 0, 100), 0);
    EXPECT_EQ(math::clamp(100, 0, 100), 100);
}

TEST(MathClamp, BelowLowerBound) {
    EXPECT_EQ(math::clamp(-10, 0, 100), 0);
    EXPECT_EQ(math::clamp(-999, -100, 0), -100);
}

TEST(MathClamp, AboveUpperBound) {
    EXPECT_EQ(math::clamp(200, 0, 100), 100);
}

/* ── gcd ──────────────────────────────────────────────────────────── */

TEST(MathGcd, BasicCases) {
    EXPECT_EQ(math::gcd(12, 8), 4u);
    EXPECT_EQ(math::gcd(48, 18), 6u);
    EXPECT_EQ(math::gcd(100, 75), 25u);
}

TEST(MathGcd, Coprimes) {
    EXPECT_EQ(math::gcd(7, 13), 1u);
}

TEST(MathGcd, WithZero) {
    EXPECT_EQ(math::gcd(0, 5), 5u);
    EXPECT_EQ(math::gcd(5, 0), 5u);
}

/* ── is_prime ─────────────────────────────────────────────────────── */

TEST(MathIsPrime, SmallPrimes) {
    EXPECT_TRUE(math::is_prime(2));
    EXPECT_TRUE(math::is_prime(3));
    EXPECT_TRUE(math::is_prime(17));
    EXPECT_TRUE(math::is_prime(97));
}

TEST(MathIsPrime, Composites) {
    EXPECT_FALSE(math::is_prime(0));
    EXPECT_FALSE(math::is_prime(1));
    EXPECT_FALSE(math::is_prime(4));
    EXPECT_FALSE(math::is_prime(100));
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
