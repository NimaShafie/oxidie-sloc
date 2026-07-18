#include <gtest/gtest.h>
#include "string_utils.h"

/* ── to_lower / to_upper ──────────────────────────────────────────── */

TEST(StrCase, ToLowerMixed) {
    EXPECT_EQ(str::to_lower("Hello World"), "hello world");
    EXPECT_EQ(str::to_lower("ABC123"), "abc123");
    EXPECT_EQ(str::to_lower(""), "");
}

TEST(StrCase, ToUpperMixed) {
    EXPECT_EQ(str::to_upper("Hello World"), "HELLO WORLD");
    EXPECT_EQ(str::to_upper("abc"), "ABC");
    EXPECT_EQ(str::to_upper("123"), "123");
}

TEST(StrCase, RoundTrip) {
    const std::string s = "FoObAr";
    EXPECT_EQ(str::to_upper(str::to_lower(s)), "FOOBAR");
}

/* ── trim ─────────────────────────────────────────────────────────── */

TEST(StrTrim, Leading) {
    EXPECT_EQ(str::trim("   hello"), "hello");
}

TEST(StrTrim, Trailing) {
    EXPECT_EQ(str::trim("hello   "), "hello");
}

TEST(StrTrim, Both) {
    EXPECT_EQ(str::trim("  hello  "), "hello");
}

TEST(StrTrim, TabsAndNewlines) {
    EXPECT_EQ(str::trim("\t\nhello\r\n"), "hello");
}

TEST(StrTrim, AllWhitespace) {
    EXPECT_EQ(str::trim("   "), "");
    EXPECT_EQ(str::trim(""), "");
}

TEST(StrTrim, NoWhitespace) {
    EXPECT_EQ(str::trim("nospaces"), "nospaces");
}

/* ── split ────────────────────────────────────────────────────────── */

TEST(StrSplit, CommaDelimited) {
    auto p = str::split("a,b,c", ',');
    ASSERT_EQ(p.size(), 3u);
    EXPECT_EQ(p[0], "a");
    EXPECT_EQ(p[1], "b");
    EXPECT_EQ(p[2], "c");
}

TEST(StrSplit, SingleToken) {
    auto p = str::split("hello", ',');
    ASSERT_EQ(p.size(), 1u);
    EXPECT_EQ(p[0], "hello");
}

TEST(StrSplit, EmptyString) {
    auto p = str::split("", ',');
    ASSERT_EQ(p.size(), 1u);
    EXPECT_EQ(p[0], "");
}

TEST(StrSplit, TrailingDelimiter) {
    auto p = str::split("a,b,", ',');
    ASSERT_EQ(p.size(), 3u);
    EXPECT_EQ(p[2], "");
}

/* ── join ─────────────────────────────────────────────────────────── */

TEST(StrJoin, WithSeparator) {
    std::vector<std::string> v = {"one", "two", "three"};
    EXPECT_EQ(str::join(v, ", "), "one, two, three");
}

TEST(StrJoin, EmptySeparator) {
    std::vector<std::string> v = {"a", "b", "c"};
    EXPECT_EQ(str::join(v, ""), "abc");
}

TEST(StrJoin, EmptyList) {
    EXPECT_EQ(str::join({}, "-"), "");
}

TEST(StrJoin, SingleElement) {
    EXPECT_EQ(str::join({"only"}, ","), "only");
}

/* ── starts_with / ends_with ──────────────────────────────────────── */

TEST(StrPrefix, Match) {
    EXPECT_TRUE(str::starts_with("hello world", "hello"));
    EXPECT_FALSE(str::starts_with("hello world", "world"));
}

TEST(StrPrefix, EmptyPrefix) {
    EXPECT_TRUE(str::starts_with("abc", ""));
    EXPECT_TRUE(str::starts_with("", ""));
}

TEST(StrSuffix, Match) {
    EXPECT_TRUE(str::ends_with("hello world", "world"));
    EXPECT_FALSE(str::ends_with("hello world", "hello"));
}

TEST(StrSuffix, EmptySuffix) {
    EXPECT_TRUE(str::ends_with("abc", ""));
}

/* ── replace_all ──────────────────────────────────────────────────── */

TEST(StrReplaceAll, Single) {
    EXPECT_EQ(str::replace_all("foo bar", "bar", "baz"), "foo baz");
}

TEST(StrReplaceAll, Multiple) {
    EXPECT_EQ(str::replace_all("aaa", "a", "bb"), "bbbbbb");
}

TEST(StrReplaceAll, NoMatch) {
    EXPECT_EQ(str::replace_all("hello", "xyz", "abc"), "hello");
}

TEST(StrReplaceAll, EmptyFrom) {
    EXPECT_EQ(str::replace_all("abc", "", "x"), "abc");
}

/* ── count_occurrences ────────────────────────────────────────────── */

TEST(StrCount, Present) {
    EXPECT_EQ(str::count_occurrences("banana", "a"), 3);
    EXPECT_EQ(str::count_occurrences("aaa", "aa"), 1);  // non-overlapping
}

TEST(StrCount, Absent) {
    EXPECT_EQ(str::count_occurrences("hello", "z"), 0);
}

TEST(StrCount, EmptyNeedle) {
    EXPECT_EQ(str::count_occurrences("hello", ""), 0);
}

/* ── reverse ──────────────────────────────────────────────────────── */

TEST(StrReverse, Basic) {
    EXPECT_EQ(str::reverse("abcde"), "edcba");
    EXPECT_EQ(str::reverse("A"), "A");
    EXPECT_EQ(str::reverse(""), "");
}

TEST(StrReverse, Palindrome) {
    const std::string p = "racecar";
    EXPECT_EQ(str::reverse(p), p);
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
