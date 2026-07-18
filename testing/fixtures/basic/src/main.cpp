#include <iostream>
#include <iomanip>
#include "math_utils.h"
#include "string_utils.h"

static void print_section(const char* title) {
    std::cout << "\n" << title << "\n";
    std::cout << std::string(40, '-') << "\n";
}

int main(int /*argc*/, char* /*argv*/[]) {
    std::cout << "Demo Project — Math & String Utilities\n";
    std::cout << std::string(40, '=') << "\n";

    print_section("Arithmetic");
    std::cout << "  add(3, 4)          = " << math::add(3, 4) << "\n";
    std::cout << "  subtract(10, 3)    = " << math::subtract(10, 3) << "\n";
    std::cout << "  multiply(6, 7)     = " << math::multiply(6, 7) << "\n";
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "  divide(22, 7)      = " << math::divide(22, 7) << "\n";

    print_section("Exponentiation & combinatorics");
    std::cout << "  power(2, 10)       = " << math::power(2, 10) << "\n";
    std::cout << "  power(3, 5)        = " << math::power(3, 5) << "\n";
    std::cout << "  factorial(10)      = " << math::factorial(10) << "\n";
    std::cout << "  gcd(48, 18)        = " << math::gcd(48, 18) << "\n";

    print_section("Predicates & clamping");
    std::cout << "  is_prime(17)       = " << std::boolalpha << math::is_prime(17) << "\n";
    std::cout << "  is_prime(18)       = " << math::is_prime(18) << "\n";
    std::cout << "  clamp(150, 0, 100) = " << math::clamp(150, 0, 100) << "\n";
    std::cout << "  clamp(-5, 0, 100)  = " << math::clamp(-5, 0, 100) << "\n";

    print_section("String utilities");
    const std::string sample = "  Hello, World!  ";
    std::cout << "  trim(\"" << sample << "\") = \"" << str::trim(sample) << "\"\n";
    std::cout << "  to_lower()         = \"" << str::to_lower(str::trim(sample)) << "\"\n";
    std::cout << "  to_upper()         = \"" << str::to_upper(str::trim(sample)) << "\"\n";
    std::cout << "  reverse(\"abcde\")   = \"" << str::reverse("abcde") << "\"\n";

    auto words = str::split("one,two,three,four", ',');
    std::cout << "  split on ','       = " << words.size() << " tokens\n";
    std::cout << "  join(\" | \")        = \"" << str::join(words, " | ") << "\"\n";

    const std::string haystack = "banana";
    std::cout << "  count('a' in \"" << haystack << "\") = "
              << str::count_occurrences(haystack, "a") << "\n";

    return 0;
}
