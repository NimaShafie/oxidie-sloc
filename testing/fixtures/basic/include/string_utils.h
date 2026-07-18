#pragma once
#include <string>
#include <vector>

/**
 * @brief String manipulation utilities.
 *
 * All functions that take a std::string by value return a modified copy.
 * Functions taking const-ref return a new std::string.
 */
namespace str {

/// Converts every character to lowercase; returns the modified copy.
std::string to_lower(std::string s);

/// Converts every character to uppercase; returns the modified copy.
std::string to_upper(std::string s);

/// Strips leading and trailing ASCII whitespace (space, tab, CR, LF).
std::string trim(const std::string& s);

/// Splits s on delim and returns the resulting tokens.
std::vector<std::string> split(const std::string& s, char delim);

/// Joins parts with sep inserted between consecutive elements.
std::string join(const std::vector<std::string>& parts, const std::string& sep);

/// Returns true iff s begins with prefix.
bool starts_with(const std::string& s, const std::string& prefix);

/// Returns true iff s ends with suffix.
bool ends_with(const std::string& s, const std::string& suffix);

/// Replaces every non-overlapping occurrence of from with to in subject.
std::string replace_all(std::string subject,
                        const std::string& from,
                        const std::string& to);

/// Returns the number of times needle appears in haystack.
int count_occurrences(const std::string& haystack, const std::string& needle);

/// Reverses s in place and returns it.
std::string reverse(std::string s);

} // namespace str
