// nlohmann/json — stub header for demo fixture.
// Real library: https://github.com/nlohmann/json  (MIT licence)
// This stub exposes just enough surface to compile the demo project.
#pragma once
#include <map>
#include <string>
#include <vector>
#include <stdexcept>
#include <initializer_list>
#include <utility>

namespace nlohmann {

class json {
public:
    enum class value_t { null, boolean, number_integer, number_float, string, array, object };

    json() = default;
    json(std::nullptr_t) {}                                            // NOLINT
    json(bool v) : type_(value_t::boolean), bool_(v) {}               // NOLINT
    json(int v) : type_(value_t::number_integer), int_(v) {}          // NOLINT
    json(double v) : type_(value_t::number_float), float_(v) {}       // NOLINT
    json(const char* v) : type_(value_t::string), str_(v) {}          // NOLINT
    json(std::string v) : type_(value_t::string), str_(std::move(v)) {} // NOLINT

    static json array() { json j; j.type_ = value_t::array; return j; }
    static json object() { json j; j.type_ = value_t::object; return j; }

    /* Structured-binding / initialiser-list construction omitted in stub. */
    static json parse(const std::string& text);
    std::string dump(int indent = -1) const;

    json& operator[](const std::string& key) { return obj_[key]; }
    const json& operator[](const std::string& key) const { return obj_.at(key); }
    json& operator[](std::size_t idx) { return arr_[idx]; }
    const json& operator[](std::size_t idx) const { return arr_[idx]; }
    json& at(const std::string& key) { return obj_.at(key); }

    bool contains(const std::string& key) const { return obj_.count(key) != 0; }
    bool is_null() const   { return type_ == value_t::null; }
    bool is_string() const { return type_ == value_t::string; }
    bool is_number() const {
        return type_ == value_t::number_integer || type_ == value_t::number_float;
    }
    bool is_array()  const { return type_ == value_t::array; }
    bool is_object() const { return type_ == value_t::object; }

    std::string get_string() const { return str_; }
    int get_int() const { return int_; }
    double get_double() const { return float_; }

    void push_back(json v) { type_ = value_t::array; arr_.push_back(std::move(v)); }
    std::size_t size() const { return is_array() ? arr_.size() : obj_.size(); }
    bool empty() const { return size() == 0; }

    using iterator = std::vector<json>::iterator;
    iterator begin() { return arr_.begin(); }
    iterator end()   { return arr_.end(); }

private:
    value_t type_ = value_t::null;
    bool    bool_  = false;
    int     int_   = 0;
    double  float_ = 0.0;
    std::string str_;
    std::vector<json> arr_;
    std::map<std::string, json> obj_;
};

} // namespace nlohmann
