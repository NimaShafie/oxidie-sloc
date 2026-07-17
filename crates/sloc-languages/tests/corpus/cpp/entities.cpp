#include <string>
#include <vector>

namespace demo {

class Widget {
public:
    int id;
    std::string name;
    std::string render() const;
};

struct Point {
    int x;
    int y;
};

std::string Widget::render() const {
    std::string out = name;
    return out;
}

int add(int a, int b) {
    int sum = a + b;
    return sum;
}

std::vector<int> range(int n) {
    std::vector<int> result;
    for (int i = 0; i < n; ++i) {
        result.push_back(i);
    }
    return result;
}

bool is_even(int n);

}  // namespace demo
