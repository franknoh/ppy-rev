#include <iostream>
#include <string>
#include <vector>

// The input pushed into a std::vector, then summed: heap allocation on the checked path.
int main() {
    std::string line;
    std::getline(std::cin, line);
    if (line.size() != 6) {
        std::cout << "Wrong\n";
        return 1;
    }
    std::vector<int> values;
    for (std::size_t i = 0; i < line.size(); i++) {
        values.push_back((unsigned char)line[i] * 3 + (int)i);
    }
    int total = 0;
    for (int value : values) {
        total += value;
    }
    if (total == 1803 && values[0] == 'v' * 3) {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Wrong\n";
    return 1;
}
