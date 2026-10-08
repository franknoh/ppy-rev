#include <iostream>
#include <string>

// operator[] and at() on a std::string, with a per-position transformation.
int main() {
    std::string line;
    std::getline(std::cin, line);
    if (line.size() != 8) {
        std::cout << "Wrong\n";
        return 1;
    }
    static const char expected[8] = {0x52, 0x35, 0x7a, 0x39, 0x7a, 0x7d, 0x3f, 0x2f};
    for (std::size_t i = 0; i < 8; i++) {
        char c = line.at(i);
        if ((char)(c + (char)(i * 2)) != expected[i]) {
            std::cout << "Wrong\n";
            return 1;
        }
    }
    std::cout << "Correct!\n";
    return 0;
}
