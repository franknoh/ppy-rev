#include <array>
#include <iostream>
#include <string>

// A std::array of expected bytes: a fixed-size container with no allocation.
int main() {
    static const std::array<unsigned char, 5> expected = {0x3b, 0x29, 0x2e, 0x69, 0x27};
    std::string line;
    std::getline(std::cin, line);
    if (line.size() != expected.size()) {
        std::cout << "Denied\n";
        return 1;
    }
    for (std::size_t i = 0; i < expected.size(); i++) {
        if ((unsigned char)(line[i] ^ (unsigned char)(0x5a + i)) != expected[i]) {
            std::cout << "Denied\n";
            return 1;
        }
    }
    std::cout << "Access granted\n";
    return 0;
}
