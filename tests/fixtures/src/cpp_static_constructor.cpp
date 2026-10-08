#include <iostream>
#include <string>

// The key table is built before main by a global constructor.
static unsigned char table[16];

namespace {
struct Setup {
    Setup() {
        for (int i = 0; i < 16; i++) {
            table[i] = (unsigned char)(i * 7 + 3);
        }
    }
};
const Setup setup;
}  // namespace

int main() {
    static const unsigned char expected[6] = {0x70, 0x7e, 0x25, 0x6c, 0x2e, 0x45};
    std::string line;
    std::getline(std::cin, line);
    if (line.size() != 6) {
        std::cout << "Wrong\n";
        return 1;
    }
    for (std::size_t i = 0; i < 6; i++) {
        if ((unsigned char)(line[i] ^ table[i]) != expected[i]) {
            std::cout << "Wrong\n";
            return 1;
        }
    }
    std::cout << "Correct!\n";
    return 0;
}
