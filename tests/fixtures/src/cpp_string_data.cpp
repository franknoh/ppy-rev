#include <cstring>
#include <iostream>
#include <string>

// The string's bytes handed to a C function: c_str() and data() reach the same buffer.
int main() {
    std::string line;
    std::getline(std::cin, line);
    const char *text = line.c_str();
    if (std::strlen(text) != 7) {
        std::cout << "Nope\n";
        return 1;
    }
    char scrambled[8];
    for (std::size_t i = 0; i < 7; i++) {
        scrambled[i] = (char)(line.data()[i] ^ 0x2a);
    }
    scrambled[7] = '\0';
    if (std::strcmp(scrambled, "Z]HHOLY") == 0) {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Nope\n";
    return 1;
}
