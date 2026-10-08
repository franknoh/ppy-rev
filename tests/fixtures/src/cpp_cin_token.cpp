#include <iostream>
#include <string>

// A whitespace-delimited token read with std::cin >>, then folded into a checksum.
int main() {
    std::string token;
    std::cin >> token;
    if (token.size() != 6) {
        std::cout << "Nope\n";
        return 1;
    }
    unsigned sum = 0;
    for (std::size_t i = 0; i < token.size(); i++) {
        sum = sum * 31 + (unsigned char)token[i];
    }
    if (sum == 0xaf4e69f8u) {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Nope\n";
    return 1;
}
