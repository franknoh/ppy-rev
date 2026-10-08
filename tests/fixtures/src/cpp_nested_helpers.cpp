#include <iostream>
#include <string>

// Helpers taking the string by reference: the call graph an inliner flattens.
__attribute__((noinline)) static unsigned weigh(const std::string &text, std::size_t i) {
    return ((unsigned char)text[i] * (unsigned)(i + 2)) % 251;
}

__attribute__((noinline)) static unsigned total(const std::string &text) {
    unsigned sum = 0;
    for (std::size_t i = 0; i < text.size(); i++) {
        sum += weigh(text, i);
    }
    return sum;
}

int main() {
    std::string line;
    std::getline(std::cin, line);
    if (line.size() == 7 && total(line) == 867 && line[0] == 'h') {
        std::cout << "Access granted\n";
        return 0;
    }
    std::cout << "Denied\n";
    return 1;
}
