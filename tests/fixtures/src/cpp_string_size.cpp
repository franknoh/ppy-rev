#include <iostream>
#include <string>

// size(), length() and empty() decide the answer together with a small sum.
int main() {
    std::string line;
    std::getline(std::cin, line);
    if (line.empty() || line.length() != 5) {
        std::cout << "Denied\n";
        return 1;
    }
    unsigned sum = 0;
    for (std::size_t i = 0; i < line.size(); i++) {
        sum += (unsigned char)line[i] * (unsigned)(i + 1);
    }
    if (sum == 1186 && line[0] == 0x70) {
        std::cout << "Access granted\n";
        return 0;
    }
    std::cout << "Denied\n";
    return 1;
}
