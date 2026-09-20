#include <iostream>
#include <string>

// A line read with std::getline, checked character by character.
int main() {
    std::string line;
    std::cout << "Password: ";
    std::getline(std::cin, line);
    if (line.size() != 9) {
        std::cout << "Denied\n";
        return 1;
    }
    for (std::size_t i = 0; i < line.size(); i++) {
        if ((line[i] ^ (char)(i + 1)) != "cpp_1s_fun"[i]) {
            std::cout << "Denied\n";
            return 1;
        }
    }
    std::cout << "Access granted\n";
    return 0;
}
