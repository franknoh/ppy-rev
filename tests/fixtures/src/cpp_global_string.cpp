#include <iostream>
#include <string>

// A global std::string built before main, compared against the input.
static const std::string secret = "gl0bal_str";

int main() {
    std::string line;
    std::getline(std::cin, line);
    if (line == secret) {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Wrong\n";
    return 1;
}
