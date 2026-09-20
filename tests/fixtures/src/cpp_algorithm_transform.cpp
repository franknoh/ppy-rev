#include <algorithm>
#include <iostream>
#include <string>

// std::transform with a lambda, then whole-string comparison.
int main() {
    std::string line;
    std::getline(std::cin, line);
    std::transform(line.begin(), line.end(), line.begin(),
                   [](char c) { return (char)(c ^ 0x20); });
    if (line == "TRANSFORM") {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Wrong\n";
    return 1;
}
