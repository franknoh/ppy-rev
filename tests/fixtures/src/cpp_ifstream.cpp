#include <fstream>
#include <iostream>
#include <string>

// The flag is in a file the program opens, not in what the user types.
int main() {
    std::ifstream file("flag.txt");
    if (!file.is_open()) {
        std::cout << "No flag file\n";
        return 2;
    }
    std::string line;
    std::getline(file, line);
    if (line.size() != 7) {
        std::cout << "Wrong\n";
        return 1;
    }
    unsigned sum = 0;
    for (std::size_t i = 0; i < line.size(); i++) {
        sum = sum * 7 + (unsigned char)line[i];
    }
    if (sum == 0xc7f9f2u) {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Wrong\n";
    return 1;
}
