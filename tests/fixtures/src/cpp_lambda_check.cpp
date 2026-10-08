#include <iostream>
#include <string>

// A lambda called per character, the shape an optimizer inlines away entirely.
int main() {
    static const char expected[6] = {0x6c, 0x37, 0x73, 0x6b, 0x70, 0x70};
    std::string line;
    std::getline(std::cin, line);
    auto matches = [&line](std::size_t i) {
        return (char)((unsigned char)line[i] + 3 * (unsigned char)i) == expected[i];
    };
    if (line.size() != 6) {
        std::cout << "Nope\n";
        return 1;
    }
    for (std::size_t i = 0; i < 6; i++) {
        if (!matches(i)) {
            std::cout << "Nope\n";
            return 1;
        }
    }
    std::cout << "Correct!\n";
    return 0;
}
