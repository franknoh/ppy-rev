#include <iostream>
#include <string>

// A range-for over the string: the iterator loop compilers like to unroll.
int main() {
    std::string line;
    std::getline(std::cin, line);
    unsigned rolling = 7;
    std::size_t count = 0;
    for (char c : line) {
        rolling = ((rolling << 3) ^ (unsigned char)c) & 0xffffu;
        count++;
    }
    if (count == 6 && rolling == 0x7fb9u) {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Wrong\n";
    return 1;
}
