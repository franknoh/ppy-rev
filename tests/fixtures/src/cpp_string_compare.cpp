#include <iostream>
#include <string>

// The classic: decode the argument and compare the whole string at once.
int main(int argc, char **argv) {
    if (argc != 2) {
        std::cout << "usage: chall <flag>\n";
        return 2;
    }
    std::string given(argv[1]);
    std::string decoded;
    for (std::size_t i = 0; i < given.size(); i++) {
        decoded += (char)(given[i] - 3);
    }
    if (decoded == "cpp_compare") {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Wrong\n";
    return 1;
}
