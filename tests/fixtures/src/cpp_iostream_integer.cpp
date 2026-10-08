#include <iostream>

// A number read with std::cin >>, not a string.
int main() {
    int value = 0;
    std::cin >> value;
    if (value * 3 + 7 == 3781) {
        std::cout << "Correct!\n";
        return 0;
    }
    std::cout << "Wrong\n";
    return 1;
}
