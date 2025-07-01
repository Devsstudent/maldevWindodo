#include <windows.h>


__declspec(code_seg("inject"))

int main_inject(int a) {
    return a * 2600;
}