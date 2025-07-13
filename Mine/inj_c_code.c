#include <windows.h>
#include <stdio.h>
//#pragma section("inject", read, execute)

__declspec(code_seg("inject"))

int main_inject(int a) {
    printf("THIS IS A TEST BRUH\n");
    
    return a * 2600;
}