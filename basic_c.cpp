// basic_c.cpp : This file contains the 'main' function. Program execution begins and ends there.  
//  

#include <windows.h>  
#include <stdio.h>  
#include <iostream> 
#include <stdlib.h>


void iteration() {
    // Basit bir for döngüsü  
    for (int i = 1; i <= 5; ++i) {
        printf("Loop iteration %d\n", i);
        Sleep(500);
    }
}

int main()  
{
   printf("Hello World!\n");
   iteration();
   return 0;
}  