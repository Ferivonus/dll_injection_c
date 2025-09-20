// dll_test.c
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) void notify(void) {
    // Konsola ��kt� (DLL, �a�r�ld��� s�re� bir konsol uygulamas� ise g�r�n�r)
    printf("enject successfull\n");

    // Ayr�ca g�ze �arpmas� i�in bir MessageBox g�ster
    MessageBoxA(NULL, "enject successfull", "DLL", MB_OK | MB_ICONINFORMATION);
}

// DllMain bo� b�rak�labilir; burada hi�bir kritik i�lem yapm�yoruz
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // normalde a��r i� ya da API �a�r�lar� yapmamak en iyisi
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
