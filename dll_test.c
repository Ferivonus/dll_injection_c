// dll_test.c
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) void notify(void) {
    // Konsola çýktý (DLL, çaðrýldýðý süreç bir konsol uygulamasý ise görünür)
    printf("enject successfull\n");

    // Ayrýca göze çarpmasý için bir MessageBox göster
    MessageBoxA(NULL, "enject successfull", "DLL", MB_OK | MB_ICONINFORMATION);
}

// DllMain boþ býrakýlabilir; burada hiçbir kritik iþlem yapmýyoruz
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // normalde aðýr iþ ya da API çaðrýlarý yapmamak en iyisi
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
