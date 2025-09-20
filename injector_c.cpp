// injector.cpp
#include <stdio.h>
#include <windows.h>
#include <string.h>

int main() {
    char targetPath[MAX_PATH];
    char libraryPath[MAX_PATH];

    printf("Hedef EXE dosyasinin yolu: ");
    if (scanf_s("%s", targetPath, (unsigned)sizeof(targetPath)) != 1) {
        printf("Gecersiz girdi.\n");
        return 1;
    }

    printf("DLL dosyasinin yolu: ");
    if (scanf_s("%s", libraryPath, (unsigned)sizeof(libraryPath)) != 1) {
        printf("Gecersiz girdi.\n");
        return 1;
    }

    STARTUPINFOA StartInfo = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION ProcessInfo = { 0 };

    // Hedef sureci askiya alinmis durumda baslat
    BOOL success = CreateProcessA(
        targetPath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &StartInfo, &ProcessInfo
    );
    if (!success) {
        printf("Surec olusturulamadi! Hata Kodu: %d\n", GetLastError());
        return 1;
    }

    // kernel32.dll'nin adresini al
    HMODULE kernel32Handle = GetModuleHandleA("kernel32.dll");
    if (kernel32Handle == NULL) {
        printf("kernel32.dll bulunamadi.\n");
        return 1;
    }

    // LoadLibraryA fonksiyonunun adresini al
    FARPROC loadLibraryAddr = GetProcAddress(kernel32Handle, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        printf("LoadLibraryA fonksiyonu bulunamadi.\n");
        return 1;
    }

    // Hedef surecte DLL yolunu tutacak bellek ayir
    LPVOID remoteMemory = VirtualAllocEx(
        ProcessInfo.hProcess, NULL, strlen(libraryPath) + 1,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (remoteMemory == NULL) {
        printf("Hedef surecte bellek tahsisi yapilamadi.\n");
        return 1;
    }

    // DLL yolunu ayrilan bellek alanina yaz
    BOOL memoryWritten = WriteProcessMemory(
        ProcessInfo.hProcess, remoteMemory,
        libraryPath, strlen(libraryPath) + 1, NULL
    );
    if (!memoryWritten) {
        printf("Bellege yazma basarisiz oldu.\n");
        return 1;
    }

    // DLL'i yuklemek icin uzak bir thread olustur
    HANDLE remoteThread = CreateRemoteThread(
        ProcessInfo.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL
    );
    if (remoteThread == NULL) {
        printf("Uzak thread olusturulamadi.\n");
        return 1;
    }
    else {
        // Thread'in tamamlanmasini bekle
        WaitForSingleObject(remoteThread, INFINITE);
        CloseHandle(remoteThread);
    }

    // Ana thread'i devam ettir
    ResumeThread(ProcessInfo.hThread);

    // Islemleri temizle
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

    printf("DLL basariyla enjekte edildi.\n");
    return 0;
}
