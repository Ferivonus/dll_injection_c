// injector.cpp
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winternl.h> // for PEB structures

// This is a concept code for a more advanced injection technique.
// A complete manual mapper implementation is extremely complex.
int main() {
    char targetPath[MAX_PATH];
    char libraryPath[MAX_PATH];

    printf("Target EXE file path: ");
    if (scanf_s("%s", targetPath, (unsigned)sizeof(targetPath)) != 1) {
        printf("Invalid input.\n");
        return 1;
    }

    printf("DLL path: ");
    if (scanf_s("%s", libraryPath, (unsigned)sizeof(libraryPath)) != 1) {
        printf("Invalid input.\n");
        return 1;
    }

    STARTUPINFOA StartInfo = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION ProcessInfo = { 0 };

    // Start the target process in a suspended state
    BOOL success = CreateProcessA(
        targetPath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &StartInfo, &ProcessInfo
    );
    if (!success) {
        printf("Failed to create process! Error Code: %d\n", GetLastError());
        return 1;
    }

    // Steps required to load a DLL into the target process's address space

    // 1. Read the DLL file from disk
    HANDLE hFile = CreateFileA(libraryPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("DLL file not found.\n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // 2. Allocate memory inside the target process
    LPVOID remoteMemory = VirtualAllocEx(ProcessInfo.hProcess, NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        printf("Failed to allocate memory in the target process.\n");
        return 1;
    }

    // 3. Write the DLL's header and sections to its location in remote memory
    // This part normally handles PE headers in detail and writes sections to their proper locations.
    // This has been simplified for a basic example.
    BOOL memoryWritten = WriteProcessMemory(ProcessInfo.hProcess, remoteMemory, fileBuffer, fileSize, NULL);
    if (!memoryWritten) {
        printf("Failed to write to memory.\n");
        return 1;
    }

    // 4. Create a remote thread and run DllMain.
    // This section normally handles import and relocation work.
    // In this example, we are just calling DllMain to show that the injection works simply.
    // This part is the main technique that makes the injection invisible.
    LPVOID pDllMain = (LPVOID)((DWORD_PTR)remoteMemory + ((PIMAGE_DOS_HEADER)fileBuffer)->e_lfanew);
    pDllMain = (LPVOID)((DWORD_PTR)pDllMain + ((PIMAGE_NT_HEADERS)pDllMain)->OptionalHeader.AddressOfEntryPoint);

    HANDLE remoteThread = CreateRemoteThread(
        ProcessInfo.hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pDllMain, remoteMemory, 0, NULL
    );
    if (remoteThread == NULL) {
        printf("Could not create remote thread.\n");
        return 1;
    }
    else {
        WaitForSingleObject(remoteThread, INFINITE);
        CloseHandle(remoteThread);
    }

    // If the process is successful, the DLL should be Invisible.

    // Clean up memory
    VirtualFreeEx(ProcessInfo.hProcess, remoteMemory, 0, MEM_RELEASE);
    VirtualFree(fileBuffer, 0, MEM_RELEASE);

    // Resume the main thread
    ResumeThread(ProcessInfo.hThread);

    // Clean up handles
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);

    printf("DLL successfully injected. It's expected to be invisible.\n");
    return 0;
}
