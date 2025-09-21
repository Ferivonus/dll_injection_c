#include <stdio.h>
#include <windows.h>
#include <string.h>

// PE yapıları için tanımlamalar
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5

#pragma pack(push, 1)
typedef struct {
    WORD offset : 12;
    WORD type : 4;
} BASE_RELOCATION_ENTRY;
#pragma pack(pop)

// İşlemci mimarisi kontrolü
BOOL IsTargetProcess64Bit(HANDLE hProcess) {
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProcess, &isWow64)) {
        return FALSE;
    }
    return !isWow64;
}

// Manual mapping fonksiyonu
BOOL ManualMapDLL(HANDLE hProcess, const char* dllPath) {
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* fileBuffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);

    DWORD bytesRead;
    ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    // PE başlık kontrolü
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    // Bellek ayırma
    LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    // PE başlıklarını kopyala
    WriteProcessMemory(hProcess, remoteBase, fileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    // Section'ları kopyala
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDest = (BYTE*)remoteBase + sectionHeader[i].VirtualAddress;
        LPVOID sectionSrc = fileBuffer + sectionHeader[i].PointerToRawData;

        WriteProcessMemory(hProcess, sectionDest, sectionSrc, sectionHeader[i].SizeOfRawData, NULL);
    }

    // İmport tablosunu işle
    PIMAGE_DATA_DIRECTORY importDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(fileBuffer + importDirectory->VirtualAddress);

        while (importDesc->Name != 0) {
            char* moduleName = (char*)(fileBuffer + importDesc->Name);
            HMODULE hModule = LoadLibraryA(moduleName);

            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(fileBuffer + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(fileBuffer + importDesc->FirstThunk);

            while (origThunk->u1.AddressOfData != 0) {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Ordinal ile import
                    FARPROC func = GetProcAddress(hModule, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                    WriteProcessMemory(hProcess, (BYTE*)remoteBase + firstThunk->u1.Function, &func, sizeof(func), NULL);
                }
                else {
                    // Name ile import
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(fileBuffer + origThunk->u1.AddressOfData);
                    FARPROC func = GetProcAddress(hModule, (LPCSTR)importByName->Name);
                    WriteProcessMemory(hProcess, (BYTE*)remoteBase + firstThunk->u1.Function, &func, sizeof(func), NULL);
                }

                origThunk++;
                firstThunk++;
            }

            importDesc++;
        }
    }

    // Relocation işlemi
    PIMAGE_DATA_DIRECTORY relocDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDirectory->Size > 0) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(fileBuffer + relocDirectory->VirtualAddress);

        while (reloc->VirtualAddress != 0) {
            DWORD entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(reloc + 1);

            for (DWORD i = 0; i < entries; i++) {
                if (entry[i].type == IMAGE_REL_BASED_HIGHLOW || entry[i].type == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* address = (DWORD_PTR*)((BYTE*)remoteBase + reloc->VirtualAddress + entry[i].offset);
                    DWORD_PTR delta = (DWORD_PTR)remoteBase - ntHeaders->OptionalHeader.ImageBase;

                    DWORD_PTR value;
                    ReadProcessMemory(hProcess, address, &value, sizeof(value), NULL);
                    value += delta;
                    WriteProcessMemory(hProcess, address, &value, sizeof(value), NULL);
                }
            }

            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // Entry point'i çağır
    LPVOID entryPoint = (BYTE*)remoteBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, remoteBase, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFree(fileBuffer, 0, MEM_RELEASE);
    return TRUE;
}

int main() {
    char targetPath[MAX_PATH];
    char libraryPath[MAX_PATH];

    printf("Hedef EXE yolu: ");
    scanf_s("%s", targetPath, (unsigned)sizeof(targetPath));

    printf("DLL yolu: ");
    scanf_s("%s", libraryPath, (unsigned)sizeof(libraryPath));

    // Hedef process'i askıda başlat
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Process olusturulamadi: %d\n", GetLastError());
        return 1;
    }

    // Manual mapping ile DLL enjekte et
    if (ManualMapDLL(pi.hProcess, libraryPath)) {
        printf("DLL basariyla manual mapping ile enjekte edildi!\n");
    }
    else {
        printf("Manual mapping basarisiz: %d\n", GetLastError());
    }

    // Temizlik
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
