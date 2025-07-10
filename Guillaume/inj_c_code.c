#include <windows.h>
#include <winternl.h>
#pragma section("inject", read, execute)

static inline wchar_t wlow(wchar_t c)
{
    if (c >= L'A' && c <= L'Z')
        return c - L'A' + L'a';
    return c;
}

static inline wchar_t low(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

__declspec(code_seg("inject"))
wchar_t my_wcsicmp(wchar_t *s1, wchar_t *s2)
{
    for (int i = 0; s1[i]; i++)
    {
        wchar_t c1 = wlow(s1[i]);
        wchar_t c2 = wlow(s2[i]);
        if (c1 != c2)
            return c2;
    }
    return 0;
}

__declspec(code_seg("inject"))
char my_stricmp(char *s1, char *s2)
{
    for (int i = 0; s1[i]; i += 1)
{


    char c1 = low(s1[i]);
    char c2 = low(s2[i]);
    if (c1 != c2)
        return c1 - c2;
}
return 0;
}

__declspec(code_seg("inject"))
void *get_dll(wchar_t *name)
{
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (!my_wcsicmp(pEntry->FullDllName.Buffer, name))
                return pEntry->DllBase;
}
return 0;
}

__declspec(code_seg("inject"))
PVOID get_func(void *dll, char *name)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) dll;
    PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)dll + pDosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dll + pDir->VirtualAddress);

    PDWORD  rvaNames = (PDWORD)((PUCHAR)dll + pExport->AddressOfNames);
    PDWORD  rvaPtrs = (PDWORD)((PUCHAR)dll + pExport->AddressOfFunctions);
    PWORD  rvaOrd = (PWORD)((PUCHAR)dll + pExport->AddressOfNameOrdinals);
    for (int i = 0; i < pExport->NumberOfNames; i += 1)
    {
        char *fname = (char*)((PUCHAR)dll + rvaNames[i]);
        WORD ord = rvaOrd[i];
        PVOID ptr = (PVOID)((PUCHAR)dll + rvaPtrs[ord]);
        if (!my_stricmp(name, fname))
            return ptr;
    }
    return 0;
}

typedef HMODULE (*load_lib_t)(LPCSTR);
typedef FARPROC (*get_proc_t)(HMODULE, LPCSTR);
typedef int (*msg_box_t)(
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
int main_inject(void *rbp)
{
// !!!
    LONGLONG delta_k32 = (PUCHAR)(&__kern32_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_load = (PUCHAR)(&__loadlib_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_getp = (PUCHAR)(&__getproc_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_user = (PUCHAR)(&__user32_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_msg_str = (PUCHAR)(&__msgbox_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_msg_title = (PUCHAR)(&__msgbox_title_str[0]) - (PUCHAR)&__begin_of_code;
    LONGLONG delta_msg_content = (PUCHAR)(&__msgbox_content_str[0]) - (PUCHAR)&__begin_of_code;

    void *kern32 = get_dll((wchar_t *)((PUCHAR)rbp + delta_k32));
    void *loadlib = get_func(kern32, (char *)((PUCHAR)rbp + delta_load));
    void *getproc = get_func(kern32, (char *)((PUCHAR)rbp + delta_getp));

    HMODULE user32 = ((load_lib_t)loadlib)((char *)((PUCHAR)rbp + delta_user));
    void *msgbox = ((get_proc_t)getproc)(user32, (char *)((PUCHAR)rbp + delta_msg_str));
    ((msg_box_t)msgbox)(NULL,
        (char *)((PUCHAR)rbp + delta_msg_title),
        (char *)((PUCHAR)rbp + delta_msg_content),
        0);

    return 2600;
}