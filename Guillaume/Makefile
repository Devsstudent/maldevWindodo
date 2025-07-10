
all:
        cl.exe hello.c
        cl.exe minimal.c
        cl.exe injector.c /c
        cl.exe inj_c_code.c /Ob3 /Os /O2 /c
        ml64.exe inj_asm_code_begin.asm /c
        ml64.exe inj_asm_code_end.asm /c
        link.exe injector.obj \
                inj_asm_code_begin.obj \
                inj_c_code.obj \
                inj_asm_code_end.obj \
                -out:injector.exe

inj:
        injector.exe hello.exe
        injector.exe minimal.exe

clean:
        del hello.exe
        del minimal.exe
        del *.obj

distclean: clean
        del injector.exe