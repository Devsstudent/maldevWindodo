all:
	cl.exe hello.c
	cl.exe injector.c /c
	cl.exe inj_c_code.c /c
	ml64.exe inj_asm_code_begin.asm /c
	ml64.exe end_of_code.asm /c
	link.exe injector.obj inj_asm_code_begin.obj inj_c_code.obj end_of_code.obj -out:injector.exe

clean:
	del hello.exe
	del *.obj
	del injector.exe
inj:
	injector.exe hello.exe
