all: start.exe

start.exe: start.exe.c
	cc start.exe.c -o start.exe

