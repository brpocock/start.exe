all: start.exe

start.exe: start.exe.c
	cc start.exe.c -o start.exe

install:
	sudo cp start.exe /usr/bin/
	sudo restorecon /usr/bin/start.exe
	sudo cp binfmt.exe.conf /etc/binfmt.d/start.exe.conf
	sudo restorecon /etc/binfmt.d/start.exe.conf
	sudo cp start.exe.desktop /usr/share/applications/
	sudo restorecon /usr/share/applications/start.exe.desktop
