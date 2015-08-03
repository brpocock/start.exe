start.exe
=========

PC-DOS/MS-DOS/DR-DOS,  MS-Windows,  and  .NET  (Mono)  executable  files
all  use  the .exe  extension, and have the  same  magic cookie bytes in
their header.

This program  will  look deeper  into the headers  to identify  the type
of executable file you have,  and run the appropriate  helper program to
start that program.

It is meant as a binfmt handler for Linux.

Usage
=====

    make start.exe
    sudo cp start.exe /usr/bin/
    sudo restorecon /usr/bin/start.exe
    sudo cp binfmt.exe.conf /etc/binfmt.d/start.exe.conf
    sudo restorecon /etc/binfmt.d/start.exe.conf


