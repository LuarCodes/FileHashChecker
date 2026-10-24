@echo off
rem Build HashCheck.exe with MinGW-w64 (MSYS2: pacman -S mingw-w64-ucrt-x86_64-gcc)

cd hashcheck
echo 1 ICON "app.ico" > app.rc
echo 1 24 "../common/app.manifest" >> app.rc
windres app.rc -O coff -o app.res.o
g++ -O2 -std=c++17 -municode -mwindows -static -s main.cpp app.res.o  -ldwmapi -luxtheme -lcomctl32 -lcomdlg32 -lgdi32 -lshell32 -lbcrypt -o HashCheck.exe
cd ..
echo Built hashcheck\HashCheck.exe
