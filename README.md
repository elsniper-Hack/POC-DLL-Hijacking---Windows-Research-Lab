# POC-DLL-Hijacking---Windows-Research-Lab

## Advertencia 
Proyecto exclusivamente para fines educativos.

## Descripción
Prueba de concepto de DLL Hijacking usando WINMM.dll
contra WordPad en Windows 10. Incluye:
  DLL Proxy (app funciona con normalidad)
  Reverse Shell estable con pipes
  Cifrado XOR de strings
  Evasión básica de análisis estático

## Entorno de laboratorio
Windows 10 VM → objetivo

## Compilación desde Linux
x86_64-w64-mingw32-g++ -shared -o WINMM.dll src/version.cpp -lws2_32 -lkernel32 -static-libgcc -static-libstdc++ -Wl,--subsystem,windows -m64

## Referencias
MITRE ATT&CK T1574.001 - DLL Search Order Hijacking
Sysinternals Process Monitor
