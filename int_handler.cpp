#include <windows.h>
#include <atomic>

std::atomic<bool> g_shouldStop(false);

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        g_shouldStop = true;
        return TRUE;
    }
    return FALSE;
}