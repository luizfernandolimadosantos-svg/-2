
#include <windows.h>

int WINAPI wWinMain(
    HINSTANCE,
    HINSTANCE,
    PWSTR,
    int
) {
    MessageBoxW(
        nullptr,
        L"Macaquito Scanner V38\n"
        L"Cloud build successful!",
        L"Macaquito Scanner",
        MB_OK | MB_ICONINFORMATION
    );

    return 0;
}
