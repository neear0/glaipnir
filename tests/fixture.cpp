#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <fcntl.h>
#include <io.h>

static std::string utf8(const std::wstring& text) {
    int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0'); WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr); return result;
}
int wmain(int argc, wchar_t** argv) {
    _setmode(_fileno(stdout), _O_BINARY); _setmode(_fileno(stderr), _O_BINARY);
    if (argc > 1 && std::wstring(argv[1]) == L"sleep") { Sleep(10000); return 0; }
    if (argc > 1 && std::wstring(argv[1]) == L"exit") return 7;
    if (argc > 1 && std::wstring(argv[1]) == L"spam") {
        auto write = [](DWORD stream) {
            std::string bytes(8192, 'x');
            for (int index = 0; index < 64; ++index) { DWORD count{}; WriteFile(GetStdHandle(stream), bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr); }
        };
        std::thread output(write, STD_OUTPUT_HANDLE), error(write, STD_ERROR_HANDLE); output.join(); error.join(); return 0;
    }
    if (argc > 1 && std::wstring(argv[1]) == L"child") {
        std::wstring command = L"\"" + std::wstring(argv[0]) + L"\" sleep";
        STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
        if (!CreateProcessW(argv[0], command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return 8;
        std::cout << process.dwProcessId << std::endl; CloseHandle(process.hThread); CloseHandle(process.hProcess); Sleep(10000); return 0;
    }
    for (int index = 1; index < argc; ++index) std::cout << utf8(argv[index]) << '\n';
    return 0;
}
