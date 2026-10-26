#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <io.h>

__declspec(noinline) static void fault() { *reinterpret_cast<volatile unsigned int*>(static_cast<std::uintptr_t>(1)) = 42; }
__declspec(noinline) static int marker(int input) { volatile int value = input; return value + 1; }
static void handled_fault() { __try { fault(); } __except(EXCEPTION_EXECUTE_HANDLER) {} }
int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    _setmode(_fileno(stdout), _O_BINARY); _setmode(_fileno(stderr), _O_BINARY); _setmode(_fileno(stdin), _O_BINARY);
    const std::wstring mode = argc > 1 ? argv[1] : L"normal";
    if (mode == L"layout") { std::cout << "{\"marker_rva\":" << reinterpret_cast<std::uintptr_t>(&marker) - reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)) << "}\n"; return 0; }
    if (mode == L"marker") { std::cout << "marker=" << marker(42) << '\n'; return 0; }
    if (mode == L"crash") fault();
    if (mode == L"handled") { handled_fault(); std::cout << "handled\n"; return 0; }
    if (mode == L"debug_strings") { OutputDebugStringA("fixture-debug-string"); OutputDebugStringW(L"\u017elt\u00fd-debug-string"); return 0; }
    if (mode == L"sleep" || mode == L"pidfile") {
        if (mode == L"pidfile" && argc > 2) { std::ofstream file{std::filesystem::path(argv[2])}; file << GetCurrentProcessId(); file.flush(); }
        Sleep(10000); return 0;
    }
    if (mode == L"child") {
        std::wstring command = L"\"" + std::wstring(argv[0]) + L"\" sleep"; STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION child{};
        if (!CreateProcessW(argv[0], command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child)) return 9;
        std::cout << child.dwProcessId << std::endl; CloseHandle(child.hThread); CloseHandle(child.hProcess); Sleep(10000); return 0;
    }
    if (mode == L"input") {
        std::string input;
        if (argc > 2 && std::wstring(argv[2]) != L"-") { std::ifstream file(std::filesystem::path(argv[2]), std::ios::binary); input.assign(std::istreambuf_iterator<char>(file), {}); }
        else input.assign(std::istreambuf_iterator<char>(std::cin), {});
        if (input.starts_with("HANG")) Sleep(10000);
        if (input.starts_with("EXIT")) return 7;
        if (input.find("CRASH") != std::string::npos || input.find(static_cast<char>(0xff)) != std::string::npos) fault();
        std::cout << "bytes=" << input.size() << '\n'; return 0;
    }
    std::cout << "normal\n"; return 0;
}
