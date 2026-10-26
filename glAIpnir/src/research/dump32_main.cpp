#include <Windows.h>
#include <DbgHelp.h>
#include "harness/research/dump_wire.hpp"
#include <cstring>
#include <fstream>
#include <filesystem>
#include <iostream>

static HANDLE cancellation_event;
static std::uint64_t byte_limit;
static bool budget_exhausted = false;
static BOOL CALLBACK callback(PVOID, const PMINIDUMP_CALLBACK_INPUT input, PMINIDUMP_CALLBACK_OUTPUT output) {
    const bool cancelled = WaitForSingleObject(cancellation_event, 0) == WAIT_OBJECT_0;
    if (input->CallbackType == CancelCallback) { output->CheckCancel = TRUE; output->Cancel = cancelled; }
    else if (input->CallbackType == IoStartCallback) output->Status = S_FALSE;
    else if (input->CallbackType == IoFinishCallback) output->Status = S_OK;
    else if (input->CallbackType == IoWriteAllCallback) {
        if (cancelled || input->Io.Offset > byte_limit || input->Io.BufferBytes > byte_limit - input->Io.Offset) { budget_exhausted = !cancelled; output->Status = E_ABORT; return TRUE; }
        LARGE_INTEGER offset{}; offset.QuadPart = static_cast<LONGLONG>(input->Io.Offset); DWORD written{};
        const auto success = SetFilePointerEx(input->Io.Handle, offset, nullptr, FILE_BEGIN) && WriteFile(input->Io.Handle, input->Io.Buffer, input->Io.BufferBytes, &written, nullptr);
        output->Status = success && written == input->Io.BufferBytes ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    }
    return TRUE;
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--version") { std::cout << HARNESS_VERSION "\n"; return 0; }
    if (argc != 6) return 2;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    harness::research::dump_reply_t reply;
    try {
        harness::research::dump_request_t request;
        std::ifstream input{std::filesystem::path(argv[1]), std::ios::binary}; input.read(reinterpret_cast<char*>(&request), sizeof(request));
        if (input.gcount() != sizeof(request) || request.magic != reply.magic || request.parameter_count > 15) return 3;
        cancellation_event = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::stoull(argv[4]))); byte_limit = std::stoull(argv[5]);
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, request.pid);
        if (!process) reply.error = GetLastError();
        else {
            HANDLE file = CreateFileW(argv[2], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) reply.error = GetLastError();
            else {
                CONTEXT context{}; static_assert(sizeof(context) == 716); std::memcpy(&context, request.context.data(), sizeof(context));
                EXCEPTION_RECORD exception{}; exception.ExceptionCode = request.exception_code; exception.ExceptionFlags = request.exception_flags;
                exception.ExceptionAddress = reinterpret_cast<void*>(static_cast<std::uintptr_t>(request.exception_address)); exception.NumberParameters = request.parameter_count;
                for (DWORD index = 0; index < request.parameter_count; ++index) exception.ExceptionInformation[index] = static_cast<ULONG_PTR>(request.parameters[index]);
                EXCEPTION_POINTERS pointers{&exception, &context}; MINIDUMP_EXCEPTION_INFORMATION information{request.tid, &pointers, FALSE};
                MINIDUMP_CALLBACK_INFORMATION callbacks{callback, nullptr};
                const auto type = static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules);
                if (!MiniDumpWriteDump(process, request.pid, file, type, request.has_exception ? &information : nullptr, nullptr, &callbacks)) reply.error = GetLastError();
                FlushFileBuffers(file); CloseHandle(file);
            }
            CloseHandle(process);
        }
    } catch (const std::exception&) { reply.error = ERROR_INVALID_PARAMETER; }
    reply.budget_exhausted = budget_exhausted;
    std::ofstream output{std::filesystem::path(argv[3]), std::ios::binary}; output.write(reinterpret_cast<const char*>(&reply), sizeof(reply)); return output ? 0 : 4;
}
