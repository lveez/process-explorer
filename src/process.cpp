#include "process.hpp"

#include <TlHelp32.h>
#include <format>
#include <iostream>
#include <memory>

namespace pe {

Process::Process() {
    process_id_ = 0;
    process_handle_ = nullptr;
    window_handle_ = 0;

    win_error_ = 0;
    open_handle_ = false;
}

Process::Process(const std::string& process_name, const std::string& window_name) {
    process_id_ = 0;
    process_handle_ = nullptr;
    window_handle_ = 0;

    win_error_ = 0;
    open_handle_ = false;

    if (process_name.empty() == false) {
        OpenFromProcessName(process_name);
    } else if (window_name.empty() == false) {
        OpenFromWindowName(window_name);
    }
}

Process::~Process() {
    Close();
}

bool Process::OpenFromProcessName(const std::string& process_name) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (process_snapshot == INVALID_HANDLE_VALUE)
        return this->HandleError();

    /* get first process */
    if (!Process32First(process_snapshot, &entry)) {
        return this->HandleError();
    }

    bool found = false;
    do {
        if (process_name == entry.szExeFile) {
            found = true;
            break;
        }
    } while (Process32Next(process_snapshot, &entry));

    if (!found) {
        std::cerr << std::format("ERROR: Unable to find process ({})\n", process_name);
        return false;
    }

    if (!OpenFromProcessID(entry.th32ProcessID)) {
        return false;
    }

    process_name_ = entry.szExeFile;
    std::cout << std::format("Process opened --- ({})\n", process_name_);

    if (!WindowNameFromProcessID()) {
        std::cerr << std::format("WARNING: Unable to find window name for {}\n", process_name);
    }

    return true;
}

bool Process::OpenFromWindowName(const std::string& window_name) {
    std::pair<HWND, const std::string&> callback_params = {0, window_name};

    EnumWindows(
        [](HWND window_handle, LPARAM param) -> BOOL CALLBACK {
            auto params = reinterpret_cast<std::pair<HWND, const std::string&>*>(param);
            char buf[256];

            GetWindowText(window_handle, buf, 256);

            if (params->second == buf) {
                params->first = window_handle;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&callback_params));

    if (callback_params.first == 0) {
        std::cerr << std::format("ERROR: Unable to find window titled \"{}\"\n", window_name);
        return false;
    }

    DWORD process_id;
    if (!GetWindowThreadProcessId(callback_params.first, &process_id)) {
        return this->HandleError();
    }

    if (!OpenFromProcessID(process_id)) {
        return false;
    }

    window_name_ = window_name;
    window_handle_ = callback_params.first;

    DWORD buf_size = MAX_PATH;
    char buf[buf_size];
    if (!QueryFullProcessImageName(process_handle_, 0, buf, &buf_size))
        std::cerr << std::format("WARNING: Unable to find process name.\n");
    else
        process_name_ = buf;

    process_name_ = process_name_.substr(process_name_.find_last_of("\\/") + 1);

    return true;
}

bool Process::OpenFromProcessID(const DWORD& process_id) {
    process_handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);

    if (process_handle_ == nullptr) {
        return this->HandleError();
    }

    process_id_ = process_id;
    return true;
}

bool Process::Close() {
    if (open_handle_ == false)
        return false;

    if (CloseHandle(process_handle_) == false)
        return this->HandleError();

    return true;
}

bool Process::HandleError() {
    win_error_ = GetLastError();
    std::cerr << std::format("ERROR: WINERROR {}\n", win_error_);
    return false;
}

bool Process::WindowNameFromProcessID() {
    std::pair<HWND, DWORD> callback_params = {0, process_id_};

    EnumWindows(
        [](HWND window_handle, LPARAM param) -> BOOL CALLBACK {
            auto params = reinterpret_cast<std::pair<HWND, DWORD>*>(param);

            DWORD process_id;
            GetWindowThreadProcessId(window_handle, &process_id);

            if (GetWindow(window_handle, GW_OWNER) != 0) {
                return TRUE;
            }

            if (process_id == params->second) {
                params->first = window_handle;
                return FALSE;
            }

            return TRUE;
        },
        reinterpret_cast<LPARAM>(&callback_params));

    if (callback_params.first == 0)
        return false;

    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(256);
    GetWindowText(callback_params.first, buffer.get(), 256);
    window_name_ = buffer.get();
    window_handle_ = callback_params.first;
    buffer.reset();
    return true;
}

};  // namespace pe