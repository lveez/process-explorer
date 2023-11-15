#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x600
#include <windows.h>

#include <string>
#include <vector>

namespace pe {

class Process {
   public:
    Process();
    Process(const std::string& process_name, const std::string& window_name);
    ~Process();

    /* management */
    bool OpenFromProcessName(const std::string& process_name);
    bool OpenFromWindowName(const std::string& window_name);
    bool OpenFromProcessID(const DWORD& process_id);

    bool Close();

    /* basic read/write process memory wrappers */
    template <typename T>
    T ProtectedRead(DWORD src_address) {
        T buf;
        void* src = reinterpret_cast<void*>(src_address);

        DWORD old_protect;
        VirtualProtectEx(process_handle_, src, sizeof(T), PAGE_EXECUTE_READWRITE, &old_protect);
        if (!ReadProcessMemory(process_handle_, src, &buf, sizeof(T), nullptr)) {
            VirtualProtectEx(process_handle_, src, sizeof(T), old_protect, nullptr);
            return this->HandleError();
        }

        VirtualProtectEx(process_handle_, src, sizeof(T), old_protect, nullptr);
        return buf;
    }

    /* num_to_read is number of T to read, not bytes */
    template <typename T>
    std::vector<T> ReadProtected(DWORD src_address, size_t num_to_read) {
        std::vector<T> buf(num_to_read);
        void* src = reinterpret_cast<void*>(src_address);

        DWORD old_protect;
        VirtualProtectEx(process_handle_, src, sizeof(T) * buf.capacity(), PAGE_EXECUTE_READWRITE, &old_protect);

        if (!ReadProcessMemory(process_handle_, src, buf.data(), buf.capacity() * sizeof(T), nullptr)) {
            VirtualProtectEx(process_handle_, src, sizeof(T), old_protect, nullptr);
            this->HandleError();
            return std::vector<T>(0);
        }

        VirtualProtectEx(process_handle_, src, sizeof(T) * buf.capacity(), old_protect, nullptr);
        return buf;
    }

    template <typename T>
    T Read(DWORD src_address) {
        T buf;
        void* src = reinterpret_cast<void*>(src_address);

        if (!ReadProcessMemory(process_handle_, src, &buf, sizeof(T), nullptr))
            return this->HandleError();

        return buf;
    }

    /* num_to_read is number of T to read, not bytes */
    template <typename T>
    std::vector<T> Read(DWORD src_address, size_t num_to_read) {
        std::vector<T> buf(num_to_read);
        void* src = reinterpret_cast<void*>(src_address);

        if (!ReadProcessMemory(process_handle_, src, buf.data(), buf.capacity() * sizeof(T), nullptr)) {
            this->HandleError();
            return std::vector<T>(0);
        }

        return buf;
    }

    template <typename T>
    bool Write(DWORD dest_address, const T& value) {
        void* dest = reinterpret_cast<void*>(dest_address);
        if (!WriteProcessMemory(process_handle_, dest, &value, sizeof(T), nullptr))
            return this->HandleError();
        return true;
    }

    template <typename T>
    bool Write(DWORD dest_address, const std::vector<T>& data) {
        void* dest = reinterpret_cast<void*>(dest_address);
        if (!WriteProcessMemory(process_handle_, dest, data.data(), sizeof(T) * data.size(), nullptr))
            return this->HandleError();
        return true;
    }

    template <typename T>
    bool Write(DWORD dest_address, T* data, size_t num_to_write) {
        void* dest = reinterpret_cast<void*>(dest_address);
        if (!WriteProcessMemory(process_handle_, dest, data, sizeof(T) * num_to_write, nullptr))
            return this->HandleError();
        return true;
    }

    /* getters */
    const std::string&
    GetWindowName() const {
        return window_name_;
    }

    const DWORD& GetProcessID() const {
        return process_id_;
    }

    const std::string& GetProcessName() const {
        return process_name_;
    }

    const HWND& GetWindowHandle() const {
        return window_handle_;
    }

   private:
    bool HandleError();
    bool WindowNameFromProcessID();

    std::string process_name_;
    std::string window_name_;

    DWORD process_id_;
    HANDLE process_handle_;
    HWND window_handle_;

    DWORD win_error_;
    bool open_handle_;
};
};  // namespace pe