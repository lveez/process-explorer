#include "image.hpp"

#include <format>
#include <iostream>

namespace pe {

Image::Image() {
}

Image::Image(const std::string& exe_path) {
    LoadExe(exe_path);
}

bool Image::LoadExe(const std::string& exe_path) {
    /* open the file */
    HANDLE file_handle = CreateFileA(exe_path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle == INVALID_HANDLE_VALUE) {
        return this->HandleWinError();
    }

    this->exe_path_ = exe_path;
    this->exe_name_ = exe_path.substr(exe_path.find_last_of("\\/") + 1);

    old_image_size_ = GetFileSize(file_handle, nullptr);
    old_image_data_.resize(old_image_size_);

    DWORD bytes_read;
    if (!ReadFile(file_handle, old_image_data_.data(), old_image_size_, &bytes_read, nullptr)) {
        old_image_data_.clear();
        old_image_data_.shrink_to_fit();
        return this->HandleWinError();
    }

    if (bytes_read != old_image_size_) {
        return this->HandleError(std::format("ERROR: {} bytes read instead of {}.\n", bytes_read, old_image_size_));
    }

    old_image_data_ptr_ = reinterpret_cast<DWORD>(old_image_data_.data());

    IMAGE_DOS_HEADER* image_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(old_image_data_ptr_);
    image_nt_header_ = reinterpret_cast<IMAGE_NT_HEADERS32*>(old_image_data_ptr_ + image_dos_header->e_lfanew);

    if (image_nt_header_->Signature != IMAGE_NT_SIGNATURE || image_dos_header->e_magic != 0x5a4d) {
        return this->HandleError("ERROR: Invalid EXE file.");
    }

    if (image_nt_header_->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        bit64_ = true;
        image_nt_header64_ = reinterpret_cast<IMAGE_NT_HEADERS64*>(image_nt_header_);
        image_data_directory_ = image_nt_header64_->OptionalHeader.DataDirectory;
    } else if (image_nt_header_->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        bit64_ = false;
        image_data_directory_ = image_nt_header_->OptionalHeader.DataDirectory;
    } else {
        return this->HandleError("ERROR: Invalid EXE File");
    }

    std::cout << std::format("{} bytes read from {}-bit file {}.\n", bytes_read, (bit64_) ? 64 : 32, exe_name_);

    return true;
}

bool Image::ParseImportTable() {
    if (image_nt_header_ == nullptr) {
        std::cerr << "ERROR: EXE not loaded.\n";
        return false;
    }

    import_table_base_ = 0;

    /* get import table base address */
    DWORD base_header = image_nt_header_->FileHeader.SizeOfOptionalHeader + reinterpret_cast<DWORD>(&(image_nt_header_->OptionalHeader));
    DWORD virtual_address = image_data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_SECTION_HEADER* current_section_header;

    last_section_header_ = reinterpret_cast<IMAGE_SECTION_HEADER*>(base_header);

    for (int i = 0; i < image_nt_header_->FileHeader.NumberOfSections; i++) {
        current_section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(base_header + (i * sizeof(IMAGE_SECTION_HEADER)));

        if (current_section_header->PointerToRawData > last_section_header_->PointerToRawData) {
            last_section_header_ = current_section_header;
        }

        if (current_section_header->SizeOfRawData == 0)
            continue;

        if (virtual_address < current_section_header->VirtualAddress)
            continue;

        if (virtual_address < (current_section_header->VirtualAddress + current_section_header->SizeOfRawData)) {
            /* correct section */
            import_table_base_ = old_image_data_ptr_ + current_section_header->PointerToRawData + (virtual_address - current_section_header->VirtualAddress);
        }
    }

    if (import_table_base_ == 0) {
        std::cerr << "ERROR: Import table not found.\n";
        return false;
    }

    new_data_va_ = last_section_header_->VirtualAddress + last_section_header_->SizeOfRawData;
    new_data_fp_ = last_section_header_->PointerToRawData + last_section_header_->SizeOfRawData;

    // std::cout << "End of section headers found at virtual address: 0x" << std::hex << new_data_va_ << std::endl;

    /* Get number of imports already in file */
    old_module_count_ = 0;
    IMAGE_IMPORT_DESCRIPTOR* image_import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_table_base_);
    if (image_data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) {
        DWORD offset = 0;
        while (image_import_descriptor->Name != 0) {
            old_module_count_ += 1;
            offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            image_import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_table_base_ + offset);
        }
    }

    std::cout << std::format("{} imports found in {}.\n", old_module_count_, exe_name_);

    return true;
}

bool Image::AddImportToTable(const std::string& dll_path) {
    current_import_path_ = dll_path;
    current_import_ = dll_path.substr(dll_path.find_last_of("\\/") + 1);

    old_import_table_size_ = old_module_count_ * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    new_import_table_size_ = old_import_table_size_ + sizeof(new_import_descriptors_);
    new_import_directory_data_.resize(new_import_table_size_);

    new_import_descriptors_[0].Name = new_data_va_ + new_import_table_size_;
    new_import_descriptors_[0].OriginalFirstThunk = new_data_va_ + new_import_table_size_ + dll_path.length() + 1;
    new_import_descriptors_[0].FirstThunk = new_import_descriptors_[0].OriginalFirstThunk + ((bit64_) ? 2 * sizeof(IMAGE_THUNK_DATA64) : 2 * sizeof(IMAGE_THUNK_DATA32));
    new_import_descriptors_[0].TimeDateStamp = 0;
    new_import_descriptors_[0].ForwarderChain = 0;

    new_import_descriptors_[1].Name = 0;
    new_import_descriptors_[1].OriginalFirstThunk = 0;
    new_import_descriptors_[1].FirstThunk = 0;
    new_import_descriptors_[1].TimeDateStamp = 0;
    new_import_descriptors_[1].ForwarderChain = 0;

    /* copy original imports */
    void* ptr = new_import_directory_data_.data();
    if (old_module_count_ > 0) {
        memcpy(ptr, reinterpret_cast<void*>(import_table_base_), old_import_table_size_);
        ptr += old_import_table_size_;
    }

    /* add new import */
    memcpy(ptr, &new_import_descriptors_, sizeof(new_import_descriptors_));

    /* luts */
    import_lut_[0].u1.Ordinal = 0x80000001;
    import_lut_[1].u1.Ordinal = 0x00000000;

    import_lut64_[0].u1.Ordinal = 0x8000000000000001;
    import_lut64_[1].u1.Ordinal = 0x0000000000000000;

    image_data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = new_data_va_;
    image_data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = new_import_table_size_;

    /* how much data to add */
    total_added_size_ = new_import_table_size_ + dll_path.length() + 1;

    DWORD file_alignment;
    if (bit64_) {
        file_alignment = image_nt_header64_->OptionalHeader.FileAlignment;
        total_added_size_ += (2 * sizeof(import_lut64_));
    } else {
        file_alignment = image_nt_header_->OptionalHeader.FileAlignment;
        total_added_size_ += (2 * sizeof(import_lut_));
    }

    num_padding_bytes_ = (file_alignment - (total_added_size_ % file_alignment)) % file_alignment;
    total_added_size_ += num_padding_bytes_;

    last_section_header_->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    last_section_header_->SizeOfRawData += total_added_size_;
    last_section_header_->Misc.VirtualSize += total_added_size_;

    // check if debug symbols are currently stored at the end of the exe
    if (image_nt_header_->FileHeader.PointerToSymbolTable == new_data_fp_) {
        // adjust debug symbol ptr
        image_nt_header_->FileHeader.PointerToSymbolTable += total_added_size_;
    }

    if (bit64_) {
        image_nt_header64_->OptionalHeader.SizeOfImage += total_added_size_;
    } else {
        image_nt_header_->OptionalHeader.SizeOfImage += total_added_size_;
    }

    return true;
}

bool Image::WriteChanges(const std::string& append_to_name) {
    /* TODO: check actually loaded */

    std::string new_path = exe_path_.substr(0, exe_path_.find_last_of(".")) + append_to_name;
    HANDLE file_handle = CreateFileA(new_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        return this->HandleWinError();
    }

    /* original data */
    WriteFile(file_handle, old_image_data_.data(), new_data_fp_, nullptr, nullptr);

    /* new import */
    WriteFile(file_handle, new_import_directory_data_.data(), new_import_table_size_, nullptr, nullptr);

    /* dll name */
    WriteFile(file_handle, current_import_path_.c_str(), current_import_path_.length() + 1, nullptr, nullptr);

    /* LUTs */
    if (bit64_) {
        WriteFile(file_handle, import_lut64_, sizeof(import_lut64_), nullptr, nullptr);
        WriteFile(file_handle, import_lut64_, sizeof(import_lut64_), nullptr, nullptr);
    } else {
        WriteFile(file_handle, import_lut_, sizeof(import_lut_), nullptr, nullptr);
        WriteFile(file_handle, import_lut_, sizeof(import_lut_), nullptr, nullptr);
    }

    DWORD padding_byte = 0;
    for (int i = 0; i < num_padding_bytes_; i++) {
        WriteFile(file_handle, &padding_byte, 1, nullptr, nullptr);
    }

    /* append rest of original */
    WriteFile(file_handle, reinterpret_cast<void*>(old_image_data_ptr_ + new_data_fp_), old_image_size_ - new_data_fp_, nullptr, nullptr);

    CloseHandle(file_handle);

    return true;
}

bool Image::HandleWinError() {
    win_error_ = GetLastError();

    if (win_error_ == 0) {
        std::cerr << "ERROR: Unknown error.\n";
        return false;
    }

    if (error_info_.find(win_error_) != error_info_.end()) {
        std::cerr << std::format("ERROR: WINERROR ({})\n", error_info_[win_error_]);
    } else {
        std::cerr << std::format("ERROR: WINERROR ({:#x})\n", win_error_);
    }
    return false;
}

bool Image::HandleError(const std::string& error_string) {
    old_image_data_.clear();
    old_image_data_.shrink_to_fit();
    old_image_data_ptr_ = 0;
    image_nt_header_ = nullptr;
    image_nt_header64_ = nullptr;

    std::cerr << error_string;
    return false;
}
};  // namespace pe