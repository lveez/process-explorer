#pragma once

/**********
 *
 *    This implementation is based off this article:
 * https://www.x86matthew.com/view_post?id=add_exe_import
 *
 ***********/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace pe {

class Image {
   public:
    Image();
    Image(const std::string& exe_path);

    bool LoadExe(const std::string& exe_path);
    bool ParseImportTable();
    bool AddImportToTable(const std::string& dll_path);
    bool WriteChanges(const std::string& append_to_name);

   private:
    bool HandleWinError();
    bool HandleError(const std::string& error_string);

    std::string exe_name_;
    std::string exe_path_;
    std::string current_import_;
    std::string current_import_path_;

    /* file info */
    DWORD old_image_size_ = 0;
    std::vector<BYTE> old_image_data_;
    DWORD old_image_data_ptr_ = 0;
    IMAGE_NT_HEADERS32* image_nt_header_ = nullptr;
    IMAGE_NT_HEADERS64* image_nt_header64_ = nullptr;
    IMAGE_DATA_DIRECTORY* image_data_directory_ = nullptr;

    /* end of data info */
    IMAGE_SECTION_HEADER* last_section_header_ = nullptr;
    DWORD new_data_va_ = 0;
    DWORD new_data_fp_ = 0;

    /* import info */
    DWORD import_table_base_ = 0;
    DWORD old_module_count_ = 0;
    DWORD old_import_table_size_ = 0;

    /* new import info */
    IMAGE_IMPORT_DESCRIPTOR new_import_descriptors_[2];
    DWORD new_import_table_size_ = 0;
    std::vector<BYTE> new_import_directory_data_;
    IMAGE_THUNK_DATA32 import_lut_[2];
    IMAGE_THUNK_DATA64 import_lut64_[2];
    DWORD total_added_size_ = 0;
    DWORD num_padding_bytes_ = 0;

    bool bit64_;

    DWORD win_error_ = 0;
    std::unordered_map<DWORD, std::string> error_info_ = {
        {0x2, "FILE_NOT_FOUND"}};
};

};  // namespace pe