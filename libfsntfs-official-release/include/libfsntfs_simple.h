#pragma once
#include "libfsntfs.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct simple_file_data_run_of_mft_tag
{
    unsigned long long offset; // 文件内容块的偏移地址。相对于文件系统的起始地址
    unsigned long long size; // 文件内容块的大小
} simple_file_data_run_of_mft_t;

typedef struct simple_file_info_of_mft_tag
{
    wchar_t file_name[MAX_PATH];
    unsigned long long file_size;
    unsigned long long creation_time;
    unsigned long long modification_time;
    unsigned long long access_time;
    unsigned long long mft_record_number;
    unsigned long long parent_mft_record_number;
    unsigned long meta_seq;
    int data_run_count;
    simple_file_data_run_of_mft_t data_run[MAX_PATH];
} simple_file_info_of_mft_t;

/**
 * @brief 简单解析MFT块（磁盘中以FILE0开头的MFT记录块）
 * @param[out] file_info 解析得到的文件信息
 * @param[in] mft_buffer MFT记录块
 * @param[in] buffer_len MFT记录块的大小，一般为1024
 * @return 成功返回1
 */
LIBFSNTFS_EXTERN \
int libfsntfs_simple_parse_mft_entry(simple_file_info_of_mft_t* file_info, const void* mft_buffer, const int buffer_len);


#if defined( __cplusplus )
}
#endif
