#pragma once
#include "libfsntfs.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct simple_file_data_run_of_mft_tag
{
    unsigned long long offset; // �ļ����ݿ��ƫ�Ƶ�ַ��������ļ�ϵͳ����ʼ��ַ
    unsigned long long size; // �ļ����ݿ�Ĵ�С
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
 * @brief �򵥽���MFT�飨��������FILE0��ͷ��MFT��¼�飩
 * @param[out] file_info �����õ����ļ���Ϣ
 * @param[in] mft_buffer MFT��¼��
 * @param[in] buffer_len MFT��¼��Ĵ�С��һ��Ϊ1024
 * @return �ɹ�����1
 */
LIBFSNTFS_EXTERN \
int libfsntfs_simple_parse_mft_entry(simple_file_info_of_mft_t* file_info, const void* mft_buffer, const int buffer_len);


#if defined( __cplusplus )
}
#endif
