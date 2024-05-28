#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>

#define UTILS_SIZEOF_ARR(arr) (sizeof(arr) / sizeof(*arr))

size_t utils_split_str(const char* result, char*** result_arr);

size_t utils_split_on_delim(const char* str, const char* delim, char*** str_arr);

char* utils_read_file_line(const char* file_path, int line_num);

char* utils_trim_str(char* str);

void utils_truncate_str(char* str, int index);

void utils_free_str_arr(char** str_arr);

char** utils_get_sub_array(const char** array, int index);

struct list* utils_get_cscope_output(const char* cmd);

bool utils_char_in_array(const char* array, char chr, size_t array_len);

bool utils_val_in_array(const size_t* array, size_t val, size_t array_len);

bool utils_str_in_array(const char** array, const char* str, size_t array_len);

bool utils_substr_in_array(const char** array, const char* str, size_t array_len,
                           size_t substr_end);

size_t utils_get_char_occurences(const char* str, char chr, size_t** indices);

size_t utils_get_str_occurences(const char* str, const char* token, size_t** indices);

bool utils_isnumeric(const char* str);

void utils_free_if_different(void* ptr_to_free, const void* ptr_to_cmp);

void utils_free_if_both_different(void* ptr_to_free, const void* ptr_to_cmp1,
                                  const void* ptr_to_cmp2);

#endif /* UTILS_H */
