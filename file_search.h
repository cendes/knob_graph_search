#ifndef FILE_SEARCH_H
#define FILE_SEARCH_H

char* file_get_multiline_expr(const char* var_ref, const char** var_ref_arr,
                              bool has_invalid_code);

ssize_t file_get_func_from_src(const char* source_file, const char* func_name,
                               ssize_t* func_start_line);

ssize_t file_get_func_end_line(const char* source_file, size_t func_start_line);

char* file_find_struct_name(const char* source_file, size_t line_number);

char* file_get_line(const char* source_file, size_t line_number);

char* file_get_sysctl_table_entry(const char* source_file, size_t line_number,
                                  char** table_name, size_t* entry_index);

struct list* file_get_enum_list(const char* enum_name);

#endif /* FILE_SEARCH_H */
