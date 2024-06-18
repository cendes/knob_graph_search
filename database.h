#ifndef DATABASE_H
#define DATABASE_H

#include "hash_map.h"

hash_map database_read_func_vars_visited(const char* filename);

void database_read_visited_func_decls(const char* filename);

void database_write_func_vars_visited_entry(const char* func, const char* var,
                                            struct func_var_entry* entry);

void database_write_visited_func_decls_entry(const char* func,
                                             const char* func_declaration,
                                             const char* source_file,
                                             size_t line_number);

void database_read_macros_return_range(const char* filename);

void database_write_macros_return_range(const char* macro, const char* source_file,
                                        size_t return_start, size_t return_end);

#endif /* DATABASE_H */
