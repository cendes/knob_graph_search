#ifndef DATABASE_H
#define DATABASE_H

hash_map database_read_func_vars_visited(const char* filename);

hash_map database_read_visited_func_decls(const char* filename);

void database_write_func_vars_visited_entry(const char* func, const char* var,
                                            struct func_var_entry* entry);

void database_write_visited_func_decls_entry(const char* func,
                                             const char* func_declaration);

#endif /* DATABASE_H */
