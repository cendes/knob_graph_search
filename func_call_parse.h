#ifndef FUNC_CALL_PARSE_H
#define FUNC_CALL_PARSE_H

#include "list.h"
#include "hash_map.h"

enum FuncDeclStatus {
  FUNC_DECL_FOUND,
  FUNC_DECL_NOT_FOUND,
  FUNC_DECL_NOT_EXISTS
};

struct output_arg {
  char* name;
  struct list* struct_hierarchy;
};

void func_load_visited_func_decls(const char* filename);

struct list* func_get_curr_func_arg_names(const char* func_name,
                                          const char* ref_src_file);

ssize_t func_get_func_start_line(const char* func_name, const char* ref_src_file);

bool func_handle_func_call(const char* var_name,
                           struct list* struct_hierarchy,
                           const char* var_ref, const char** var_ref_arr,
                           size_t var_ref_arr_len, const char* func_name,
                           hash_map func_ptrs, bool record_match,
                           struct list** return_struct_hierarchy,
                           struct list** output_vars,
                           struct list** call_return_hierarchy);

struct list* func_get_func_args(const char* var_ref,
                                size_t args_start_index,
                                struct list** args_range);

struct list* func_get_func_call_args(const char* var_name,
                                     struct list* struct_hierarchy,
                                     const char* var_ref, struct list** funcs,
                                     struct list** funcs_start,
                                     struct list** var_args_indices,
                                     struct list** args_struct_matches,
                                     struct list** args_range);

struct list* func_extract_func_arg_names(const char* func_name,
                                         const char* ref_src_file,
                                         struct list* func_args,
                                         struct list** func_ptr_args,
                                         bool* is_define,
                                         char*** func_declaration_arr,
                                         size_t* func_declaration_arr_len);

enum FuncDeclStatus func_get_func_decl(const char* func_name,
                                       const char* ref_src_file,
                                       const char** func_decl,
                                       const char** func_src_file,
                                       size_t* func_start_line);

void func_insert_func_decl_entry(const char* func_name,
                                 const char* func_declaration,
                                 const char* source_file,
                                 size_t line_number);

struct list* func_get_func_args_name(const char* func_name,
                                     struct list* args_declaration,
                                     bool is_define);

struct list* func_get_func_args_refs(const char* func_name,
                                     struct list* func_arg_names,
                                     struct list* var_args_indices,
                                     const char* func_src_file,
                                     ssize_t func_start_line,
                                     bool is_define);

void func_free_out_arg(void* void_out_arg);

struct output_arg* func_list_get_output_arg(struct list* out_args,
                                            const char* out_arg_name);

void func_handle_entrypoint_out_args(const char* entry_func, const char* caller_func,
                                     struct list* output_args, const char* func_ref,
                                     const char** func_ref_arr, size_t func_ref_arr_len,
                                     bool record_match, struct list** return_hierarchy,
                                     struct list** caller_out_args);

#endif /* FUNC_CALL_PARSE_H */
