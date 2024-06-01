#ifndef FUNC_CALL_PARSE_H
#define FUNC_CALL_PARSE_H

#include "list.h"
#include "hash_map.h"

struct output_arg {
  char* name;
  struct list* struct_hierarchy;
};

extern hash_map visited_func_args_decl;

extern hash_map visited_func_decls;

struct list* func_get_curr_func_arg_names(const char* func_name,
                                          const char* ref_src_file);

bool func_handle_func_call(const char* var_name,
                           struct list* struct_hierarchy,
                           const char* var_ref, const char** var_ref_arr,
                           size_t var_ref_arr_len, const char* func_name,
                           hash_map func_ptrs,
                           struct list** return_struct_hierarchy,
                           struct list** output_vars);

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
                                         char*** statement_arr,
                                         size_t* statement_arr_len);

struct list* func_get_func_args_name(const char* func_name,
                                     struct list* args_declaration,
                                     const char** func_declaration_arr,
                                     size_t func_declaration_arr_len);

struct list* func_get_func_args_refs(const char* func_name,
                                     struct list* func_arg_names,
                                     struct list* var_args_indices,
                                     const char** statement_arr,
                                     size_t statement_arr_len,
                                     bool is_func_declaration);

void func_free_out_arg(void* void_out_arg);

bool func_list_contains_output_arg(struct list* out_args, struct output_arg* out_arg);

#endif /* FUNC_CALL_PARSE_H */
