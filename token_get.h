#ifndef TOKEN_GET_H
#define TOKEN_GET_H

enum TokenReturnType {
  VAR_RETURN,
  FUNC_RETURN,
  NO_RETURN
};

char* token_find_func_name(const char* var_ref);

char* token_get_func_name(const char* var_ref, size_t args_start_index);

char* token_get_func_ptr_name(const char* func_ptr_declaration);

void token_insert_macro_return_entry(const char* macro_name, const char* src_file,
                                     size_t return_start, size_t return_end);

enum TokenReturnType token_get_return_match_node(const char* var_ref,
                                                 const char** var_ref_arr,
                                                 const char* var_name,
                                                 struct list* struct_hierarchy,
                                                 const char* func_name,
                                                 struct list_node** return_match_node);

ssize_t token_get_eq_index(const char* var_ref);

size_t token_get_actual_indices(const char* curr_var_ref, const char* comment_type,
                                bool has_open_str, size_t** comment_indices);

char* token_get_preprocessor_macro(const char* var_ref);

#endif /* TOKEN_GET_H */
