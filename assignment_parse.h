#ifndef ASSIGNMENT_PARSE_H
#define ASSIGNMENT_PARSE_H

struct list* assignment_handle_var_assignment(const char* func_name,
                                              const char* var_ref,
                                              const char** var_ref_arr,
                                              size_t var_ref_arr_len,
                                              const char* var_name,
                                              struct list* struct_hierarchy,
                                              bool is_return_assignment,
                                              hash_map func_ptrs,
                                              struct list** return_hierarchy,
                                              struct list** output_args);

char* assignment_get_assignment_var(const char* func_name, const char* var_ref,
                                    const char** var_ref_arr, size_t var_ref_arr_len,
                                    const char* var_name, bool is_return_assignment,
                                    const char** assignment_lhs,
                                    bool* out_arg_assignment);

struct list* assignment_get_assigned_var_funcs(const char* func_name,
                                               char* assigned_var,
                                               struct list* struct_hierarchy,
                                               const char** var_ref_arr,
                                               size_t var_ref_arr_len,
                                               hash_map func_ptrs,
                                               struct list** return_hierarchy,
                                               struct list** output_args);

void assignment_append_out_arg(struct list* out_args, char* arg_name,
                               struct list* struct_hierarchy);

#endif /* ASSIGNEMNT_PARSE_H */
