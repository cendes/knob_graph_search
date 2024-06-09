#ifndef CHECK_EXPRESSION_H
#define CHECK_EXPRESSION_H

#include "list.h"
#include "hash_map.h"

struct index_range {
  size_t start;
  size_t end;
};

extern hash_map check_out_of_scope;

bool check_is_expression_with_effect(const char* var_ref, const char** var_ref_arr);

bool check_is_control_flow_expr(const char* var_ref);

bool check_is_func(const char* var_ref);

bool check_has_mismatched_parenthesis(const char* var_ref);

bool check_is_ref(const char* var_ref, const char* var_name, const char* func_name, bool is_global);

bool check_is_var_declaration(const char* var_name, const char* var_ref);

ssize_t check_recur_with_parenthesis(const char* var_ref, size_t curr_index, char parenthesis_type);

bool check_has_var_name(const char* var_ref, const char* var_name);

bool check_has_unary_operand(const char* token);

bool check_is_valid_varname(const char* token);

bool check_is_valid_varname_char(char chr);

bool check_is_asm_block(const char* var_ref);

bool check_is_extern(const char* var_ref);

bool check_has_arg_names(struct list* func_args_declaration);

bool check_is_func_ptr(const char* var_declaration);

bool check_has_open_string(const char* var_ref);

bool check_is_assignment_op(const char* token, size_t curr_char);

bool check_is_static(const char* var_ref);

bool check_is_token_match(const char* var_ref, size_t index, size_t token_len);

struct list* check_get_string_ranges(const char* var_ref, bool* has_open_str);

bool check_is_arg_assignment(const char* var_name, struct list* func_args_name);

bool check_is_struct_root(const char* var_ref, size_t root_index);

bool check_is_func_decl_in_scope(const char* func_decl, const char* decl_src_file,
                                 const char* ref_src_file);

#endif /* CHECK_EXPRESSION_H */
