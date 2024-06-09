#ifndef SANITIZE_EXPRESSION_H
#define SANITIZE_EXPRESSION_H

char *sanitize_extract_varname(const char* var_name);

char* sanitize_peel_parenthesis(const char* var_ref);

char* sanitize_remove_comments_and_strip(char* var_ref, bool* has_open_comment,
                                         bool* has_open_str);

char* sanitize_remove_sizeof(const char* var_ref);

char* sanitize_remove_string_literals(const char* var_ref, bool* has_open_str);

char* sanitize_remove_casts(const char* var_ref);

char* sanitize_remove_array_indexing(const char* var_ref);

char* sanitize_remove_substring(const char* var_ref, struct list* substring_indices);

char* sanitize_clean_var_ref(const char* var_ref);

#endif /* SANITIZE_EXPRESSION_H */
