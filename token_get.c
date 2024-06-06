#include <string.h>
#include <ctype.h>
#include "c_keywords.h"
#include "list.h"
#include "hash_map.h"
#include "utils.h"
#include "check_expression.h"
#include "struct_parse.h"
#include "token_get.h"
#include "func_call_parse.h"

char* token_find_func_name(const char* var_ref) {
  size_t* args_start_indices;
  size_t num_start_indices = utils_get_char_occurences(var_ref, '(',
                                                       &args_start_indices);
  for (size_t i = 0; i < num_start_indices; i++) {
    char* func_name = token_get_func_name(var_ref, args_start_indices[i]);
    if (func_name != NULL) {
      free(args_start_indices);
      return func_name;
    }
  }

  free(args_start_indices);
  return NULL;
}

char* token_get_func_name(const char* var_ref, size_t args_start_index) {
  ssize_t func_name_start = args_start_index - 1;
  while (func_name_start >= 0 &&
         (check_is_valid_varname_char(var_ref[func_name_start]) ||
          utils_char_in_array(".>", var_ref[func_name_start], 2))) {
    if (var_ref[func_name_start] == '>' && func_name_start > 0 &&
        var_ref[func_name_start - 1] == '-') {
      func_name_start -= 2;
    } else {
      func_name_start--;
    }
  }

  size_t func_name_len = args_start_index - func_name_start - 1;
  char* func_name = (char*) malloc(func_name_len + 1);
  strncpy(func_name, var_ref + func_name_start + 1, func_name_len);
  func_name[func_name_len] = '\0';

  if (func_name_len == 0 ||
      utils_str_in_array(C_KEYWORDS, func_name, UTILS_SIZEOF_ARR(C_KEYWORDS))) {
    free(func_name);
    return NULL;
  } else {
    return func_name;
  }
}

char* token_get_func_ptr_name(const char* func_ptr_declaration) {
  const char* parenthesis_ptr = strchr(func_ptr_declaration, '(');
  char* start_ptr = (char*) parenthesis_ptr + 1;
  while (isspace(*start_ptr) || *start_ptr == '*') {
    start_ptr++;
  }
  
  char* end_ptr = start_ptr;
  char* declaration_end = (char*) func_ptr_declaration + strlen(func_ptr_declaration);
  while (end_ptr < declaration_end && (check_is_valid_varname_char(*end_ptr) || *end_ptr == '*')) {
    end_ptr++;
  }

  size_t func_ptr_name_len = end_ptr - start_ptr;
  char* func_ptr_name = (char*) malloc(func_ptr_name_len + 1);
  strncpy(func_ptr_name, start_ptr, func_ptr_name_len);
  func_ptr_name[func_ptr_name_len] = '\0';
  
  return func_ptr_name;
}

enum TokenReturnType token_get_return_match_node(const char* var_ref,
                                                 const char** var_ref_arr,
                                                 const char* var_name,
                                                 struct list* struct_hierarchy,
                                                 const char* func_name,
                                                 struct list_node** return_match_node) {
  bool is_define = false;
  size_t statement_start = 0;

  const char* func_declaration;
  const char* func_src_file;
  enum FuncDeclStatus status = func_get_func_decl(func_name, var_ref_arr[0],
                                                  &func_declaration, &func_src_file);
  if (status == FUNC_DECL_FOUND) {
    char** func_declaration_arr;
    size_t declaration_len = utils_split_str(func_declaration, &func_declaration_arr);
    if (utils_str_in_array((const char**) func_declaration_arr, "#define", declaration_len)) {
      is_define = true;
      if (strchr(func_declaration_arr[declaration_len - 1], '\\') != NULL ||
          strcmp(func_declaration_arr[0], var_ref_arr[0]) != 0) {
        utils_free_str_arr(func_declaration_arr);
        return NO_RETURN;
      } else if (atoi(func_declaration_arr[2]) == atoi(var_ref_arr[2])) {
        size_t args_start = strchr(var_ref, '(') - var_ref;
        statement_start = check_recur_with_parenthesis(var_ref, args_start + 1, '(');
      } else {
        statement_start = 0;
      }
    }
    utils_free_str_arr(func_declaration_arr);
  }

  if (!is_define) {
    const char* return_ptr = strstr(var_ref, "return");
    size_t return_index = return_ptr - var_ref;
    if (return_ptr == NULL || !check_is_token_match(var_ref, return_index, strlen("return"))) {
      return NO_RETURN;
    }

    statement_start = return_index + strlen("return");
  }

  if (check_is_func(var_ref + statement_start + 1)) {
    return FUNC_RETURN;
  }

  size_t* var_occurences;
  size_t var_occurences_len = utils_get_str_occurences(var_ref, var_name, &var_occurences);
  struct list* var_indices = list_create();
  for (size_t i = 0; i < var_occurences_len; i++) {
    if (var_occurences[i] > statement_start) {
      list_append(var_indices, (void*) var_occurences[i]);
    }
  }
  free(var_occurences);

  for (struct list_node* curr = var_indices->head; curr != NULL; curr = curr->next) {
    size_t var_index = (size_t) curr->payload;
    if (check_is_token_match(var_ref, var_index, strlen(var_name))) {
      struct list* hierarchy_matches = struct_get_struct_matches(var_ref, var_name,
                                                                 struct_hierarchy);
      list_free_nodes(var_indices);
      if (hierarchy_matches->len == 0) {
        list_free_nodes(hierarchy_matches);
        return NO_RETURN;
      } else {
        *return_match_node = struct_get_highest_match(hierarchy_matches);
        list_free_nodes(hierarchy_matches);
        return VAR_RETURN;
      }
    }
  }

  list_free_nodes(var_indices);
  return NO_RETURN;
}

ssize_t token_get_eq_index(const char* var_ref) {
  size_t* eq_indices;
  size_t num_eq_indices = utils_get_char_occurences(var_ref, '=', &eq_indices);
  for (size_t i = 0; i < num_eq_indices; i++) {
    if (check_is_assignment_op(var_ref, eq_indices[i])) {
      size_t eq_index = eq_indices[i];
      free(eq_indices);
      return eq_index;
    }
  }

  free(eq_indices);
  return -1;
}
                                                              
