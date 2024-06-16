#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <assert.h>
#include "c_keywords.h"
#include "list.h"
#include "hash_map.h"
#include "utils.h"
#include "database.h"
#include "check_expression.h"
#include "sanitize_expression.h"
#include "struct_parse.h"
#include "token_get.h"
#include "func_call_parse.h"
#include "file_search.h"

struct macro_return_range {
  size_t return_start;
  size_t return_end;
};

static struct macro_return_range* get_macro_return_entry(const char* macro_name,
                                                         const char* src_file);

static bool is_func_return(const char* var_ref, const char* var_name,
                           char** var_ref_no_funcs);

static hash_map macro_return_ranges = map_create();

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
  if (strcmp(var_ref,"arch/x86/kernel/cpu/microcode/amd.c apply_microcode_early_amd 430 patch = (u8 (*)[PATCH_MAX_SIZE])__pa_nodebug(&amd_ucode_patch);") == 0) {
    int test = 1;
  }
  if (args_start_index == 0 || check_is_func_ptr(var_ref)) {
    return NULL;
  }
  if (!check_is_define(var_ref)) {
    size_t par_start = args_start_index + 1;
    while (par_start < strlen(var_ref) && (isspace(var_ref[par_start]) || var_ref[par_start] == '*')) {
      par_start++;
    }
    size_t par_end = par_start;
    size_t valid_varname_nested_chars = 0;
    while (par_end < strlen(var_ref) && check_is_valid_varname_char(var_ref[par_end])) {
      par_end++;
      valid_varname_nested_chars++;
    }
    size_t curr_idx = par_end;
    while (curr_idx < strlen(var_ref) && isspace(var_ref[curr_idx])) {
      curr_idx++;
    }
    if (curr_idx < strlen(var_ref) && var_ref[curr_idx] == ')') {
      curr_idx++;
      while (curr_idx < strlen(var_ref) && isspace(var_ref[curr_idx])) {
        curr_idx++;
      }
      if (curr_idx < strlen(var_ref) &&
          (token_get_eq_index(var_ref) < 0 || valid_varname_nested_chars == 0) &&
          (var_ref[curr_idx] == '(' || var_ref[curr_idx] == '[')) {
        return NULL;
      }
    }
  }
  
  ssize_t func_name_end = args_start_index - 1;
  while(func_name_end > 0 && isspace(var_ref[func_name_end])) {
    func_name_end--;
  }
  if (!check_is_valid_varname_char(var_ref[func_name_end])) {
    return NULL;
  }

  // TODO: add support for array function pointers
  ssize_t func_name_start = func_name_end;
  while (func_name_start > 0 &&
         (check_is_valid_varname_char(var_ref[func_name_start]) ||
          var_ref[func_name_start] == '.' ||
          (var_ref[func_name_start] == '>' && var_ref[func_name_start-1] == '-'))) {
    if (func_name_start > 1 && var_ref[func_name_start] == '>' &&
        var_ref[func_name_start - 1] == '-') {
      func_name_start -= 2;
    } else {
      func_name_start--;
    }
  }
  if (!check_is_valid_varname_char(var_ref[func_name_start]) &&
      var_ref[func_name_start] != '.') {
    func_name_start++;
  }

  if (!check_is_valid_varname_char(var_ref[func_name_start])) {
    return NULL;
  }

  size_t func_name_len = func_name_end - func_name_start + 1;
  char* func_name = (char*) malloc(func_name_len + 1);
  strncpy(func_name, var_ref + func_name_start, func_name_len);
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

void token_insert_macro_return_entry(const char* macro_name, const char* src_file,
                                     size_t return_start, size_t return_end) {
  hash_map src_file_map;
  if (map_contains(macro_return_ranges, macro_name)) {
    src_file_map = (hash_map) map_get(macro_return_ranges, macro_name);
  } else {
    src_file_map = map_create();
    map_insert(macro_return_ranges, macro_name, src_file_map);
  }

  if (!map_contains(src_file_map, src_file)) {
    struct macro_return_range* entry =
      (struct macro_return_range*) malloc(sizeof(struct macro_return_range));
    entry->return_start = return_start;
    entry->return_end = return_end;
    map_insert(src_file_map, src_file, entry);
    database_write_macros_return_range(macro_name, src_file, return_start, return_end);
  }
}

enum TokenReturnType token_get_return_match_node(const char* var_ref,
                                                 const char** var_ref_arr,
                                                 const char* var_name,
                                                 struct list* struct_hierarchy,
                                                 const char* func_name,
                                                 struct list_node** return_match_node) {
  if (strstr(var_ref, var_ref_arr[0]) == var_ref) {
    var_ref = strstr(var_ref, var_ref_arr[2]) + strlen(var_ref_arr[2]) + 1;
  }
  const char* original_var_ref = var_ref;
  char* san_var_ref = sanitize_remove_array_indexing(var_ref);
  var_ref = san_var_ref;
  
  if (strcmp(func_name, "HASH_MIX") == 0) {
    int test = 1;
  }
  bool is_define = false;
  size_t statement_start = 0;

  const char* func_declaration;
  const char* func_src_file;
  size_t func_start_line;
  enum FuncDeclStatus status = func_get_func_decl(func_name, var_ref_arr[0],
                                                  &func_declaration, &func_src_file,
                                                  &func_start_line);
  if (status == FUNC_DECL_FOUND) {
    if (check_is_define(func_declaration)) {
      is_define = true;
      if (strcmp(func_src_file, var_ref_arr[0]) == 0) {
        size_t curr_ref_line = atoi(var_ref_arr[2]);
        struct macro_return_range* return_range =
          get_macro_return_entry(func_name, func_src_file);
        if (return_range != NULL && curr_ref_line >= return_range->return_start &&
            curr_ref_line <= return_range->return_end) {
          if (check_is_define(var_ref)) {
            size_t args_start = strchr(var_ref, '(') - var_ref;
            statement_start = check_recur_with_parenthesis(var_ref, args_start + 1, '(');
            statement_start++;
          } else {
            statement_start = 0;
          }
        } else {
          return NO_RETURN;
        }
      } else {
        return NO_RETURN;
      }
    }
  } else {
    //printf("No function declaration cached for current function: %s\n", func_name);
  }

  if (!is_define) {
    const char* return_ptr = strstr(var_ref, "return");
    size_t return_index = return_ptr - var_ref;
    if (return_ptr == NULL || !check_is_token_match(var_ref, return_index, strlen("return"))) {
      return NO_RETURN;
    }

    statement_start = return_index + strlen("return") + 1;
  }

  const char* return_statement = var_ref + statement_start;
  char* var_ref_no_funcs;
  if (is_func_return(return_statement, var_name, &var_ref_no_funcs)) {
    free(var_ref_no_funcs);
    utils_free_if_different(san_var_ref, original_var_ref);
    return FUNC_RETURN;
  }

  struct list* struct_matches = struct_get_struct_matches(var_ref_no_funcs,
                                                          var_name, struct_hierarchy);
  utils_free_if_different(var_ref_no_funcs, return_statement);
  if (struct_matches->len == 0) {
    list_free_nodes(struct_matches);
    utils_free_if_different(san_var_ref, original_var_ref);
    return NO_RETURN;
  } else {
    *return_match_node = struct_get_highest_match(struct_matches);
    list_free_nodes(struct_matches);
    utils_free_if_different(san_var_ref, original_var_ref);
    return VAR_RETURN;
  }
  
  /* for (size_t i = 0; i < num_var_occurences; i++) { */
  /*   if (check_is_token_match(var_ref, var_occurences[i], strlen(var_name))) { */
  /*     struct list* curr_matches = struct_get_struct_matches(var_ref, var_name, */
  /*                                                           struct_hierarchy); */
  /*     list_free_nodes(var_indices); */
  /*     if (hierarchy_matches->len == 0) { */
  /*       list_free_nodes(hierarchy_matches); */
  /*       return NO_RETURN; */
  /*     } else { */
  /*       *return_match_node = struct_get_highest_match(hierarchy_matches); */
  /*       list_free_nodes(hierarchy_matches); */
  /*       return VAR_RETURN; */
  /*     } */
  /*   } */
  /* } */

  /* list_free_nodes(var_indices); */
  /* return NO_RETURN; */
}

static bool is_func_return(const char* var_ref, const char* var_name,
                           char** var_ref_no_funcs) {
  size_t* args_start_indices;
  size_t num_args_start = utils_get_char_occurences(var_ref, '(', &args_start_indices);
  struct list* funcs_ranges = list_create();
  for (size_t i = 0; i < num_args_start; i++) {
    char* func_name = token_get_func_name(var_ref, args_start_indices[i]);
    if (func_name != NULL) {
      size_t func_end_index = check_recur_with_parenthesis(var_ref, args_start_indices[i] + 1, '(');
      assert(func_end_index < strlen(var_ref) &&
             "is_func_return: function call does not end with parenthesis");
      struct index_range* func_range =
        (struct index_range*) malloc(sizeof(struct index_range));
      *func_range = {args_start_indices[i] - strlen(func_name), func_end_index + 1};
      list_append(funcs_ranges, func_range);
    }
    free(func_name);
  }
  free(args_start_indices);
  
  if (funcs_ranges->len == 0) {
    list_free(funcs_ranges);
    *var_ref_no_funcs = (char*) var_ref;
    return false;
  }
  *var_ref_no_funcs = sanitize_remove_substring(var_ref, funcs_ranges);
  list_free(funcs_ranges);

  size_t* var_occurences;
  size_t num_var_occurences = utils_get_str_occurences(*var_ref_no_funcs, var_name,
                                                       &var_occurences);
  for (size_t i = 0; i < num_var_occurences; i++) {
    if (check_is_token_match(*var_ref_no_funcs, var_occurences[i], strlen(var_name))) {
      free(var_occurences);
      return false;
    }
  }

  free(var_occurences);
  return true;
}

static struct macro_return_range* get_macro_return_entry(const char* macro_name, const char* src_file) {
  if (!map_contains(macro_return_ranges, macro_name)) {
    return NULL;
  }

  hash_map src_file_map = (hash_map) map_get(macro_return_ranges, macro_name);
  if (!map_contains(src_file_map, src_file)) {
    return NULL;
  }

  return (struct macro_return_range*) map_get(src_file_map, src_file);
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

size_t token_get_actual_indices(const char* curr_var_ref, const char* comment_type,
                                bool has_open_str, size_t** comment_indices) {
  if (strcmp(curr_var_ref,"\t\t/* \"typedef void new_void\", \"const void\"...etc */\n") == 0) {
    int test = 1;
  }
  size_t* all_comment_indices;
  size_t total_num_comments = utils_get_str_occurences(curr_var_ref, comment_type, &all_comment_indices);
  struct list* string_ranges = check_get_string_ranges(curr_var_ref, &has_open_str);
  if (string_ranges->len == 0) {
    list_free(string_ranges);
    *comment_indices = all_comment_indices;
    return total_num_comments;
  }

  *comment_indices = (size_t*) malloc(sizeof(size_t) * total_num_comments);
  size_t num_comments = 0;
  for (size_t i = 0; i < total_num_comments; i++) {
    bool is_comment = true;
    for (struct list_node* curr = string_ranges->head; curr != NULL;
         curr = curr->next) {
      struct index_range* curr_range = (struct index_range*) curr->payload;
      if (all_comment_indices[i] >= curr_range->start &&
          all_comment_indices[i] <= curr_range->end) {
        is_comment = false;
        break;
      }
    }
    if (is_comment) {
      (*comment_indices)[num_comments] = all_comment_indices[i];
      num_comments++;
    }
  }

  free(all_comment_indices);
  list_free(string_ranges);
  return num_comments;
}

char* token_get_preprocessor_macro(const char* var_ref) {
  size_t macro_start = 1;
  while (macro_start < strlen(var_ref) && isspace(var_ref[macro_start])) {
    macro_start++;
  }
  while (macro_start < strlen(var_ref) &&
         check_is_valid_varname_char(var_ref[macro_start])) {
    macro_start++;
  }
  while (macro_start < strlen(var_ref) && isspace(var_ref[macro_start])) {
    macro_start++;
  }
  assert(macro_start < strlen(var_ref) &&
         "token_get_preprocessor_macro: directive has no macro");

  size_t macro_len = strlen(var_ref) - macro_start;
  char* macro = (char*) malloc(macro_len + 1);
  size_t curr_macro_char = 0;
  for (size_t i = macro_start; i < strlen(var_ref); i++) {
    if (!isspace(var_ref[i])) {
      macro[curr_macro_char] = var_ref[i];
      curr_macro_char++;
    }
  }

  macro[curr_macro_char] = '\0';
  return macro;
}

char* token_get_sysctl_table_name(const char* var_ref, size_t* assignment_start) {
  size_t* struct_keywords;
  size_t num_struct_keywords = utils_get_str_occurences(var_ref, "struct",
                                                        &struct_keywords);
  for (size_t i = 0; i < num_struct_keywords; i++) {
    if (check_is_token_match(var_ref, struct_keywords[i], strlen("struct"))) {
      size_t type_start = struct_keywords[i] + strlen("struct");
      while (type_start < strlen(var_ref) && isspace(var_ref[type_start])) {
        type_start++;
      }
      size_t type_end = type_start;
      while (type_end < strlen(var_ref) &&
             check_is_valid_varname_char(var_ref[type_end])) {
        type_end++;
      }

      if (type_end < strlen(var_ref)) {
        size_t token_len = type_end - type_start;
        char* type_token = (char*) malloc(token_len + 1);
        strncpy(type_token, var_ref + type_start, token_len);
        type_token[token_len] = '\0';
        if (strcmp(type_token, "ctl_table") == 0) {
          size_t name_start = type_end + 1;
          while (name_start < strlen(var_ref) && isspace(var_ref[name_start])) {
            name_start++;
          }
          size_t name_end = name_start;
          while (name_end < strlen(var_ref) &&
                 check_is_valid_varname_char(var_ref[name_end])) {
            name_end++;
          }

          if (name_end < strlen(var_ref)) {
            size_t name_len = name_end - name_start;
            char* table_name = (char*) malloc(name_len + 1);
            strncpy(table_name, var_ref + name_start, name_len);
            table_name[name_len] = '\0';

            size_t bracket_start = name_end;
            while (bracket_start < strlen(var_ref) && var_ref[bracket_start] != '[') {
              bracket_start++;
            }
            size_t bracket_end = check_recur_with_parenthesis(var_ref, bracket_start + 1, '[');
            if (bracket_end < strlen(var_ref)) {
              size_t eq_index = bracket_end + 1;
              while (eq_index < strlen(var_ref) && isspace(var_ref[eq_index])) {
                eq_index++;
              }
              if (eq_index < strlen(var_ref) &&
                  check_is_assignment_op(var_ref, eq_index)) {
                free(struct_keywords);
                free(type_token);
                *assignment_start = eq_index;
                return table_name;
              }
            }
            free(table_name);
          }
        }
        free(type_token);
      }
    }
  }

  free(struct_keywords);
  return NULL;
}

const char* token_get_func_call(const char* var_ref, const char* curr_func) {
  if (check_is_func(var_ref)) {
    if (!check_is_var_declaration(curr_func, var_ref)) {
      return var_ref;
    } else {
      const char* curr_var_ref = var_ref;
      size_t* args_start_indices;
      size_t num_start_indices = utils_get_char_occurences(var_ref, '(',
                                                           &args_start_indices);
      for (size_t i = 0; i < num_start_indices; i++) {
        char* func_name = token_get_func_name(var_ref, args_start_indices[i]);
        if (func_name != NULL) {
          if (strcmp(func_name, curr_func) == 0) {
            free(func_name);
            size_t decl_end =
              check_recur_with_parenthesis(var_ref, args_start_indices[i] + 1, '(');
            curr_var_ref += (decl_end + 1);
          } else {
            free(func_name);
            free(args_start_indices);
            return curr_var_ref;
          }
        }
      }
      free(args_start_indices);
    }
  }

  return NULL;
}
                                                              
