#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "c_keywords.h"
#include "utils.h"
#include "sanitize_expression.h"
#include "token_get.h"
#include "check_expression.h"
#include "file_search.h"
#include "func_call_parse.h"

#define EXPR_SIZE 65536

static char* get_full_expr(const char* source_file, size_t line_number);

static bool is_c_source_file(const char* source_file);

static char* get_clean_line(char** line_buf, FILE* f, size_t* buf_size,
                            bool* has_open_comment, size_t* nexted_if_0_levels,
                            bool* has_open_str);

static char* remove_comments(char* line_buf, size_t bytes_read,
                             bool* has_open_comment, size_t* nested_if_0_levels,
                             bool* has_open_str);

static bool is_curr_define(char** line);

static bool get_open_brackets(char* line, size_t* open_brackets);

static size_t get_actual_num_brackets(char* line, char bracket_char);

static void verify_multiline_var_ref(const char* multiline_var_ref,
                                     const char* san_var_ref, const char** var_ref_arr);

char* file_get_multiline_expr(const char* var_ref, const char** var_ref_arr,
                              bool has_invalid_code) {
  if (strstr(var_ref, "net/xfrm/xfrm_policy.c xfrm_policy_inexact_lookup_rcu 1983 struct xfrm_pol_inexact_key k = {") != NULL) {
    int test = 1;
  }
  bool has_open_str = false;
  char* san_var_ref = sanitize_remove_string_literals(var_ref, &has_open_str);
  char* trimmed_var_ref = utils_trim_str(san_var_ref);
  utils_free_if_both_different(san_var_ref, var_ref, trimmed_var_ref);
  san_var_ref = trimmed_var_ref;
  
  size_t last = strlen(san_var_ref) - 1;
  char* multiline_var_ref = NULL;
  bool is_partial_directive;
  if (san_var_ref[last] == '\\') {
    is_partial_directive = true;
    utils_truncate_str(san_var_ref, -1);
    trimmed_var_ref = utils_trim_str(san_var_ref);
    utils_free_if_both_different(san_var_ref, var_ref, trimmed_var_ref);
    san_var_ref = trimmed_var_ref;
  } else {
    is_partial_directive = false;
  }

  if (has_invalid_code || is_partial_directive || check_has_open_string(san_var_ref) ||
      check_has_mismatched_parenthesis(san_var_ref) || check_is_define(var_ref_arr[3]) ||
      (var_ref_arr[3][0] != '#' && !check_is_control_flow_expr(san_var_ref) &&
       !check_is_expression_with_effect(san_var_ref, var_ref_arr))) {
    if (var_ref_arr[3][0] == '.') {
      int test = 1;
    }
      multiline_var_ref = get_full_expr(var_ref_arr[0], atoi(var_ref_arr[2]));
  }
  //} //else if (strstr(san_var_ref, "#define") == NULL &&
//         (!check_is_expression(san_var_ref, var_ref_arr) ||
//            check_has_mismatched_parenthesis(san_var_ref))) {
//  multiline_var_ref = get_full_expr(var_ref_arr[0], atoi(var_ref_arr[2]));
//}
  
  if (multiline_var_ref == NULL && !check_has_mismatched_parenthesis(san_var_ref) &&
      strchr(san_var_ref, '=') == NULL && strchr(san_var_ref, '"') == NULL &&
      check_is_func(san_var_ref) && !check_is_control_flow_expr(san_var_ref)) {
    char* func_name = token_find_func_name(san_var_ref);
    if (func_name != NULL &&
        !utils_str_in_array(C_KEYWORDS, func_name, UTILS_SIZEOF_ARR(C_KEYWORDS))) {
      char* str_after_args = strchr(san_var_ref, '(');
      size_t args_start_index = str_after_args - san_var_ref;
      struct list* args_range;
      struct list* func_args = func_get_func_args(var_ref, args_start_index, &args_range);
      list_free(args_range);
      char* nested_func_name = token_find_func_name(str_after_args);
      if (nested_func_name == NULL &&
          ((func_args->len == 1 && strcmp((char*) func_args->head->payload, "void") == 0) ||
           check_has_arg_names(func_args)) &&
          !check_is_var_declaration(func_name, san_var_ref)) {
        multiline_var_ref = get_full_expr(var_ref_arr[0], atoi(var_ref_arr[2]));
      }
    }
  }

  if (multiline_var_ref == NULL && check_is_func(san_var_ref) &&
      !check_is_control_flow_expr(san_var_ref) &&
      strchr(san_var_ref, '=') == NULL && strchr(san_var_ref, '"') == NULL &&
      strstr(san_var_ref, "->") == NULL) {
    char* func_name = token_find_func_name(san_var_ref);
    if (func_name != NULL && !check_is_var_declaration(func_name, san_var_ref)) {
      char* func_and_parenthesis = (char*) malloc(strlen(func_name) + 2);
      strncpy(func_and_parenthesis, func_name, strlen(func_name));
      func_and_parenthesis[strlen(func_name)] = '(';
      func_and_parenthesis[strlen(func_name) + 1] = '\0';
      size_t args_start = (strstr(san_var_ref, func_and_parenthesis) - san_var_ref) +
        strlen(func_name) + 1;
      free(func_and_parenthesis);
      size_t curr_char = args_start;
      while (curr_char < strlen(san_var_ref) && san_var_ref[curr_char] != ',' &&
             san_var_ref[curr_char] != ')') {
        curr_char++;
      }
      size_t arg_declaration_len = curr_char - args_start;
      char* arg_declaration = (char*) malloc(arg_declaration_len + 1);
      strncpy(arg_declaration, san_var_ref + args_start, arg_declaration_len);
      arg_declaration[arg_declaration_len] = '\0';
      struct list* arg_declaration_lst = list_create();
      list_append(arg_declaration_lst, arg_declaration);
      if (strlen(arg_declaration) > 0 && strchr(arg_declaration, '(') == NULL &&
          check_has_arg_names(arg_declaration_lst)) {
        multiline_var_ref = get_full_expr(var_ref_arr[0], atoi(var_ref_arr[2]));
      }
      list_free(arg_declaration_lst);
    }
    free(func_name);
  }

  char* final_var_ref;
  if (multiline_var_ref != NULL) {
    final_var_ref = sanitize_clean_var_ref(multiline_var_ref);
    verify_multiline_var_ref(final_var_ref, san_var_ref, var_ref_arr);
    utils_free_if_different(multiline_var_ref, final_var_ref);
  } else {
    final_var_ref = sanitize_clean_var_ref(san_var_ref);
    utils_free_if_both_different(san_var_ref, var_ref, final_var_ref);
  }
  return final_var_ref;
}

static void verify_multiline_var_ref(const char* multiline_var_ref,
                                     const char* san_var_ref, const char** var_ref_arr) {
  const char* old_var_ref = san_var_ref;
  size_t code_start_idx = strlen(var_ref_arr[0]) + strlen(var_ref_arr[1]) +
    strlen(var_ref_arr[2]) + 3;
  san_var_ref = sanitize_clean_var_ref(san_var_ref + code_start_idx);
  char* var_ref_no_space = (char*) malloc(strlen(san_var_ref) + 1);
  size_t dst_i = 0;
  for (size_t i = 0; i < strlen(san_var_ref); i++) {
    if (!isspace(san_var_ref[i])) {
      var_ref_no_space[dst_i] = san_var_ref[i];
      dst_i++;
    }
  }
  var_ref_no_space[dst_i] = '\0';

  char* multiline_no_space = (char*) malloc(strlen(multiline_var_ref) + 1);
  dst_i = 0;
  for (size_t i = 0; i < strlen(multiline_var_ref); i++) {
    if (!isspace(multiline_var_ref[i])) {
      multiline_no_space[dst_i] = multiline_var_ref[i];
      dst_i++;
    }
  }
  multiline_no_space[dst_i] = '\0';
  
  assert((strlen(multiline_var_ref) == 0 || strstr(multiline_no_space, var_ref_no_space) != NULL) &&
         "file_get_multiline_expr: complete expression does not include var_ref");
  free(var_ref_no_space);
  free(multiline_no_space);
  utils_free_if_different((char*) san_var_ref, old_var_ref + code_start_idx);
}

static char* get_full_expr(const char* source_file, size_t line_number) {
  if (strcmp(source_file, "net/rose/rose_route.c") == 0) {
    int test = 1;
  }
  if (!is_c_source_file(source_file)) {
    printf("get_full_expr: not a C souce file: %s\n", source_file);
    char* empty_str = (char*) calloc(1, 1);
    return empty_str;
  }
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return NULL;
  }

  size_t curr_line = 0;
  char* expr = (char*) malloc(EXPR_SIZE);
  size_t curr_expr_size = EXPR_SIZE;
  expr[0] = '\0';
  size_t curr_idx = 0;
  size_t open_assignment_brackets = 0;
  size_t open_block_brackets = 0;
  size_t nested_if_0_levels = 0;
  bool prev_bracket_assign = false;
  bool prev_define = false;
  bool has_open_comment = false;
  bool has_open_str = false;
  bool is_in_macro = false;
  size_t macro_return_start = 0;
  char* macro_name = NULL;
  char* line_buf = NULL;
  size_t buf_size = 0;
  char* line;
  do {
    if (curr_line == 533) {
      int test = 1;
    }
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &has_open_str);
    assert(line != NULL && "get_full_expr: line is NULL");
    //if (line == NULL) {
    //  utils_free_if_different(line, line_buf);
    //  free(line_buf);
    //  free(expr);
    //  fclose(f);
    //  return NULL;
    //}
    if (curr_line == line_number && nested_if_0_levels > 0) {
      utils_free_if_different(line, line_buf);
      free(line_buf);
      free(expr);
      fclose(f);
      char* empty_str = (char*) calloc(1, 1);
      return empty_str;
    }
    if (strlen(line) == 0) {
      utils_free_if_different(line, line_buf);
      continue;
    }
    
    char* original_line = line;
    bool curr_define = is_curr_define(&line);
    utils_free_if_both_different(original_line, line_buf, line);
    if (strlen(line) == 0) {
      prev_define = true;
      utils_free_if_different(line, line_buf);
      continue;
    }
    get_open_brackets(line, &open_block_brackets);

    size_t last = strlen(line) - 1;
    bool curr_bracket_assign = false;
    if (open_assignment_brackets == 0) {
      if (line[last] == '{' && last > 0) {
        size_t search_idx = last - 1;
        while (search_idx >= 0 && isspace(line[search_idx])) {
          search_idx--;
        }
        if (check_is_assignment_op(line, search_idx)) {
          open_assignment_brackets = 1;
          curr_bracket_assign = true;
        }
      }
    } else {
      size_t num_open_brackets = utils_get_char_occurences(line, '{', NULL);
      size_t num_close_brackets = utils_get_char_occurences(line, '}', NULL);
      open_assignment_brackets += num_open_brackets;
      open_assignment_brackets -= num_close_brackets;
    }

    if (check_is_define(line)) {
      is_in_macro = true;
      macro_return_start = curr_line;
    }
    
    //if (line[0] == '#' && !check_has_mismatched_parenthesis(line)) {
    //  expr[0] = '\0';
    //  curr_idx = 0;
    if (line[0] == '.' && line[last] == ',' &&
        prev_bracket_assign && curr_line <= line_number)  {
      open_assignment_brackets = 0;
      strncpy(expr, line, strlen(line));
      curr_idx = strlen(line);
      expr[curr_idx] = '\0';
    } else {
      //if (strlen(expr) > 0 && expr[strlen(expr) - 1] == '(') {
      //   expr[curr_idx] = ' ';
      //  curr_idx++;
      //}
      if (curr_idx + strlen(line) + 1 >= curr_expr_size) {
        curr_expr_size += EXPR_SIZE;
        expr = (char*) realloc(expr, curr_expr_size);
      }
      if (curr_idx > 0){
        expr[curr_idx] = ' ';
        curr_idx++;
      }
      strncpy(expr + curr_idx, line, strlen(line));
      curr_idx += strlen(line);
      expr[curr_idx] = '\0';
    }
    if (line[last] == ':') {
      int test = 1;
    }

    if (line[last] == ';' || line[last] == '}' ||
        (line[last] == ':' && strchr(expr, '?') == NULL && !check_is_asm_block(expr)) ||
        (line[last] == '{' && open_assignment_brackets == 0) ||
        (expr[0] == '.' && expr[last] == ',' && open_assignment_brackets == 0 &&
         !check_has_mismatched_parenthesis(expr)) ||
        (prev_define && !curr_define) ||
        (expr[0] == '#' && !check_has_mismatched_parenthesis(expr)) ||
        (check_is_control_flow_expr(expr) &&
         !check_has_mismatched_parenthesis(expr)) ||
        (open_block_brackets == 0 && !curr_define && check_is_func(expr) &&
         !check_has_mismatched_parenthesis(expr))) {
      if (curr_line >= line_number) {
        if (is_in_macro && !curr_define && macro_name != NULL) {
          token_insert_macro_return_entry(macro_name, source_file,
                                          macro_return_start, curr_line);
        }
        utils_free_if_different(line, line_buf);
        break;
      } else {
        if (is_in_macro) {
          macro_return_start = curr_line + 1;
          if (check_is_define(expr)) {
            macro_name = token_find_func_name(expr);
          }
          if (!curr_define) {
            is_in_macro = false;
            free(macro_name);
            macro_name = NULL;
          }
        }
        expr[0] = '\0';
        curr_idx = 0;
      }
    } else if (line[last] == '/' && line[last-1] == '*') {
      expr[0] = '\0';
      curr_idx = 0;
    }

    prev_define = curr_define;
    prev_bracket_assign = curr_bracket_assign;
    utils_free_if_different(line, line_buf);
  } while (line != NULL);

  //printf("Full expression: %s\n", expr);
  free(line_buf);
  fclose(f);
  
  char* final_expr = (char*) malloc(strlen(expr) + 1);
  strncpy(final_expr, expr, strlen(expr));
  final_expr[strlen(expr)] = '\0';
  free(expr);
  assert(strlen(final_expr) > 0 && "get_full_expr: expression is empty");
  return final_expr;
}

static bool is_c_source_file(const char* source_file) {
  size_t extention_start = strlen(source_file) - 1;
  while (extention_start > 0 && source_file[extention_start] != '.') {
    extention_start--;
  }
  return strcmp(source_file + extention_start, ".c") == 0 ||
    strcmp(source_file + extention_start, ".h") == 0;
}

ssize_t file_get_func_from_src(const char* source_file, const char* func_name,
                               ssize_t* func_start_line) {
  if (!is_c_source_file(source_file)) {
    printf("file_get_func_from_src: not a C souce file: %s\n", source_file);
    return -1;
  }
  
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return -1;
  }

  *func_start_line = -1;
  size_t open_brackets = 0;
  bool bracket_found = false;
  bool is_macro = false;
  bool prev_define = false;
  size_t nested_if_0_levels = 0;
  bool has_open_comment = false;
  bool has_open_str = false;
  size_t curr_line = 0;
  char* expr = (char*) malloc(EXPR_SIZE);
  size_t curr_expr_size = EXPR_SIZE;
  expr[0] = '\0';
  size_t curr_idx = 0;
  char* line_buf = NULL;
  size_t buf_size = 0;
  char* line;
  do {
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &has_open_str);
    if (line == NULL) {
      utils_free_if_different(line, line_buf);
      //free(line_buf);
      //free(expr);
      //fclose(f);
      break;
    }
    if (strlen(line) == 0) {
      utils_free_if_different(line, line_buf);
      continue;
    }

    char* original_line = line;
    bool curr_define = is_curr_define(&line);
    utils_free_if_both_different(original_line, line_buf, line);
    if (strlen(line) == 0) {
      prev_define = true;
      utils_free_if_different(line, line_buf);
      continue;
    }

    if (curr_idx + strlen(line) + 1 >= curr_expr_size) {
      curr_expr_size += EXPR_SIZE;
      expr = (char*) realloc(expr, curr_expr_size);
    }
    expr[curr_idx] = ' ';
    curr_idx++;
    strncpy(expr + curr_idx, line, strlen(line));
    curr_idx += strlen(line);
    expr[curr_idx] = '\0';

    if (check_is_var_declaration(func_name, expr)) {
      *func_start_line = curr_line;
      if (check_is_define(expr)) {
        is_macro = true;
      }
    }

    size_t last = strlen(line) - 1;
    if (strlen(line) > 0 && (line[0] == '#' ||
                             utils_char_in_array("{};", line[last], 3) ||
                             (prev_define && line[last] == ')'))) {
      expr[0] = '\0';
      curr_idx = 0;
    }

    if (*func_start_line >= 0) {
      bracket_found = get_open_brackets(line, &open_brackets) || bracket_found;
      if ((open_brackets == 0 && bracket_found && !is_macro) ||
          (is_macro && !curr_define)) {
        free(line_buf);
        utils_free_if_different(line, line_buf);
        fclose(f);
        free(expr);
        return curr_line;
      }
    }

    prev_define = curr_define;
    utils_free_if_different(line, line_buf);
  } while (line != NULL);

  // assert(*func_start_line == -1 &&
  //       "file_get_func_from_src: Found start line, but not end line");
  fclose(f);
  free(line_buf);
  free(expr);
  return -1;
}

ssize_t file_get_func_end_line(const char* source_file, size_t func_start_line) {
  if (!is_c_source_file(source_file)) {
    printf("file_get_func_end_line: not a C souce file: %s\n", source_file);
    return -1;
  }
  
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return -1;
  }

  size_t open_brackets = 0;
  bool bracket_found = false;
  bool is_macro = false;
  bool has_open_comment = false;
  size_t nested_if_0_levels = 0;
  bool has_open_str = false;
  size_t curr_line = 0;
  char* line_buf = NULL;
  size_t buf_size = 0;
  char* line;
  do {
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &has_open_str);
    if (line == NULL) {
      utils_free_if_different(line, line_buf);
      free(line_buf);
      fclose(f);
      return -1;
    }
    if (strlen(line) == 0) {
      utils_free_if_different(line, line_buf);
      continue;
    }

    if (curr_line == func_start_line && check_is_define(line)) {
      is_macro = true;
    }
    if (curr_line >= func_start_line) {
      bracket_found = get_open_brackets(line, &open_brackets) || bracket_found;
      if (!bracket_found && !is_macro && line[strlen(line) - 1] == ';') {
        utils_free_if_different(line, line_buf);
        free(line_buf);
        fclose(f);
        return -1;
      }
      if ((open_brackets == 0 && bracket_found && !is_macro) ||
          (is_macro && line[strlen(line) - 1] != '\\')) {
        fclose(f);
        utils_free_if_different(line, line_buf);
        free(line_buf);
        return curr_line;
      }
    }

    utils_free_if_different(line, line_buf);
  } while (line != NULL);

  assert(false && "file_get_func_end_line: Reached unreachable point");
  return -1;
  //fclose(f);
  //free(line_buf);
  //return -1;
}

static char* get_clean_line(char** line_buf, FILE* f, size_t* buf_size,
                            bool* has_open_comment, size_t* nested_if_0_levels,
                            bool* has_open_str) {
  ssize_t bytes_read = getline(line_buf, buf_size, f);
  if (bytes_read < 0) {
    return NULL;
  }
  (*line_buf)[bytes_read] = '\0';

  return remove_comments(*line_buf, bytes_read, has_open_comment,
                         nested_if_0_levels, has_open_str);
}

static char* remove_comments(char* line_buf, size_t bytes_read,
                             bool* has_open_comment, size_t* nested_if_0_levels,
                             bool* has_open_str) {

  char* line = sanitize_remove_comments_and_strip(line_buf, has_open_comment,
                                                  has_open_str);
  if (*nested_if_0_levels == 0 &&
      (strstr(line, "#if 0") != NULL ||
       strstr(line, "#elif 0"))) {
    *has_open_comment = false;
    *has_open_str = false;
    *nested_if_0_levels = 1;
    line[0] = '\0';
  } else if (*nested_if_0_levels > 0) {
    *has_open_comment = false;
    *has_open_str = false;
    if (strstr(line, "#if") != NULL ||
        strstr(line, "#ifdef") != NULL||
        strstr(line, "#ifndef") != NULL) {
      (*nested_if_0_levels)++;
    }
    if (strstr(line, "#endif") != NULL ||
        (*nested_if_0_levels == 1 &&
         (strstr(line, "#else") != NULL ||
          (strstr(line, "#elif") != NULL &&
           strstr(line, "#elif 0") == NULL)))) {
      assert(*nested_if_0_levels > 0 &&
             "remove_comments: inconsistent nested #if 0 level");
      (*nested_if_0_levels)--;
    }
    line[0] = '\0';
  }

  return line;
}

static bool is_curr_define(char** line) {
  if ((*line)[strlen(*line) - 1] == '\\') {
    utils_truncate_str(*line, -1);
    *line = utils_trim_str(*line);
    return true;
  } else {
    return false;
  }
}

static bool get_open_brackets(char* line, size_t* open_brackets) {
  bool bracket_found = false;

  size_t num_open = get_actual_num_brackets(line, '{');
  size_t num_close = get_actual_num_brackets(line, '}');

  if (num_open > 0) {
    bracket_found = true;
  }
  (*open_brackets) += num_open;
  assert((num_close == 0 || *open_brackets > 0) &&
         "get_open_brackets: found close bracket without matching open bracket");
  (*open_brackets) -= num_close;
  
  /* if (strchr(line, '{') != NULL) { */
  /*   (*open_brackets)++; */
  /*   bracket_found = true; */
  /* } */
  /* if (strchr(line, '}') != NULL) { */
  /*   assert(*open_brackets > 0 && */
  /*          "get_open_brackets: found close bracket without matching open bracket"); */
  /*   (*open_brackets)--; */
  /* } */

  return bracket_found;
}

static size_t get_actual_num_brackets(char* line, char bracket_char) {
  size_t num_chars = utils_get_char_occurences(line, bracket_char, NULL);

  char bracket_literal[4];
  sprintf(bracket_literal, "'%c'", bracket_char);
  size_t num_literals = utils_get_str_occurences(line, bracket_literal, NULL);

  return num_chars - num_literals;
}

char* file_find_struct_name(const char* source_file, size_t line_number) {
  if (!is_c_source_file(source_file)) {
    printf("file_find_struct_name: not a C souce file: %s\n", source_file);
    char* empty_str = (char*) calloc(1, 1);
    return empty_str;
  }
  
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return NULL;
  }

  char* var_name = NULL;
  size_t curr_line = 0;
  char* line_buf = NULL;
  size_t nested_if_0_levels = 0;
  bool has_open_comment = false;
  bool has_open_str = false;
  size_t buf_size = 0;
  do {
    curr_line++;
    char* line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                                &nested_if_0_levels, &has_open_str);
    if (line == NULL) {
      utils_free_if_different(line, line_buf);
      free(line_buf);
      fclose(f);
      return NULL;
    }
    if (strlen(line) == 0) {
      utils_free_if_different(line, line_buf);
      continue;
    }

    char* old_line = line;
    line = sanitize_clean_var_ref(line);
    utils_free_if_both_different(old_line, line_buf, line);

    if (strstr(line, "struct") != NULL && strchr(line, '=') != NULL &&
        strchr(line, '{') != NULL) {
      char** tokens;
      size_t num_tokens = utils_split_str(line, &tokens);
      for (size_t i = 0; i < num_tokens; i++) {
        if (strcmp(tokens[i], "struct") == 0) {
          var_name = (char*) malloc(strlen(tokens[i + 2]) + 1);
          strncpy(var_name, tokens[i + 2], strlen(tokens[i + 2]) + 1);
          utils_free_str_arr(tokens);
          break;
        }
      }
    } else if (check_is_define(line)) {
      utils_free_if_different(line, line_buf);
      free(line_buf);
      fclose(f);
      return NULL;
    }

    if (curr_line == line_number) {
      utils_free_if_different(line, line_buf);
      free(line_buf);
      fclose(f);
      return var_name;
    }
    
    utils_free_if_different(line, line_buf);
  } while(feof(f));

  free(line_buf);
  fclose(f);
  return NULL;
}
