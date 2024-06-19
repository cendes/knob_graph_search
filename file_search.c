#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "c_keywords.h"
#include "utils.h"
#include "database.h"
#include "sanitize_expression.h"
#include "token_get.h"
#include "check_expression.h"
#include "file_search.h"
#include "func_call_parse.h"

#define EXPR_SIZE 65536

struct bracket_state {
  char* label;
  struct bracket_state* parent;
  hash_map children;
  ssize_t open_block_brackets_diff;
  ssize_t open_assignment_brackets_diff;
  bool prev_bracket_assign;
  size_t open_block_brackets_in;
  size_t open_assignment_brackets_in;
};

static char* get_full_expr(const char* source_file, size_t line_number);

static bool is_c_source_file(const char* source_file);

static char* get_clean_line(char** line_buf, FILE* f, size_t* buf_size,
                            bool* has_open_comment, size_t* nested_if_0_levels,
                            bool* in_if_0_else_block, size_t* nested_asm_levels,
                            bool* has_open_str);

static char* remove_comments(char* line_buf, size_t bytes_read,
                             bool* has_open_comment, size_t* nested_if_0_levels,
                             bool* in_if_0_else_block, size_t* nested_asm_levels,
                             bool* has_open_str);

static bool is_curr_define(char** line);

static struct bracket_state* create_bracket_state_node(struct bracket_state* parent,
                                                       char* label,
                                                       size_t open_block_brackets,
                                                       size_t open_assignment_brackets,
                                                       bool prev_bracket_assign);

static struct bracket_state* create_bracket_state_root();

static void save_current_bracket_state(struct bracket_state* curr_state,
                                       size_t open_block_brackets,
                                       size_t open_assignment_brackets,
                                       bool prev_bracket_assign);

static size_t visit_next_bracket_state(char* line, struct bracket_state** curr_state,
                                       char* last_label,
                                       size_t* open_block_brackets,
                                       size_t* open_assignment_brackets,
                                       bool* prev_bracket_assign);

static size_t restore_previous_bracket_state(struct bracket_state** curr_state,
                                             size_t* open_block_brackets,
                                             size_t* open_assignment_brackets,
                                             bool* prev_bracket_assign,
                                             char** last_label);

static void merge_bracket_states(struct bracket_state* parent_state,
                                 struct bracket_state* else_state,
                                 size_t open_block_brackets,
                                 size_t open_assignment_brackets);

static void free_bracket_state_tree(struct bracket_state* curr_state);

static bool get_open_brackets(char* line, size_t* open_brackets);

static size_t get_actual_num_brackets(char* line, char bracket_char);

static void verify_multiline_var_ref(const char* multiline_var_ref,
                                     const char* san_var_ref, const char** var_ref_arr);

char* file_get_multiline_expr(const char* var_ref, const char** var_ref_arr,
                              bool has_invalid_code) {
  //if (strstr(var_ref_arr[1], "codegen_attach_detach") != NULL) {
  //  int test = 1;
  //}
  if (strlen(var_ref) == 0) {
    return (char*) var_ref;
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
  if (strcmp(source_file, "include/uapi/linux/if_hippi.h") == 0) {
    int test = 1;
  }
  if (strcmp(source_file, "security/tomoyo/group.c") == 0) {
    int test = 1;
  }
  if (!is_c_source_file(source_file)) {
    fprintf(stderr, "get_full_expr: not a C souce file: %s\n", source_file);
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
  bool prev_bracket_assign = false;
  struct bracket_state* bracket_state_root = create_bracket_state_root();
  struct bracket_state* curr_bracket_state = bracket_state_root;
  bool is_else_state = false;
  size_t nested_if_0_levels = 0;
  bool in_if_0_else_block = false;
  size_t nested_asm_levels = 0;
  bool prev_define = false;
  bool is_cond_directive = false;
  bool has_open_comment = false;
  bool has_open_str = false;
  bool is_in_macro = false;
  size_t macro_return_start = 0;
  char* macro_name = NULL;
  char* line_buf = NULL;
  size_t buf_size = 0;
  char* line;
  do {
    if (curr_line == 79) {
      int test = 1;
    }
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &in_if_0_else_block,
                          &nested_asm_levels, &has_open_str);
    assert(line != NULL && "get_full_expr: line is NULL");
    //if (line == NULL) {
    //  utils_free_if_different(line, line_buf);
    //  free(line_buf);
    //  free(expr);
    //  fclose(f);
    //  return NULL;
    //}
    if ((curr_line == line_number &&
         (nested_if_0_levels > 0 || nested_asm_levels > 0 || is_cond_directive)) ||
        check_is_preprocessor_macro(line, "define", "TRACE_SYSTEM")) {
      free_bracket_state_tree(bracket_state_root);
      utils_free_if_different(line, line_buf);
      free(line_buf);
      free(expr);
      fclose(f);
      char* empty_str = (char*) calloc(1, 1);
      return empty_str;
    }
    if (strlen(line) == 0) {
      is_cond_directive = false;
      utils_free_if_different(line, line_buf);
      if (curr_line >= line_number && prev_define) {
        int test = 1;
        break;
      } else {
        continue;
      }
    }
    
    char* original_line = line;
    bool curr_define = is_curr_define(&line);
    utils_free_if_both_different(original_line, line_buf, line);
    if (strlen(line) == 0 || is_cond_directive) {
      if (is_cond_directive) {
        int test = 1;
      }
      prev_define = curr_define;
      is_cond_directive = is_cond_directive && curr_define;
      utils_free_if_different(line, line_buf);
      continue;
    }
    if (check_is_preprocessor_directive(line, "if") ||
        check_is_preprocessor_directive(line, "ifdef") ||
        check_is_preprocessor_directive(line, "ifndef")) {
      if (curr_line == line_number) {
        free_bracket_state_tree(bracket_state_root);
        utils_free_if_different(line, line_buf);
        free(line_buf);
        free(expr);
        fclose(f);
        char* empty_str = (char*) calloc(1, 1);
        return empty_str;
      }
      is_cond_directive = curr_define;
      save_current_bracket_state(curr_bracket_state, open_block_brackets,
                                 open_assignment_brackets, prev_bracket_assign);
      open_block_brackets = visit_next_bracket_state(line, &curr_bracket_state,
                                                     NULL, &open_block_brackets,
                                                     &open_assignment_brackets,
                                                     &prev_bracket_assign);
      utils_free_if_different(line, line_buf);
      continue;
    } else if (check_is_preprocessor_directive(line, "else") ||
               check_is_preprocessor_directive(line, "elsif") ||
               check_is_preprocessor_directive(line, "endif")) {
      if (curr_line == line_number) {
        free_bracket_state_tree(bracket_state_root);
        utils_free_if_different(line, line_buf);
        free(line_buf);
        free(expr);
        fclose(f);
        char* empty_str = (char*) calloc(1, 1);
        return empty_str;
      }
      is_cond_directive = curr_define;
      size_t old_open_block_brackets = open_block_brackets;
      size_t old_open_assignment_brackets = open_assignment_brackets;
      char* last_label;
      if (in_if_0_else_block) {
        int test = 1;
      }
      if (is_else_state) {
        if (curr_bracket_state->parent != NULL) {
          merge_bracket_states(curr_bracket_state->parent, curr_bracket_state,
                               open_block_brackets, open_assignment_brackets);
          curr_bracket_state = curr_bracket_state->parent;
        }
        is_else_state = false;
      } else if (!in_if_0_else_block) {
        open_block_brackets = restore_previous_bracket_state(&curr_bracket_state,
                                                             &open_block_brackets,
                                                             &open_assignment_brackets,
                                                             &prev_bracket_assign,
                                                             &last_label);
      }
      in_if_0_else_block = false;
      if (check_is_preprocessor_directive(line, "else") ||
          check_is_preprocessor_directive(line, "elsif")) {
        open_block_brackets = visit_next_bracket_state(line, &curr_bracket_state,
                                                       last_label,
                                                       &open_block_brackets,
                                                       &open_assignment_brackets,
                                                       &prev_bracket_assign);
        is_else_state = check_is_preprocessor_directive(line, "else");
      }
      if (old_open_block_brackets != open_block_brackets ||
          old_open_assignment_brackets != open_assignment_brackets) {
        int test = 1;
      }
      utils_free_if_different(line, line_buf);
      continue;
    }
    is_cond_directive = false;
    
    get_open_brackets(line, &open_block_brackets);

    size_t last = strlen(line) - 1;
    bool curr_bracket_assign = false;
    if (open_assignment_brackets == 0) {
      ssize_t eq_index = token_get_eq_index(line);
      ssize_t start_idx = -1;
      if (eq_index >= 0) {
        size_t search_idx = eq_index + 1;
        while (search_idx < strlen(line) && isspace(line[search_idx])) {
          search_idx++;
        }
        if (search_idx < strlen(line) && line[search_idx] == '{') {
          start_idx = search_idx;
        }
      } else if (check_is_struct(line)) {
        size_t* struct_keywords;
        size_t num_struct_keywords = utils_get_str_occurences(line, "struct",
                                                              &struct_keywords);
        for (size_t i = 0; i < num_struct_keywords; i++) {
          if (check_is_token_match(line, struct_keywords[i], strlen("struct"))) {
            size_t curr_idx = struct_keywords[i] + strlen("struct");
            while (curr_idx < strlen(line) &&
                   (isspace(line[curr_idx]) ||
                    check_is_valid_varname_char(line[curr_idx]))) {
              curr_idx++;
            }
            if (curr_idx < strlen(line) && line[curr_idx] == '{') {
              start_idx = curr_idx;
              break;
            }
          }
        }
        free(struct_keywords);
      }
      if (start_idx > 0) {
        size_t check_idx = check_recur_with_parenthesis(line, start_idx + 1, '{');
        if (check_idx >= strlen(line)) {
          size_t num_open_brackets =
            utils_get_char_occurences(line + start_idx, '{', NULL);
          size_t num_close_brackets =
            utils_get_char_occurences(line + start_idx, '}', NULL);
          open_assignment_brackets = num_open_brackets;
          assert(open_assignment_brackets >= num_close_brackets &&
                 "get_full_expr: mismatched assignment brackets");
          open_assignment_brackets -= num_close_brackets;
          curr_bracket_assign = true;
        }
      }
    } else {
      size_t num_open_brackets = utils_get_char_occurences(line, '{', NULL);
      size_t num_close_brackets = utils_get_char_occurences(line, '}', NULL);
      open_assignment_brackets += num_open_brackets;
      //assert(open_assignment_brackets >= num_close_brackets &&
      //       "get_full_expr: mismatched assignment brackets");
      if (num_close_brackets >= open_assignment_brackets) {
        open_assignment_brackets = 0;
      } else {
        open_assignment_brackets -= num_close_brackets;
      }
    }
    
    //if (line[0] == '#' && !check_has_mismatched_parenthesis(line)) {
    //  expr[0] = '\0';
    //  curr_idx = 0;
    if (line[0] == '.' && line[last] == ',' &&
        open_assignment_brackets > 0 && curr_line <= line_number)  {
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
    if (!is_in_macro && prev_define && !curr_define) {
      int test = 1;
    }

    if (check_is_define(expr)) {
      free(macro_name);
      macro_name = token_find_func_name(expr);
      is_in_macro = true;
      macro_return_start = curr_line;
    }

    if ((line[last] == ';' && open_assignment_brackets == 0 &&
         !check_has_mismatched_parenthesis(expr)) ||
        line[last] == '}' ||
        (line[last] == ':' && strchr(expr, '?') == NULL && !check_is_asm_block(expr)) ||
        (line[last] == '{' && open_assignment_brackets == 0) ||
        (expr[0] == '.' && expr[last] == ',' && open_assignment_brackets == 0 &&
         !check_has_mismatched_parenthesis(expr)) ||
        (is_in_macro && prev_define && !curr_define) ||
        (expr[0] == '#' && !check_has_mismatched_parenthesis(expr)) ||
        (check_is_control_flow_expr(expr) &&
         !check_has_mismatched_parenthesis(expr)) ||
        (open_block_brackets == 0 && !curr_define && check_is_func(expr) &&
         !check_has_mismatched_parenthesis(expr))) {
      if (curr_line >= line_number) {
        if (is_in_macro && !curr_define && macro_name != NULL) {
          token_insert_macro_return_entry(macro_name, source_file,
                                          macro_return_start, curr_line, true);
        } else {
          free(macro_name);
        }
        utils_free_if_different(line, line_buf);
        break;
      } else {
        if (is_in_macro) {
          macro_return_start = curr_line + 1;
          //if (check_is_define(expr)) {
          //  macro_name = token_find_func_name(expr);
          //}
          if (!curr_define) {
            is_in_macro = false;
          //  free(macro_name);
          //  macro_name = NULL;
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
  //list_free(bracket_state_stack);
  free_bracket_state_tree(bracket_state_root);
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
    fprintf(stderr, "file_get_func_from_src: not a C souce file: %s\n", source_file);
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
  bool in_if_0_else_block = false;
  size_t nested_asm_levels = 0;
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
                          &nested_if_0_levels, &in_if_0_else_block,
                          &nested_asm_levels, &has_open_str);
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
  if (strcmp(source_file, "include/uapi/linux/tipc_config.h") == 0) {
    int test = 1;
  }
  if (!is_c_source_file(source_file)) {
    fprintf(stderr, "file_get_func_end_line: not a C souce file: %s\n", source_file);
    return -1;
  }
  
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return -1;
  }

  size_t open_brackets = 0;
  struct bracket_state* bracket_state_root = create_bracket_state_root();
  struct bracket_state* curr_bracket_state = bracket_state_root;
  bool is_else_state = true;
  bool bracket_found = false;
  bool is_macro = false;
  bool has_open_comment = false;
  size_t nested_if_0_levels = 0;
  bool in_if_0_else_block = false;
  size_t nested_asm_levels = 0;
  bool has_open_str = false;
  size_t curr_line = 0;
  char* line_buf = NULL;
  size_t buf_size = 0;
  char* line;
  do {
    if (curr_line == 257) {
      int test = 1;
    }
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &in_if_0_else_block,
                          &nested_asm_levels, &has_open_str);
    if (line == NULL) {
      free_bracket_state_tree(bracket_state_root);
      utils_free_if_different(line, line_buf);
      free(line_buf);
      fclose(f);
      return -1;
    }
    if (strlen(line) == 0) {
      utils_free_if_different(line, line_buf);
      continue;
    }

    size_t tmp_s = 0;
    bool tmp_b = false;
    if (check_is_preprocessor_directive(line, "if") ||
        check_is_preprocessor_directive(line, "ifdef") ||
        check_is_preprocessor_directive(line, "ifndef")) {
      save_current_bracket_state(curr_bracket_state, open_brackets, tmp_s, tmp_b);
      open_brackets = visit_next_bracket_state(line, &curr_bracket_state, NULL,
                                               &open_brackets, &tmp_s, &tmp_b);
      utils_free_if_different(line, line_buf);
      continue;
    } else if (check_is_preprocessor_directive(line, "else") ||
               check_is_preprocessor_directive(line, "elsif") ||
               check_is_preprocessor_directive(line, "endif")) {
      char* last_label;
      if (is_else_state) {
        if (curr_bracket_state->parent != NULL) {
          merge_bracket_states(curr_bracket_state->parent, curr_bracket_state,
                               open_brackets, 0);
          curr_bracket_state = curr_bracket_state->parent;
        }
        is_else_state = false;
      } else if (!in_if_0_else_block) {
        open_brackets = restore_previous_bracket_state(&curr_bracket_state,
                                                       &open_brackets, &tmp_s,
                                                       &tmp_b, &last_label);
      }
      in_if_0_else_block = false;
      if (check_is_preprocessor_directive(line, "else") ||
          check_is_preprocessor_directive(line, "elsif")) {
        open_brackets = visit_next_bracket_state(line, &curr_bracket_state,
                                                 last_label, &open_brackets,
                                                 &tmp_s, &tmp_b);
        is_else_state = check_is_preprocessor_directive(line, "else");
      }
      utils_free_if_different(line, line_buf);
      continue;
    }

    if (curr_line == func_start_line && check_is_define(line)) {
      is_macro = true;
    }
    if (curr_line >= func_start_line) {
      bracket_found = get_open_brackets(line, &open_brackets) || bracket_found;
      if (!bracket_found && !is_macro && line[strlen(line) - 1] == ';') {
        free_bracket_state_tree(bracket_state_root);
        utils_free_if_different(line, line_buf);
        free(line_buf);
        fclose(f);
        return -1;
      }
      if ((open_brackets == 0 && bracket_found && !is_macro) ||
          (is_macro && line[strlen(line) - 1] != '\\')) {
        free_bracket_state_tree(bracket_state_root);
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
                            bool* in_if_0_else_block, size_t* nested_asm_levels,
                            bool* has_open_str) {
  ssize_t bytes_read = getline(line_buf, buf_size, f);
  if (bytes_read < 0) {
    return NULL;
  }
  (*line_buf)[bytes_read] = '\0';

  return remove_comments(*line_buf, bytes_read, has_open_comment,
                         nested_if_0_levels, in_if_0_else_block, nested_asm_levels,
                         has_open_str);
}

static char* remove_comments(char* line_buf, size_t bytes_read,
                             bool* has_open_comment, size_t* nested_if_0_levels,
                             bool* in_if_0_else_block, size_t* nested_asm_levels,
                             bool* has_open_str) {

  char* line = sanitize_remove_comments_and_strip(line_buf, has_open_comment,
                                                  has_open_str);
  if (*nested_if_0_levels == 0 &&
      (check_is_preprocessor_macro(line, "if", "0") ||
       check_is_preprocessor_macro(line, "elif", "0"))) {
    *has_open_comment = false;
    *has_open_str = false;
    *nested_if_0_levels = 1;
    line[0] = '\0';
  } else if (*nested_if_0_levels > 0) {
    *has_open_comment = false;
    *has_open_str = false;
    if (check_is_preprocessor_directive(line, "if") ||
        check_is_preprocessor_directive(line, "ifdef") ||
        check_is_preprocessor_directive(line, "ifndef")) {
      (*nested_if_0_levels)++;
    }
    if (check_is_preprocessor_directive(line, "endif") ||
        (*nested_if_0_levels == 1 &&
         (check_is_preprocessor_directive(line, "else") ||
          (check_is_preprocessor_directive(line, "elif") &&
           !check_is_preprocessor_macro(line, "elif", "0"))))) {
      assert(*nested_if_0_levels > 0 &&
             "remove_comments: inconsistent nested #if 0 level");
      *in_if_0_else_block = check_is_preprocessor_directive(line, "else");
      (*nested_if_0_levels)--;
    }
    line[0] = '\0';
  }

  if (*nested_asm_levels == 0 &&
      (check_is_preprocessor_macro(line, "ifndef", "__ASSEMBLY__") ||
       check_is_preprocessor_macro(line, "ifdef", "__ASSEMBLY__"))) {
    *has_open_comment = false;
    *has_open_str = false;
    *nested_asm_levels = 1;
    line[0] = '\0';
  } else if (*nested_asm_levels > 0) {
    *has_open_comment = false;
    *has_open_str = false;
    if (check_is_preprocessor_directive(line, "if") ||
        check_is_preprocessor_directive(line, "ifdef") ||
        check_is_preprocessor_directive(line, "ifndef")) {
      (*nested_asm_levels)++;
    } else if (check_is_preprocessor_directive(line, "endif")) {
      assert(*nested_asm_levels > 0 &&
             "remove_comments: inconsistent nested #ifdef __ASSEMBLY__ levels");
      (*nested_asm_levels)--;
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

static struct bracket_state* create_bracket_state_node(struct bracket_state* parent,
                                                       char* label,
                                                       size_t open_block_brackets,
                                                       size_t open_assignment_brackets,
                                                       bool prev_bracket_assign) {
  struct bracket_state* state =
    (struct bracket_state*) malloc(sizeof(struct bracket_state));
  state->label = label;
  state->parent = parent;
  state->open_block_brackets_in = open_block_brackets;
  state->open_assignment_brackets_in = open_assignment_brackets;
  state->prev_bracket_assign = prev_bracket_assign;
  state->open_block_brackets_diff = 0;
  state->open_assignment_brackets_diff = 0;
  state->children = map_create();
  return state;
}

static struct bracket_state* create_bracket_state_root() {
  char* empty_label = (char*) calloc(1, 1);
  return create_bracket_state_node(NULL, empty_label, 0, 0, false);
}

static void save_current_bracket_state(struct bracket_state* curr_state,
                                       size_t open_block_brackets,
                                       size_t open_assignment_brackets,
                                       bool prev_bracket_assign) {
  if (curr_state->parent == NULL) {
    curr_state->open_block_brackets_diff = open_block_brackets;
    curr_state->open_assignment_brackets_diff = open_assignment_brackets;
    curr_state->prev_bracket_assign = prev_bracket_assign;
  } else {
    //struct bracket_state* prev_state = curr_state->parent;
    curr_state->open_block_brackets_diff =
      open_block_brackets - curr_state->open_block_brackets_in;
    curr_state->open_assignment_brackets_diff =
      open_assignment_brackets - curr_state->open_assignment_brackets_in;
  }
  curr_state->prev_bracket_assign = prev_bracket_assign;
  //curr_state->open_block_brackets_in = open_block_brackets;
  //curr_state->open_assignment_brackets_in = open_assignment_brackets;
}

static size_t visit_next_bracket_state(char* line,
                                       struct bracket_state** curr_state,
                                       char* last_label,
                                       size_t* open_block_brackets,
                                       size_t* open_assignment_brackets,
                                       bool* prev_bracket_assign) {
  char* label;
  if (check_is_preprocessor_directive(line, "else")) {
    label = (char*) malloc(strlen(last_label) + 2);
    sprintf(label, "#%s", last_label);
  } else {
    char* macro = token_get_preprocessor_macro(line);
    if (check_is_preprocessor_directive(line, "elsif")) {
      label = (char*) malloc(strlen(last_label) + strlen(macro) + 2);
      sprintf(label, "%s#%s", macro, last_label);
      free(macro);
    } else {
      label = macro;
    }
  }
  
  if (map_contains((*curr_state)->children, label)) {
    *curr_state = (struct bracket_state*) map_get((*curr_state)->children, label);
    (*curr_state)->open_block_brackets_in = *open_block_brackets;
    (*curr_state)->open_assignment_brackets_in = *open_assignment_brackets;
  } else {
    struct bracket_state* next_state =
      create_bracket_state_node(*curr_state, label, *open_block_brackets,
                                *open_assignment_brackets, *prev_bracket_assign);
    map_insert((*curr_state)->children, label, next_state);
    *curr_state = next_state;
  }

  *open_block_brackets += (*curr_state)->open_block_brackets_diff;
  *open_assignment_brackets += (*curr_state)->open_assignment_brackets_diff;
  *prev_bracket_assign = (*curr_state)->prev_bracket_assign;

  return *open_block_brackets;
}

static size_t restore_previous_bracket_state(struct bracket_state** curr_state,
                                             size_t* open_block_brackets,
                                             size_t* open_assignment_brackets,
                                             bool* prev_bracket_assign,
                                             char** last_label) {
  *last_label = (*curr_state)->label;
  struct bracket_state* prev_state = (*curr_state)->parent;
  if (prev_state == NULL) {
    return *open_block_brackets;
  }
  
  (*curr_state)->open_block_brackets_diff =
    *open_block_brackets - (*curr_state)->open_block_brackets_in;
  (*curr_state)->open_assignment_brackets_diff =
    *open_assignment_brackets - (*curr_state)->open_assignment_brackets_in;
  (*curr_state)->open_block_brackets_in = *open_block_brackets;
  (*curr_state)->open_assignment_brackets_in = *open_assignment_brackets;
  (*curr_state)->prev_bracket_assign = prev_bracket_assign;

  assert((ssize_t) *open_block_brackets >= (*curr_state)->open_block_brackets_diff &&
         (ssize_t) *open_assignment_brackets >= (*curr_state)->open_assignment_brackets_diff &&
         "restored_previous_bracket_state: difference is greater than the actual value");
  *open_block_brackets -= (*curr_state)->open_block_brackets_diff;
  *open_assignment_brackets -= (*curr_state)->open_assignment_brackets_diff;
  *prev_bracket_assign = prev_state->prev_bracket_assign;
  
  *curr_state = prev_state;
  return *open_block_brackets;
}

static void merge_bracket_states(struct bracket_state* parent_state,
                                 struct bracket_state* else_state,
                                 size_t open_block_brackets,
                                 size_t open_assignment_brackets) {
  else_state->open_block_brackets_diff =
    open_block_brackets - else_state->open_block_brackets_in;
  else_state->open_assignment_brackets_diff =
    open_assignment_brackets - else_state->open_assignment_brackets_in;
  parent_state->open_block_brackets_diff += else_state->open_block_brackets_diff;
  parent_state->open_assignment_brackets_diff += else_state->open_assignment_brackets_diff;
  parent_state->prev_bracket_assign = else_state->prev_bracket_assign;
  else_state->open_block_brackets_in = open_block_brackets;
  else_state->open_assignment_brackets_in = open_assignment_brackets;
}

static void free_bracket_state_tree(struct bracket_state* curr_state) {
  struct list* children_list = map_get_key_list(curr_state->children);
  for (struct list_node* curr = children_list->head; curr != NULL; curr = curr->next) {
    char* child_label = (char*) curr->payload;
    struct bracket_state* child_state =
      (struct bracket_state*) map_get(curr_state->children, child_label);
    free_bracket_state_tree(child_state);
  }
  list_free_nodes(children_list);
  free(curr_state->label);
  free(curr_state);
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
    fprintf(stderr, "file_find_struct_name: not a C souce file: %s\n", source_file);
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
  bool in_if_0_else_block = false;
  size_t nested_asm_levels = 0;
  bool has_open_comment = false;
  bool has_open_str = false;
  size_t buf_size = 0;
  do {
    curr_line++;
    char* line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                                &nested_if_0_levels, &in_if_0_else_block,
                                &nested_asm_levels, &has_open_str);
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

char* file_get_line(const char* source_file, size_t line_number) {
  FILE* f = fopen(source_file, "r");
  assert(f != NULL && "file_get_line: failed to open file");

  size_t curr_line = 0;
  char* line_buf = NULL;
  char* line = NULL;
  size_t nested_if_0_levels = 0;
  bool in_if_0_else_block = false;
  size_t nested_asm_levels = 0;
  bool has_open_comment = false;
  bool has_open_str = false;
  size_t buf_size = 0;
  do {
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &in_if_0_else_block,
                          &nested_asm_levels, &has_open_str);
    assert(line != NULL && "file_get_line: line cannot be NULL");
  } while(curr_line < line_number);

  utils_free_if_different(line_buf, line);
  fclose(f);
  return line;
}

char* file_get_sysctl_table_entry(const char* source_file, size_t line_number,
                                  char** table_name, size_t* entry_index) {
  FILE* f = fopen(source_file, "r");
  assert(f != NULL && "file_get_sysctl_table_entry: failed to open file");

  size_t curr_line = 0;
  char* line_buf = NULL;
  char* line = NULL;
  size_t nested_if_0_levels = 0;
  bool in_if_0_else_block = false;
  size_t nested_asm_levels = 0;
  bool has_open_comment = false;
  bool has_open_str = false;
  size_t open_brackets = 0;
  bool in_table = false;
  bool in_entry = false;
  size_t buf_size = 0;
  char* curr_table_entry = (char*) malloc(4096);
  size_t curr_char = 0;
  *table_name = NULL;
  do {
    curr_line++;
    if (curr_line == 432) {
      int tes = 1;
    }
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &in_if_0_else_block,
                          &nested_asm_levels, &has_open_str);
    assert(line != NULL && "file_get_line: line cannot be NULL");
    if (strlen(line) == 0 || line[0] == '#') {
      utils_free_if_different(line, line_buf);
      continue;
    }

    size_t curr_line_index = 0;
    if (*table_name == NULL) {
      size_t assignment_start;
      *table_name = token_get_sysctl_table_name(line, &assignment_start);
      if (*table_name != NULL) {
        curr_line_index = assignment_start + 1;
        curr_table_entry[0] = '\0';
        *entry_index = 0;
        curr_char = 0;
      }
    }

    if (*table_name != NULL) {
      if (open_brackets < 2) {
        for (size_t i = curr_line_index; i < strlen(line); i++) {
          if (line[i] == '{') {
            if (open_brackets == 1) {
              size_t entry_start = i + 1;
              size_t entry_end = check_recur_with_parenthesis(line, entry_start , '{');
              if (entry_end >= strlen(line)) {
                in_entry = true;
                entry_end = strlen(line);
                size_t num_to_copy = entry_end - entry_start;
                strncpy(curr_table_entry, line + entry_start, num_to_copy);
                curr_table_entry[num_to_copy] = '\0';
                curr_char = num_to_copy;
                open_brackets++;
              } else {
                (*entry_index)++;
                curr_line_index = entry_end + 1;
              }
              i = entry_end;
            } else {
              in_table = true;
              open_brackets++;
              curr_line_index = i + 1;
            }
          } else if (line[i] == '}') {
            open_brackets--;
            break;
          }
        }
      } else {
        char* close_bracket_ptr = strchr(line, '}');
        size_t num_to_copy;
        if (close_bracket_ptr == NULL) {
          num_to_copy = strlen(line);
        } else {
          num_to_copy = close_bracket_ptr - line;
          open_brackets--;
        }
        if (num_to_copy > 0) {
          curr_table_entry[curr_char] = ' ';
          curr_char++;
          strncpy(curr_table_entry + curr_char, line, num_to_copy);
          curr_char += num_to_copy;
          curr_table_entry[curr_char] = '\0';
        }
      }

      if (open_brackets < 2 && in_table) {
        if (curr_line >= line_number) {
          fclose(f);
          utils_free_if_different(line, line_buf);
          free(line_buf);
          return curr_table_entry;
        } else {
          curr_table_entry[0] = '\0';
          curr_char = 0;
          if (open_brackets == 0) {
            *entry_index = 0;
            free(*table_name);
            *table_name = NULL;
            in_table = false;
          } else if (in_entry) {
            (*entry_index)++;
            in_entry = false;
          }
        }
      }
      
    }
    utils_free_if_different(line, line_buf);
  } while (line != NULL);

  assert(false && "file_get_sysctl_table_entry: reached unreachable point");
  return NULL;
}

struct list* file_get_enum_list(const char* enum_name) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L1 %s", enum_name);
  struct list* results = utils_get_cscope_output(cmd);
  char* result = (char*) results->head->payload;
  list_free_nodes(results);

  char** result_arr;
  utils_split_str(result, &result_arr);
  char* source_file = result_arr[0];
  size_t line_number = atoi(result_arr[2]);

  FILE* f = fopen(source_file, "r");
  assert(f != NULL && "file_get_enum_list: failed to open file");

  size_t curr_line = 0;
  char* line_buf = NULL;
  char* line = NULL;
  size_t nested_if_0_levels = 0;
  bool in_if_0_else_block;
  size_t nested_asm_levels = 0;
  bool has_open_comment = false;
  bool has_open_str = false;
  size_t buf_size = 0;
  bool in_enum = false;
  bool enum_found = false;
  struct list* enum_list = list_create();
  do {
    curr_line++;
    if (curr_line == 553) {
      int tes = 1;
    }
    line = get_clean_line(&line_buf, f, &buf_size, &has_open_comment,
                          &nested_if_0_levels, &in_if_0_else_block,
                          &nested_asm_levels, &has_open_str);
    assert(line != NULL && "file_get_enum_list: line cannot be NULL");
    if (strlen(line) == 0 || line[0] == '#') {
      utils_free_if_different(line, line_buf);
      continue;
    }
    
    if (check_is_enum_declaration(line)) {
      in_enum = true;
      enum_found = true;
    } else if (in_enum) {
      if (strchr(line, '}') != NULL) {
        in_enum = false;
      } else {
        char* comma_ptr = strchr(line, ',');
        if (comma_ptr != NULL) {
          *comma_ptr = '\0';
        }
        char* enum_name = (char*) malloc(strlen(line) + 1);
        strncpy(enum_name, line, strlen(line) + 1);
        list_append(enum_list, enum_name);
      }
    }

    if (!in_enum) {
      if (curr_line >= line_number) {
        fclose(f);
        utils_free_if_different(line, line_buf);
        free(line_buf);
        return enum_list;
      } else if (enum_found) {
        list_free(enum_list);
        enum_list = list_create();
      }
    }
    
  } while (line != NULL);

  assert(false && "file_get_enum_list: reached unreachable point");
  return NULL;
}
