#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "sanitize_expression.h"
#include "token_get.h"
#include "check_expression.h"
#include "file_search.h"

#define EXPR_SIZE 65536

static char* get_full_expr(const char* source_file, size_t line_number);

static char* get_clean_line(char** line_buf, FILE* f, size_t* buf_size,
                            size_t* open_comments);

static size_t remove_comments(char* line_buf, size_t bytes_read,
                              size_t open_comments, char** line);

static bool is_curr_define(char** line);

static bool get_open_brackets(char* line, size_t* open_brackets);

char* file_get_multiline_expr(const char* var_ref, const char** var_ref_arr) {
  char* san_var_ref = sanitize_remove_string_literals(var_ref);
  char* trimmed_var_ref = utils_trim_str(san_var_ref);
  utils_free_if_both_different(san_var_ref, var_ref, trimmed_var_ref);
  san_var_ref = trimmed_var_ref;
  
  size_t last = strlen(san_var_ref) - 1;
  char* multiline_var_ref = NULL;
  if (san_var_ref[last] == '\\') {
    utils_truncate_str(san_var_ref, -1);
    trimmed_var_ref = utils_trim_str(san_var_ref);
    utils_free_if_both_different(san_var_ref, var_ref, trimmed_var_ref);
    san_var_ref = trimmed_var_ref;
  }

  if (check_has_open_string(san_var_ref) ||
      (san_var_ref[last] != ';' && san_var_ref[last] != '{' &&
       var_ref_arr[3][0] != '.' && strstr(san_var_ref, "#define") == NULL)) {
    if (check_has_mismatched_parenthesis(san_var_ref) ||
        (!check_is_control_flow_expr(san_var_ref) && !check_is_func(san_var_ref))) {
      multiline_var_ref = get_full_expr(var_ref_arr[0], atoi(var_ref_arr[2]));
    }
  } else if (strstr(san_var_ref, "#define") == NULL &&
             (!check_is_expression(san_var_ref, var_ref_arr) ||
              check_has_mismatched_parenthesis(san_var_ref))) {
    multiline_var_ref = get_full_expr(var_ref_arr[0], atoi(var_ref_arr[2]));
  }

  if (check_is_func(san_var_ref) && !check_is_control_flow_expr(san_var_ref) &&
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
    utils_free_if_different(multiline_var_ref, final_var_ref);
  } else {
    final_var_ref = sanitize_clean_var_ref(san_var_ref);
    utils_free_if_both_different(san_var_ref, var_ref, final_var_ref);
  }
  return final_var_ref;
}

static char* get_full_expr(const char* source_file, size_t line_number) {
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return NULL;
  }

  size_t curr_line = 0;
  char* expr = (char*) malloc(EXPR_SIZE);
  size_t curr_expr_size = EXPR_SIZE;
  expr[0] = '\0';
  size_t curr_idx = 0;
  size_t open_comments = 0;
  bool prev_define = false;
  char* line_buf = NULL;
  size_t buf_size = 0;
  char* line;
  do {
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &open_comments);
    if (line == NULL) {
      utils_free_if_different(line, line_buf);
      free(line_buf);
      free(expr);
      fclose(f);
      return NULL;
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

    if (line[0] == '#' && check_has_mismatched_parenthesis(line)) {
      int test = 1;
    }

    if (line[0] == '#' && !check_has_mismatched_parenthesis(line)) {
      expr[0] = '\0';
      curr_idx = 0;
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

    size_t last = strlen(line) - 1;
    if (utils_char_in_array(";{}", line[last], 3) ||
        (prev_define && line[last] == ')')) {
      if (curr_line >= line_number) {
        utils_free_if_different(line, line_buf);
        break;
      } else {
        expr[0] = '\0';
        curr_idx = 0;
      }
    } else if ((line[last] == '/' && line[last-1] == '*') ||
               (check_is_control_flow_expr(expr) &&
                !check_has_mismatched_parenthesis(expr))) {
      expr[0] = '\0';
      curr_idx = 0;
    }

    prev_define = curr_define;
    utils_free_if_different(line, line_buf);
  } while (line != NULL);

  //printf("Full expression: %s\n", expr);
  free(line_buf);
  fclose(f);
  
  char* final_expr = (char*) malloc(strlen(expr) + 1);
  strncpy(final_expr, expr, strlen(expr));
  final_expr[strlen(expr)] = '\0';
  free(expr);
  return final_expr;
}

ssize_t file_get_func_from_src(const char* source_file, const char* func_name,
                               ssize_t* func_start_line) {
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return -1;
  }

  *func_start_line = -1;
  size_t open_brackets = 0;
  size_t open_comments = 0;
  bool bracket_found = false;
  bool is_macro = false;
  bool prev_define = false;
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
    line = get_clean_line(&line_buf, f, &buf_size, &open_comments);
    if (line == NULL) {
      utils_free_if_different(line, line_buf);
      free(line_buf);
      free(expr);
      fclose(f);
      return -1;
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
      if (strstr(expr, "define") != NULL) {
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

  fclose(f);
  free(line_buf);
  free(expr);
  return -1;
}

ssize_t file_get_func_end_line(const char* source_file, size_t func_start_line) {
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return -1;
  }

  size_t open_brackets = 0;
  size_t open_comments = 0;
  bool bracket_found = false;
  bool is_macro = false;
  size_t curr_line = 0;
  char* line_buf = NULL;
  size_t buf_size = 0;
  char* line;
  do {
    curr_line++;
    line = get_clean_line(&line_buf, f, &buf_size, &open_comments);
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

    if (curr_line == func_start_line && strstr(line, "#define") != NULL) {
      is_macro = true;
    }
    if (curr_line >= func_start_line) {
      bracket_found = get_open_brackets(line, &open_brackets) || bracket_found;
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

  fclose(f);
  free(line_buf);
  return -1;
}

static char* get_clean_line(char** line_buf, FILE* f, size_t* buf_size,
                            size_t* open_comments) {
  ssize_t bytes_read = getline(line_buf, buf_size, f);
  if (bytes_read < 0) {
    return NULL;
  }
  (*line_buf)[bytes_read] = '\0';

  char* line;
  *open_comments = remove_comments(*line_buf, bytes_read, *open_comments, &line);
  return line;
}

static size_t remove_comments(char* line_buf, size_t bytes_read,
                              size_t open_comments, char** line) {
  if (strstr(line_buf, "/*") != NULL) {
    open_comments++;
  }
  if (strstr(line_buf, "*/") != NULL) {
    open_comments--;
  }
  if (open_comments > 0) {
    line_buf[0] = '\0';
    *line = line_buf;
    return open_comments;
  }
  
  *line = sanitize_remove_comments_and_strip(line_buf);
  return 0;
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
  if (strchr(line, '{') != NULL) {
    (*open_brackets)++;
    bracket_found = true;
  }
  if (strchr(line, '}') != NULL) {
    (*open_brackets)--;
  }

  return bracket_found;
}

char* file_find_struct_name(const char* source_file, size_t line_number) {
  FILE* f = fopen(source_file, "r");
  if (f == NULL) {
    return NULL;
  }

  char* var_name = NULL;
  size_t curr_line = 0;
  char* line_buf = NULL;
  size_t buf_size = 0;
  size_t open_comments = 0;
  do {
    curr_line++;
    char* line = get_clean_line(&line_buf, f, &buf_size, &open_comments);
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
    } else if (strstr(line, "#define") != NULL) {
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
