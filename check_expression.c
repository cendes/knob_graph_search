#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include "c_keywords.h"
#include "list.h"
#include "utils.h"
#include "sanitize_expression.h"
#include "token_get.h"
#include "check_expression.h"

hash_map check_out_of_scope = NULL;

static bool check_mismatched_parenthesis(const char* var_ref, size_t* curr_index, bool has_recurred);

static bool is_type_name(const char* var_ref, size_t var_start_index, size_t var_end_index, const char* func_name, bool is_global);

static bool is_global_var_redeclaration(const char* var_name, const char* var_ref, size_t var_start_index, const char* next_token, const char* func_name);

static bool is_func_arg_name(const char* var_name, const char* var_ref, size_t var_start_index, const char* func_name);

static bool has_asm_token(const char* var_ref, const char* asm_token);

static bool has_token_match(const char* var_ref, const char* token);

bool check_is_expression_with_effect(const char* var_ref, const char** var_ref_arr) {
  size_t var_ref_end = strlen(var_ref) - 1;
  return (token_get_eq_index(var_ref) >= 0 || has_token_match(var_ref, "return") ||
          (has_token_match(var_ref, "case") && var_ref[var_ref_end] == ':')) &&
    (var_ref[var_ref_end] == ';' || var_ref[var_ref_end] == '}' ||
     (var_ref_arr[3][0] == '.' && var_ref[var_ref_end] == ',')) &&
    (check_is_valid_varname_char(var_ref_arr[3][0]) || var_ref_arr[3][0] == '*' ||
     var_ref_arr[3][0] == '.');
}

bool check_is_control_flow_expr(const char* var_ref) {
  for (size_t i = 0; i < UTILS_SIZEOF_ARR(C_KEYWORDS) - 3; i++) {
    bool keyword_match = has_token_match(var_ref, C_KEYWORDS[i]);
    if (keyword_match) {
      return true;
    }
  }

  return false;
}

bool check_is_func(const char* var_ref) {
  if (strcmp(var_ref, "pr_debug(\"\",dir, sctp_conntrack_names[cur_state], chunk_type,sctp_conntrack_names[sctp_conntracks[dir][i][cur_state]]);") == 0) {
    int test = 1;
  }
  size_t* open_bracket_indices;
  size_t num_open_brackets = utils_get_char_occurences(var_ref, '[', &open_bracket_indices);
  struct list* bracket_indices = list_create();
  for (size_t i = 0; i < num_open_brackets; i++) {
    size_t bracket_end = check_recur_with_parenthesis(var_ref, open_bracket_indices[i] + 1, '[');
    if (bracket_end >= strlen(var_ref)) {
      bracket_end = strlen(var_ref) - 1;
    }
    struct index_range* bracket_range = (struct index_range*) malloc(sizeof(struct index_range));
    *bracket_range = {open_bracket_indices[i], bracket_end + 1};
    list_append(bracket_indices, bracket_range);
  }
  free(open_bracket_indices);

  char* san_var_ref = sanitize_remove_substring(var_ref, bracket_indices);
  list_free(bracket_indices);

  size_t* args_start_indices;
  size_t num_parenthesis = utils_get_char_occurences(san_var_ref, '(', &args_start_indices);
  for (size_t i = 0; i < num_parenthesis; i++) {
    if (args_start_indices[i] > 0) {
      size_t func_name_end  = args_start_indices[i] - 1;
      while (func_name_end > 0 && isspace(san_var_ref[func_name_end])) {
        func_name_end--;
      }
      if (check_is_valid_varname_char(san_var_ref[func_name_end])) {
        size_t func_name_start = func_name_end;
        while (func_name_start > 0 && check_is_valid_varname_char(san_var_ref[func_name_start])) {
          func_name_start--;
        }
        if (!check_is_valid_varname_char(san_var_ref[func_name_start])) {
          func_name_start++;
        }
        if (!utils_substr_in_array(C_KEYWORDS, (san_var_ref + func_name_start), UTILS_SIZEOF_ARR(C_KEYWORDS),
                                   func_name_end - func_name_start + 1)) {
          free(args_start_indices);
          utils_free_if_different(san_var_ref, var_ref);
          return true;
        }
      }
    }
  }

  free(args_start_indices);
  utils_free_if_different(san_var_ref, var_ref);
  return false;
}

bool check_has_mismatched_parenthesis(const char* var_ref) {
  size_t idx = 0;
  return check_mismatched_parenthesis(var_ref, &idx, false);
}

static bool check_mismatched_parenthesis(const char* var_ref, size_t* curr_index, bool has_recurred) {
  while (*curr_index < strlen(var_ref)) {
    if (var_ref[*curr_index] == '(') {
      (*curr_index)++;
      while (*curr_index < strlen(var_ref) && var_ref[*curr_index] != ')') {
        if (var_ref[*curr_index] == '(') {
          bool mismatched_parenthesis = check_mismatched_parenthesis(var_ref, curr_index, true);
          if (mismatched_parenthesis) {
            return true;
          }
        }
        (*curr_index)++;
      }
      if (*curr_index == strlen(var_ref) || var_ref[*curr_index] != ')') {
        return true;
      } else if (has_recurred) {
        return false;
      }
      (*curr_index)++;
    } else if (var_ref[*curr_index] == ')') {
      return true;
    } else {
      (*curr_index)++;
    }
  }
  return false;
}

bool check_is_ref(const char* var_ref, const char* var_name, const char* func_name, bool is_global) {
  while (var_name[0] == '*') {
    var_name++;
  }
  size_t* start_indices;
  size_t num_start_indices = utils_get_str_occurences(var_ref, var_name, &start_indices);
  bool check_passed = false;
  for (size_t i = 0; i < num_start_indices; i++) {
    if (check_is_token_match(var_ref, start_indices[i], strlen(var_name))) {
      size_t var_end_index = start_indices[i] + strlen(var_name);
      check_passed = check_passed || !is_type_name(var_ref, start_indices[i], var_end_index, func_name, is_global);
    }
  }
  free(start_indices);
  return check_passed;
}

static bool is_type_name(const char* var_ref, size_t var_start_index, size_t var_end_index, const char* func_name, bool is_global) {
  if (var_end_index < strlen(var_ref)) {
    char* var_name = (char*) malloc(strlen(var_ref) + 1);
    strncpy(var_name, var_ref + var_start_index, strlen(var_ref) + 1);
    utils_truncate_str(var_name, var_end_index);
    if (var_ref[var_end_index] == ' ') {
      char* original_next_token = (char*) malloc(strlen(var_ref) + 1);
      strncpy(original_next_token, var_ref + var_end_index + 1, strlen(var_ref) + 1);
      char* next_token = utils_trim_str(original_next_token);
      if (check_is_valid_varname_char(next_token[0]) || next_token[0] == '*') { // #TODO: could be a multiplication
        free(var_name);
        utils_free_if_different(next_token, original_next_token);
        free(original_next_token);
        return true;
      } else if (is_global) {
        bool ret = is_global_var_redeclaration(var_name, var_ref, var_start_index, next_token, func_name);
        free(var_name);
        utils_free_if_different(next_token, original_next_token);
        free(original_next_token);
        return ret;
      }
      free(var_name);
      utils_free_if_different(next_token, original_next_token);
      free(original_next_token);
    } else if (is_global) {
      char* next_token = (char*) malloc(strlen(var_ref) + 1);
      strncpy(next_token, var_ref + var_end_index, strlen(var_ref) + 1);
      bool ret = is_global_var_redeclaration(var_name, var_ref, var_start_index, next_token, func_name);
      free(var_name);
      free(next_token);
      return ret;
    } else {
      free(var_name);
      return false;
    }
  }
  return false;
}

static bool is_global_var_redeclaration(const char* var_name, const char* var_ref, size_t var_start_index, const char* next_token, const char* func_name) {
  if (next_token[0] == ';' || check_is_assignment_op(next_token, 0)) {
    if (check_is_var_declaration(var_name, var_ref)) {
      if (!map_contains(check_out_of_scope, func_name)) {
        map_insert(check_out_of_scope, func_name, list_create());
      }
      char* out_of_scope_name = (char*) malloc(strlen(var_name) + 1);
      strncpy(out_of_scope_name, var_name, strlen(var_name) + 1);
      list_append((struct list*) map_get(check_out_of_scope, func_name), out_of_scope_name);
      return true;
    } else {
      return false;
    }
  } else if (next_token[0] == ',' || next_token[0] == ')') {
    return is_func_arg_name(var_name, var_ref, var_start_index, func_name);
  } else {
    return false; // TODO: check this
  }
}

static bool is_func_arg_name(const char* var_name, const char* var_ref, size_t var_start_index, const char* func_name) {
  for (size_t i  = var_start_index - 1; i > 0; i--) {
    if (var_ref[i] == ',' || var_ref[i] == '(' || var_ref[i] == '.' || var_ref[i] == '=') {
      return false;
    } else if (check_is_valid_varname_char(var_ref[i])) {
      if (!map_contains(check_out_of_scope, func_name)) {
        map_insert(check_out_of_scope, func_name, list_create());
      }
      char* out_of_scope_name = (char*) malloc(strlen(var_name) + 1);
      strncpy(out_of_scope_name, var_name, strlen(var_name) + 1);
      list_insert((struct list*) map_get(check_out_of_scope, func_name), out_of_scope_name);
      return true;
    }
  }
  return false;
}


bool check_is_var_declaration(const char* var_name, const char* var_ref) {
  if (strcmp(var_name, "entry") == 0) {
    int test = 1;
  }
  size_t i = 0;
  size_t consecutive_tokens = 0;
  bool has_declaration = false;
  bool is_define_arg = false;
  bool is_after_parenthesis = false;
  bool is_after_comma = false;
  bool is_after_equals = false;
  bool is_control_decl = false;
  bool is_struct_declaration = false;
  while (i < strlen(var_ref)) {
    size_t token_start = i;
    bool has_space = false;
    while (token_start < strlen(var_ref) &&
           (isspace(var_ref[token_start]) ||
            utils_char_in_array(";,()[=*", var_ref[token_start], 7))) {
      if (utils_char_in_array(";,()[=", var_ref[token_start], 6)) {
        if (isspace(var_ref[token_start])) {
          has_space = true;
        } else if (var_ref[token_start] == ',') {
          is_after_comma = true;
        } else if (var_ref[token_start] == '(' && !has_space) {
          is_after_parenthesis = true;
        } else if (var_ref[token_start] == ')') {
          is_define_arg = false;
        } else if (var_ref[token_start] == '=') {
          is_after_equals = true;
        } else if (var_ref[token_start] == ';') {
          is_control_decl = false;
        }
        consecutive_tokens = 0;
      } else if (var_ref[token_start] == '*' &&
                  ((is_after_equals && !is_after_comma) ||
                   (is_after_parenthesis && !has_declaration && !is_control_decl))) {
        if (consecutive_tokens > 0) {
          int test = 1;
        }
        consecutive_tokens = 0;
      }
      if (var_ref[token_start] == '[') {
        token_start = check_recur_with_parenthesis(var_ref, token_start, '[');
      }
      token_start++;
    }
    if (token_start >= strlen(var_ref)) {
      return false;
    }
    
    size_t token_end = token_start;
    while (token_end < strlen(var_ref) && !isspace(var_ref[token_end]) &&
           !utils_char_in_array(";,()[=*", var_ref[token_end], 7)) {
      token_end++;
    }
    size_t token_len = token_end - token_start;
    char* token = (char*) malloc(token_len + 1);
    strncpy(token, var_ref + token_start, token_len);
    token[token_len] = '\0';
    if (strcmp(token, "{") == 0 && (is_after_equals || is_struct_declaration)) {
      token_end = check_recur_with_parenthesis(var_ref, token_end, '{');
      token_end++;
    }
    else if (strcmp(token, "return") == 0) {
      free(token);
      return false;
    } else if (strcmp(token, "struct") == 0 || strcmp(token, "union") == 0) {
      is_struct_declaration = true;
      size_t curr_idx = token_end;
      while (curr_idx < strlen(var_ref) && isspace(var_ref[curr_idx])) {
        curr_idx++;
      }
      
      if (curr_idx < strlen(var_ref) && var_ref[curr_idx] == '{') {
        token_end = check_recur_with_parenthesis(var_ref, curr_idx + 1, '{');
        token_end++;
        consecutive_tokens++;
      }
    } else if (strlen(token) > 0 && strcmp(token, "case") != 0 &&
               strcmp(token, "do") != 0 &&
               !utils_str_in_array(C_TYPE_MODIFIERS, token,
                                   UTILS_SIZEOF_ARR(C_TYPE_MODIFIERS)) &&
               ((token[0] == '#' && check_is_define(var_ref)) || check_is_valid_varname(token)) &&
               !utils_isnumeric(token)) {
      if (is_define_arg && !is_after_parenthesis && consecutive_tokens > 1) {
        consecutive_tokens = 0;
        is_define_arg = false;
      }
      
      if (token[0] == '#' && check_is_define(var_ref)) {
        if (strcmp(token, "#") == 0) {
          token_end++;
          while (isspace(var_ref[token_end])) {
            token_end++;
          }
          token_end += strlen("define");
        }
        is_define_arg = true;
      } else if (strcmp(token, "typeof") == 0) {
        while (token_end < strlen(var_ref) && isspace(var_ref[token_end])) {
          token_end++;
        }
        token_end = check_recur_with_parenthesis(var_ref, token_end + 1, '(');
        token_end++;
        if (token_end >= strlen(var_ref)) {
          free(token);
          return false;
        }
      } else if (utils_str_in_array(C_KEYWORDS, token, UTILS_SIZEOF_ARR(C_KEYWORDS) - 3)) {
        is_control_decl = true;
      } else if ((consecutive_tokens > 0 ||
                  (has_declaration && is_after_comma && !is_after_parenthesis) ||
                  (is_define_arg && (is_after_parenthesis || is_after_comma)))
                 && strcmp(token, var_name) == 0) {
        free(token);
        return true;
      }
      
      consecutive_tokens++;
      if (consecutive_tokens == 2) {
        has_declaration = true;
      }
    } else {
      consecutive_tokens = 0;
    }
    free(token);
    is_after_comma = false;
    i = token_end;
  }
  return false;
}

ssize_t check_recur_with_parenthesis(const char* var_ref, size_t curr_index, char parenthesis_type) {
  int increment;
  const char *open_parenthesis;
  char close_parenthesis;
  switch(parenthesis_type) {
    case '(':
      increment = 1;
      open_parenthesis = "([";
      close_parenthesis = ')';
      break;
    case ')':
      increment = -1;
      open_parenthesis = ")]";
      close_parenthesis = '(';
      break;
    case '[':
      increment = 1;
      open_parenthesis = "([";
      close_parenthesis = ']';
      break;
    case ']':
      increment = -1;
      open_parenthesis = ")]";
      close_parenthesis = '[';
      break;
    case '{':
      increment = 1;
      open_parenthesis = "{";
      close_parenthesis = '}';
      break;
    default:
      return -1;
  }

  while (curr_index < strlen(var_ref) && var_ref[curr_index] != close_parenthesis) {
    if (var_ref[curr_index] == open_parenthesis[0] || var_ref[curr_index] == open_parenthesis[1]) {
      curr_index = check_recur_with_parenthesis(var_ref, curr_index + increment, var_ref[curr_index]);
    }
    curr_index += increment;
  }

  return curr_index;
}

bool check_has_var_name(const char* var_ref, const char* var_name) {
  return has_token_match(var_ref, var_name);
}

bool check_has_unary_operand(const char* token) {
  return utils_char_in_array(C_UNARY_OPERANDS, token[0],
                            UTILS_SIZEOF_ARR(C_UNARY_OPERANDS) ||
                            (strlen(token) > 1 &&
                             (strncmp(token, "++", 2) == 0 ||
                              strncmp(token, "--", 2))));
}

bool check_is_valid_varname(const char* token) {
  for (size_t i = 0; i < strlen(token); i++) {
    if (!check_is_valid_varname_char(token[i])) {
      return false;
    }
  }
  return true;
}

bool check_is_valid_varname_char(char chr) {
  return isalnum(chr) || chr == '_';
}

bool check_is_asm_block(const char* var_ref) {
  return has_asm_token(var_ref, "asm") || has_asm_token(var_ref, "__asm__") ||
    has_asm_token(var_ref, "__asm");
    
  /* if (strstr(var_ref, "asm volatile (") != NULL || strstr(var_ref, "asm volatile(") != NULL || */
  /*     strstr(var_ref, "__asm__ __volatile__(") != NULL) { */
  /*   return true; */
  /* } */
  /* const char* asm_ptr = strstr(var_ref, "asm ("); */
  /* size_t asm_len; */
  /* if (asm_ptr == NULL) { */
  /*   asm_ptr = strstr(var_ref, "asm("); */
  /*   asm_len = strlen("asm("); */
  /* } else { */
  /*   asm_len = strlen("asm ("); */
  /* } */

  /* if (asm_ptr != NULL) { */
  /*   int test = 1; */
  /* } */

  /* return asm_ptr != NULL && check_is_token_match(var_ref, asm_ptr - var_ref, asm_len); */
}

static bool has_asm_token(const char* var_ref, const char* asm_token) {
  size_t* asm_occurences;
  size_t num_asms = utils_get_str_occurences(var_ref, asm_token, &asm_occurences);
  for (size_t i = 0; i < num_asms; i++) {
    if (check_is_token_match(var_ref, asm_occurences[i], strlen(asm_token))) {
      size_t curr_index = asm_occurences[i] + strlen(asm_token);
      while(curr_index < strlen(var_ref) && isspace(var_ref[curr_index])) {
        curr_index++;
      }
      const char* curr_ref_ptr = var_ref + curr_index;
      if (curr_index < strlen(var_ref) &&
          (var_ref[curr_index] == '(' ||
           strstr(curr_ref_ptr, "volatile") == curr_ref_ptr ||
           strstr(curr_ref_ptr, "__volatile__") == curr_ref_ptr)) {
        free(asm_occurences);
        return true;
      }
    }
  }

  free(asm_occurences);
  return false;
}

bool check_is_extern(const char* var_ref) {
  return has_token_match(var_ref, "extern");
}

bool check_has_arg_names(struct list* func_args_declaration) {
  for (struct list_node* curr = func_args_declaration->head; curr != NULL;
       curr = curr->next) {
    const char* arg = (const char*) curr->payload;
    if (check_is_func_ptr(arg)) {
      continue;
    }

    char** tokens;
    size_t num_tokens = utils_split_str(arg, &tokens);
    char* arg_name;
    if (utils_str_in_array(C_TYPE_MODIFIERS, tokens[0], UTILS_SIZEOF_ARR(C_TYPE_MODIFIERS))) { // TODO: handle signed and unsigned
      if (num_tokens >= 3) {
        arg_name = tokens[num_tokens - 1];
      } else {
        utils_free_str_arr(tokens);
        return false;
      }
    } else {
      if (num_tokens >= 2) {
        arg_name = tokens[num_tokens - 1];
      } else {
        utils_free_str_arr(tokens);
        return false;
      }
    }

    while (strlen(arg_name) > 0 && arg_name[0] == '*') {
      arg_name++;
    }

    if (strlen(arg_name) == 0 || utils_isnumeric(arg_name)) {
      utils_free_str_arr(tokens);
      return false;
    }
    utils_free_str_arr(tokens);
  }

  return true;
}

bool check_is_func_ptr(const char* var_declaration) {
  size_t parenthesis_index = strchr(var_declaration, '(') - var_declaration;
  size_t curr_index = parenthesis_index + 1;
  while (curr_index < strlen(var_declaration) &&
         isspace(var_declaration[curr_index])) {
    curr_index++;
  }
  if (curr_index < strlen(var_declaration) &&
      var_declaration[curr_index] == '*') {
    while(curr_index < strlen(var_declaration) &&
          var_declaration[curr_index] != ')') {
      curr_index++;
    }
    curr_index++;
    while(curr_index < strlen(var_declaration) &&
          isspace(var_declaration[curr_index])) {
      curr_index++;
    }
    if (curr_index < strlen(var_declaration) &&
        var_declaration[curr_index] == '(') {
      return true;
    }
  }
  return false;
}

bool check_has_open_string(const char* var_ref) {
  return utils_get_char_occurences(var_ref, '"', NULL) % 2 == 1;
}

bool check_is_assignment_op(const char* token, size_t curr_char) {
  return token[curr_char] == '=' &&
    (curr_char == strlen(token) - 1 || token[curr_char + 1] != '=') &&
    (curr_char == 0 ||
     !utils_char_in_array("=<>!", token[curr_char - 1], 4));
}

bool check_is_static(const char* var_ref) {
  return has_token_match(var_ref, "static");
}

static bool has_token_match(const char* var_ref, const char* token) {
  size_t* start_indices;
  int num_starts = utils_get_str_occurences(var_ref, token, &start_indices);
  for (int i = 0; i < num_starts; i++) {
    if (check_is_token_match(var_ref, start_indices[i], strlen(token))) {
      free(start_indices);
      return true;
    }
  }
  free(start_indices);
  return false;
}

bool check_is_token_match(const char* var_ref, size_t index, size_t token_len) {
  return (index == 0 || !check_is_valid_varname_char(var_ref[index-1])) &&
    (index + token_len == strlen(var_ref) ||
     !check_is_valid_varname_char(var_ref[index + token_len]));
}

struct list* check_get_string_ranges(const char* var_ref, bool* has_open_str) {
  if (strcmp(var_ref, "\t  data=0x%x\\n\", chip, addr, data);*/\n") == 0) {
    int test = 1;
  }
  size_t* quotes_indices;
  size_t* quote_literals;
  size_t* escaped_quotes;
  size_t* escaped_slashes;
  size_t quote_indices_len = utils_get_char_occurences(var_ref, '"', &quotes_indices);
  size_t quote_literals_len = utils_get_str_occurences(var_ref, "'\"'", &quote_literals);
  size_t escaped_quotes_len = utils_get_str_occurences(var_ref, "\\\"", &escaped_quotes);
  size_t escaped_slashes_len = utils_get_str_occurences(var_ref, "\\\\", &escaped_slashes);
  struct list* string_indices = list_create();
  for (size_t i = 0; i < quote_indices_len; i++) {
    size_t quote_index = quotes_indices[i];
    if (!utils_val_in_array(quote_literals, quote_index - 1, quote_literals_len) &&
        (!utils_val_in_array(escaped_quotes, quote_index - 1, escaped_quotes_len) ||
         utils_val_in_array(escaped_slashes, quote_index - 2, escaped_slashes_len))) {
      list_append(string_indices, (void*) quote_index);
    }
  }
  free(quotes_indices);
  free(quote_literals);
  free(escaped_quotes);
  free(escaped_slashes);

  struct list* string_ranges = list_create();
  if (*has_open_str) {
    if (string_indices->len == 0) {
      struct index_range* whole_range = (struct index_range*) malloc(sizeof(struct index_range));
      *whole_range = {0, strlen(var_ref)};
      list_append(string_ranges, whole_range);
    } else {
      struct list_node* first_quote_index = string_indices->head;
      size_t close_quote = (size_t) first_quote_index->payload;
      list_remove(string_indices, 0);
      free(first_quote_index);
      struct index_range* open_range = (struct index_range*) malloc(sizeof(struct index_range));
      *open_range = {0, close_quote};
      list_append(string_ranges, open_range);
      *has_open_str = false;
    }
  }

  ssize_t remainder_quote = -1;
  if (string_indices->len % 2 != 0) {
    struct list_node* last_quote_index = string_indices->tail;
    remainder_quote = (size_t) last_quote_index->payload;
    list_remove(string_indices, -1);
    free(last_quote_index);
    *has_open_str = true;
  }

  for (struct list_node* curr = string_indices->head; curr != NULL; curr = curr->next->next) {
    struct index_range* string_range = (struct index_range*) malloc(sizeof(struct index_range));
    *string_range = {(size_t) curr->payload + 1, (size_t) curr->next->payload};
    list_append(string_ranges, string_range);
  }
  if (remainder_quote >= 0) {
    struct index_range* remainder_range = (struct index_range*) malloc(sizeof(struct index_range));
    *remainder_range = {(size_t) remainder_quote + 1, strlen(var_ref)};
    list_append(string_ranges, remainder_range);
  }
  list_free_nodes(string_indices);

  return string_ranges;
}

bool check_is_arg_assignment(const char* var_name, struct list* func_args_name) {
  for (struct list_node* curr = func_args_name->head; curr != NULL; curr = curr->next) {
    char* curr_arg = (char*) curr->payload;
    if (strcmp(curr_arg, var_name) == 0) {
      return true;
    }
  }

  return false;
}

bool check_is_struct_root(const char* var_ref, size_t root_index) {
  return root_index == 0 ||
    (var_ref[root_index - 1] != '.' &&
     (root_index <= 1 ||
      (var_ref[root_index - 2] != '-' && var_ref[root_index - 1] != '>')));
}

bool check_is_func_decl_in_scope(const char* func_decl, const char* decl_src_file,
                                 const char* ref_src_file) {
  return (!check_is_static(func_decl) && !check_is_define(func_decl) &&
          strcmp(func_decl, "main") != 0) ||
    strstr(decl_src_file, ".h") != NULL || strcmp(decl_src_file, ref_src_file) == 0;
}

bool check_is_define(const char* var_ref) {
  if (strlen(var_ref) > 0 && var_ref[0] == '#') {
    const char* curr_ref_ptr = var_ref + 1;
    while (*curr_ref_ptr != '\0' && isspace(*curr_ref_ptr)) {
      curr_ref_ptr++;
    }
    return curr_ref_ptr == strstr(curr_ref_ptr, "define");
  } else {
    return false;
  }
}

bool check_has_func_call(const char* var_ref, const char* func_name) {
  size_t* args_start_indices;
  size_t num_start_indices = utils_get_char_occurences(var_ref, '(',
                                                       &args_start_indices);
  for (size_t i = 0; i < num_start_indices; i++) {
    char* func_call_name = token_get_func_name(var_ref, args_start_indices[i]);
    if (func_call_name != NULL && strcmp(func_call_name, func_name) == 0) {
      free(args_start_indices);
      free(func_call_name);
      return true;
    }
    free(func_call_name);
  }

  free(args_start_indices);
  return false;
}
