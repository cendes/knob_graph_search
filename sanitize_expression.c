#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include "c_keywords.h"
#include "utils.h"
#include "list.h"
#include "check_expression.h"
#include "token_get.h"
#include "sanitize_expression.h"

static char* remove_comment_after(const char* curr_var_ref, ssize_t comment_index);

static char* remove_comment_before(const char* curr_var_ref, size_t comment_index);

char* sanitize_extract_varname(const char* var_ref) {
  const char* var_ref_start = var_ref;
  while (utils_char_in_array(C_UNARY_OPERANDS, var_ref_start[0], UTILS_SIZEOF_ARR(C_UNARY_OPERANDS))) {
    var_ref_start++;
  }
  char* var_name = (char*) malloc(strlen(var_ref_start) + 1);
  strncpy(var_name, var_ref_start, strlen(var_ref_start) + 1);
  if (var_name[strlen(var_name) - 1] == ']') {
    // TODO: check if variable is inside the brackets
    size_t open_bracket_idx = check_recur_with_parenthesis(var_name, strlen(var_name) - 2, ']');
    var_name[open_bracket_idx] = '\0';
  }
  if (strchr(var_name, '(') != NULL) {
    char* peeled_var_name = sanitize_peel_parenthesis(var_name);
    utils_free_if_different(var_name, peeled_var_name);
    var_name = sanitize_remove_casts(peeled_var_name);
    utils_free_if_different(peeled_var_name, var_name);
  }
  while (utils_char_in_array(C_UNARY_OPERANDS, var_name[strlen(var_name) - 1],
                            UTILS_SIZEOF_ARR(C_UNARY_OPERANDS)) ||
         var_name[strlen(var_name) - 1] == '+') {
    utils_truncate_str(var_name, -1);
  }

  return var_name;
}

char* sanitize_peel_parenthesis(const char* var_ref) {
  if (var_ref[0] == '(') {
    size_t expr_end = check_recur_with_parenthesis(var_ref, 1, '(');
    if (expr_end == strlen(var_ref) - 1) {
      char* new_var_ref = (char*) malloc(strlen(var_ref));
      strncpy(new_var_ref, var_ref + 1, strlen(var_ref));
      utils_truncate_str(new_var_ref, -1);
      return new_var_ref;
    }
  }

  return (char*) var_ref;
}

char* sanitize_remove_comments_and_strip(char* var_ref, bool* has_open_comment,
                                         bool* has_open_str) {
  char* curr_var_ref = var_ref;
  if (*has_open_comment) {
    size_t* comment_indices;
    size_t num_comments = utils_get_str_occurences(var_ref, "*/", &comment_indices);
    if (num_comments > 0) {
      curr_var_ref = remove_comment_before(var_ref, comment_indices[0]);
      *has_open_comment = false;
      free(comment_indices);
    } else {
      free(comment_indices);
      var_ref[0] = '\0';
      return var_ref;
    }
  } else {
    if (strcmp(var_ref, "\t/* http://bugzilla.kernel.org/show_bug.cgi?id=14183 */\n") == 0) {
      int test = 1;
    }
    size_t* double_slash_indices;
    size_t num_double_slashes =
      token_get_actual_indices(var_ref, "//", *has_open_str, &double_slash_indices);
    size_t curr_double_slash = 0;

    size_t* slash_star_indices;
    size_t num_slash_star =
      token_get_actual_indices(var_ref, "/*", *has_open_str, &slash_star_indices);
    
    struct list* comment_ranges = list_create();
    size_t curr_close_idx = 0;
    for (size_t i = 0; i < num_slash_star; i++) {
      if (slash_star_indices[i] < curr_close_idx) {
        continue;
      } else if (curr_double_slash < num_double_slashes &&
                 slash_star_indices[i] > double_slash_indices[curr_double_slash]) {
        break;
      }
      
      curr_close_idx = slash_star_indices[i] + 3;
      while (curr_close_idx < strlen(var_ref) &&
             (var_ref[curr_close_idx - 1] != '*' || var_ref[curr_close_idx] != '/')) {
        curr_close_idx++;
      }
      curr_close_idx++;
      if (curr_close_idx > strlen(var_ref)) {
        curr_close_idx = strlen(var_ref);
        curr_double_slash = num_double_slashes;
        *has_open_comment = true;
      } else {
        for (; curr_double_slash < num_double_slashes; curr_double_slash++) {
          if (double_slash_indices[curr_double_slash] > curr_close_idx) {
            break;
          }
        }
      }
      
      struct index_range* comment_range =
        (struct index_range*) malloc(sizeof(struct index_range));
      *comment_range = {slash_star_indices[i], curr_close_idx};
      list_append(comment_ranges, comment_range);
    }

    if (curr_double_slash < num_double_slashes) {
      struct index_range* comment_range =
        (struct index_range*) malloc(sizeof(struct index_range));
      *comment_range = {double_slash_indices[curr_double_slash], strlen(var_ref)};
      list_append(comment_ranges, comment_range);
    }
    
    free(double_slash_indices);
    free(slash_star_indices);
    curr_var_ref = sanitize_remove_substring(var_ref, comment_ranges);
    list_free(comment_ranges);
  }

  char* sanitized_var_ref = sanitize_remove_string_literals(curr_var_ref, has_open_str);
  utils_free_if_both_different(curr_var_ref, sanitized_var_ref, var_ref);

  char* trimmed_var_ref = utils_trim_str(sanitized_var_ref);
  utils_free_if_both_different(sanitized_var_ref, trimmed_var_ref, var_ref);
  return trimmed_var_ref;
}

static char* remove_comment_after(const char* curr_var_ref, ssize_t comment_index) {
  char* new_var_ref = (char*) malloc(comment_index + 1);
  strncpy(new_var_ref, curr_var_ref, comment_index);
  new_var_ref[comment_index] = '\0';
  return new_var_ref;
}

static char* remove_comment_before(const char* curr_var_ref, size_t comment_index) {
  size_t str_size = strlen(curr_var_ref) - comment_index;
  char* new_var_ref = (char*) malloc(str_size);
  strncpy(new_var_ref, curr_var_ref + comment_index + 2, str_size);
  return new_var_ref;
}

char* sanitize_remove_sizeof(const char* var_ref) {
  if (strcmp(var_ref, "arch/x86/boot/boot.h <global> 31 #define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))") == 0) {
    int test = 1;
  }
  size_t* sizeofs;
  size_t num_sizeofs = utils_get_str_occurences(var_ref, "sizeof", &sizeofs);
  struct list* arg_indices = list_create();
  for (size_t i = 0; i < num_sizeofs; i++) {
    size_t arg_start = sizeofs[i] + strlen("sizeof");
    if (arg_start < strlen(var_ref) && var_ref[arg_start] == '(') {
      size_t arg_end = check_recur_with_parenthesis(var_ref, arg_start + 1, '(');
      struct index_range* arg_range = (struct index_range*) malloc(sizeof(struct index_range));
      *arg_range = {arg_start + 1, arg_end};
      list_append(arg_indices, arg_range);
    }
  }
  free(sizeofs);

  char* new_var_ref = sanitize_remove_substring(var_ref, arg_indices);
  list_free(arg_indices);
  return new_var_ref;
}

char* sanitize_remove_string_literals(const char* var_ref, bool* has_open_str) {
  if (strcmp(var_ref,"fs/proc/consoles.c show_console_dev 51 seq_printf(m, \"%c%c%c (%s)\", con->read ? 'R' : '-',") == 0) {
    int test = 1;
  }
  struct list* string_ranges = check_get_string_ranges(var_ref, has_open_str);
  char* new_var_ref = sanitize_remove_substring(var_ref, string_ranges);
  list_free(string_ranges);

  size_t* single_quotes;
  size_t num_single_quotes = utils_get_char_occurences(new_var_ref, '\'', &single_quotes);
  for (size_t i = 0; i < num_single_quotes; i++) {
    size_t end_quote = single_quotes[i] + 2;
    if (new_var_ref[end_quote] != '\'') {
      end_quote++;
    }
    for (size_t j = single_quotes[i] + 1; j < end_quote; j++) {
      new_var_ref[j] = '$';
    }
    while (i < num_single_quotes && single_quotes[i] < end_quote) {
      i++;
    }
  }
  free(single_quotes);
  return new_var_ref;
}

char* sanitize_remove_casts(const char* var_ref) {
  struct list* cast_list = list_create();
  for (size_t i = 0; i < strlen(var_ref); i++) {
    if (var_ref[i] == '(' && (i == 0 || !check_is_valid_varname_char(var_ref[i - 1]))) {
      if (strcmp(var_ref,"list_for_each_safe (item, tmp, list) kfree (list_entry (item, struct frag, list));") == 0) {
        int test = 1;
      }
      if (i > 0) {
        size_t curr_char = i - 1;
        while(curr_char > 0 && isspace(var_ref[curr_char])) {
          curr_char--;
        }
        if (check_is_valid_varname_char(var_ref[curr_char])) {
          continue;
        }
      }
      
      size_t expr_end = check_recur_with_parenthesis(var_ref, i + 1, '(');
      if (expr_end >= strlen(var_ref)) {
        continue;
      }
      size_t expr_len = expr_end - i + 1;
      char *expr = (char*) malloc(expr_len + 1);
      expr[expr_len] = '\0';
      strncpy(expr, var_ref + i, expr_len);

      char* star_ptr = NULL;
      bool has_operand = false;
      char* operand_ptr;
      for (size_t j = 0; j < UTILS_SIZEOF_ARR(C_OPERANDS); j++) {
        if ((operand_ptr = strchr(expr, C_OPERANDS[j])) != NULL) {
          if (C_OPERANDS[j] == '*') {
            star_ptr = operand_ptr;
          } else {
            has_operand = true;
          }
        }
      }

      if (star_ptr != NULL) {
        size_t star_index = star_ptr - expr;
        size_t next_char = star_index + 1;
        while (next_char < strlen(expr) && isspace(expr[next_char])) {
          next_char++;
        }
        if (check_is_valid_varname_char(expr[next_char]) || expr[next_char] == '(' ||
            (utils_char_in_array(C_UNARY_OPERANDS, expr[next_char],
                                 UTILS_SIZEOF_ARR(C_UNARY_OPERANDS)) &&
             (expr[next_char] != '*' || next_char > star_index + 1))) {
          has_operand = true;
        }
      }
      free(expr);

      bool is_cast = false;
      if (!has_operand) {
        size_t next_char = expr_end + 1;
        while (next_char < strlen(var_ref) && isspace(var_ref[next_char])) {
          next_char++;
        }
        if (next_char == strlen(var_ref)) {
          break;
        }

        if (var_ref[next_char] == '*' || var_ref[next_char] == '&' || var_ref[next_char] == '-') {
          size_t check_idx = expr_end - 1;
          while (check_idx > 0 && isspace(var_ref[check_idx])) {
            check_idx--;
          }
          if (var_ref[check_idx] == '*') {
            is_cast = true;
          }
          
          while (check_idx > 0 && check_is_valid_varname_char(var_ref[check_idx])) {
            check_idx--;
          }
          while (check_idx > 0 && isspace(var_ref[check_idx])) {
            check_idx--;
          }
          if (check_is_valid_varname_char(var_ref[check_idx])) {
            is_cast = true;
          }
          // TODO: check if it is really a cast or not
        } else if (utils_char_in_array(C_UNARY_OPERANDS, var_ref[next_char],
                                       UTILS_SIZEOF_ARR(C_UNARY_OPERANDS)) ||
                   check_is_valid_varname_char(var_ref[next_char]) ||
                   var_ref[next_char] == '(') {
          is_cast = true;
        } else {
          int test = 1;
        }
      }
      
      if (is_cast) {
        struct index_range* expr_range = (struct index_range*) malloc(sizeof(struct index_range));
        *expr_range = {i, expr_end + 1};
        list_append(cast_list, expr_range);
      }
    }
  }

  char* new_var_ref = sanitize_remove_substring(var_ref, cast_list);
  list_free(cast_list);
  return new_var_ref;
}

char* sanitize_remove_array_indexing(const char* var_ref) {
  size_t* bracket_indices;
  size_t num_brackets = utils_get_char_occurences(var_ref, '[', &bracket_indices);
  struct list* bracket_ranges = list_create();
  size_t curr_index = 0;
  for (size_t i = 0; i < num_brackets; i++) {
    size_t open_idx = bracket_indices[i];
    if (open_idx >= curr_index) {
      size_t close_idx = check_recur_with_parenthesis(var_ref, open_idx + 1, '[');
      struct index_range* bracket_range = (struct index_range*) malloc(sizeof(struct index_range));
      *bracket_range = {open_idx, close_idx + 1};
      list_append(bracket_ranges, bracket_range);
      curr_index = close_idx + 1;
    }
  }
  free(bracket_indices);

  char* new_var_ref = sanitize_remove_substring(var_ref, bracket_ranges);
  list_free(bracket_ranges);
  return new_var_ref;
}

char* sanitize_remove_substring(const char* var_ref, struct list* substring_indices) {
  if (substring_indices->len == 0) {
    return (char*) var_ref;
  }
  if (strcmp(var_ref, "include/linux/srcutiny.h __srcu_read_lock 64 WRITE_ONCE(ssp->srcu_lock_nesting[idx], READ_ONCE(ssp->srcu_lock_nesting[idx]) + 1);") == 0) {
    int test = 1;
  }
  
  char* new_var_ref = (char*) malloc(strlen(var_ref) + 1);
  size_t ref_offset;
  size_t new_ref_offset = 0;
  size_t num_to_copy;
  struct list_node* prev = NULL;
  struct index_range *prev_range = NULL;
  for (struct list_node* curr = substring_indices->head; curr != NULL; curr = curr->next) {
    struct index_range* curr_range = (struct index_range*) curr->payload;
    if (prev == NULL) {
      ref_offset = 0;
      num_to_copy = curr_range->start;
    } else {
      prev_range = (struct index_range*) prev->payload;
      if (curr_range->start < prev_range->end) {
        continue;
      }
      ref_offset = prev_range->end;
      num_to_copy = curr_range->start - prev_range->end;
    }
    strncpy(new_var_ref + new_ref_offset, var_ref + ref_offset, num_to_copy);
    new_ref_offset += num_to_copy;
    prev = curr;
  }
  if (prev != NULL) {
    prev_range = (struct index_range*) prev->payload;
    ref_offset = prev_range->end;
    num_to_copy = strlen(var_ref) - prev_range->end + 1;
    strncpy(new_var_ref + new_ref_offset, var_ref + ref_offset, num_to_copy);
  }

  return new_var_ref;
}

char* sanitize_clean_var_ref(const char* var_ref) {
  bool has_open_str = false;
  char* var_ref_no_str = sanitize_remove_string_literals(var_ref, &has_open_str);
  //assert(!has_open_str &&
  //       "sanitize_clean_var_ref: complete expression has open string");
  char* var_ref_no_sizeof = sanitize_remove_sizeof(var_ref_no_str);
  utils_free_if_both_different(var_ref_no_str, var_ref, var_ref_no_sizeof);
  //char* var_ref_no_casts = sanitize_remove_casts(var_ref_no_sizeof);
  //utils_free_if_both_different(var_ref_no_sizeof, var_ref, var_ref_no_casts);
  char* trimmed_var_ref = utils_trim_str(var_ref_no_sizeof);
  utils_free_if_both_different(var_ref_no_sizeof, var_ref, trimmed_var_ref);
  return trimmed_var_ref;
}
