#include <string.h>
#include <ctype.h>
#include "list.h"
#include "utils.h"
#include "check_expression.h"
#include "sanitize_expression.h"
#include "struct_parse.h"

#define NO_MATCH -1

static size_t get_struct_segment(const char* var_ref, size_t curr_index,
                                 char** next_segment);

static bool is_struct_segment_in_expr(const char* curr_level, const char* segment);

char* struct_get_root_name(const char* var_name) {
  char* dot_ptr = (char*) strchr(var_name, '.');
  char* arrow_ptr = (char*) strstr(var_name, "->");
  char* bracket_ptr = (char*) strchr(var_name, '[');

  char* trunc_ptr = (dot_ptr == NULL || (arrow_ptr != NULL && dot_ptr > arrow_ptr)) ?
    arrow_ptr : dot_ptr;
  trunc_ptr = (bracket_ptr == NULL || (trunc_ptr != NULL && bracket_ptr > trunc_ptr)) ?
    trunc_ptr : bracket_ptr; 

  char* root_var_name = (char*) var_name;
  if (trunc_ptr != NULL) {
    size_t root_len = trunc_ptr - var_name;
    root_var_name = (char*) malloc(root_len + 1);
    strncpy(root_var_name, var_name, root_len);
    root_var_name[root_len] = '\0';
  }

  char* original_root_name = root_var_name;
  root_var_name = sanitize_extract_varname(root_var_name);
  utils_free_if_both_different(original_root_name, root_var_name, var_name);
  original_root_name = root_var_name;
  
  while(root_var_name[0] == '*' || root_var_name[0] == '&' ||
        root_var_name[0] == '(') {
    root_var_name++;
  }
  if (original_root_name != root_var_name) {
    char* new_root_var_name = (char*) malloc(strlen(root_var_name) + 1);
    strncpy(new_root_var_name, root_var_name, strlen(root_var_name) + 1);
    utils_free_if_different(original_root_name, var_name);
    root_var_name = new_root_var_name;
  }

  return root_var_name;
}

struct list* struct_get_struct_hierarchy(const char* var_name, char** root_name) {
  *root_name = struct_get_root_name(var_name);
  struct list* hierarchy = list_create();
  size_t curr_index = (strstr(var_name, *root_name) + strlen(*root_name)) - var_name;
  if (var_name[curr_index] == '[') {
    curr_index = check_recur_with_parenthesis(var_name, curr_index + 1, '[');
    curr_index++;
  }
  while (curr_index < strlen(var_name) &&
         (var_name[curr_index] == '.' ||
          (var_name[curr_index] == '-' &&
           (curr_index < strlen(var_name) - 1 && var_name[curr_index + 1] == '>')))) {
    char* segment;
    curr_index = get_struct_segment(var_name, curr_index, &segment);
    list_append(hierarchy, segment);
    while (isspace(var_name[curr_index]) || var_name[curr_index] == '(' ||
           var_name[curr_index] == ')') {
      curr_index++;
    }
  }

  return hierarchy;
}

static size_t get_struct_segment(const char* var_ref, size_t curr_index,
                                 char** next_segment) {
  if (var_ref[curr_index] == '.') {
    curr_index++;
  } else {
    curr_index += 2;
  }
  size_t segment_start = curr_index;

  while (curr_index < strlen(var_ref) &&
         (check_is_valid_varname_char(var_ref[curr_index]) ||
          utils_char_in_array("*&([", var_ref[curr_index], 4))) {
    if (var_ref[curr_index] == '(' || var_ref[curr_index] == '[') {
      curr_index = check_recur_with_parenthesis(var_ref, curr_index + 1, var_ref[curr_index]);
    }
    curr_index++;
  }

  size_t segment_len = curr_index - segment_start;
  char* segment = (char*) malloc(segment_len + 1);
  strncpy(segment, var_ref + segment_start, segment_len);
  segment[segment_len] = '\0';

  char* original_segment = segment;
  while(segment[0] == '*' || segment[0] == '&') {
    segment++;
  }
  if (segment[0] == '(' && segment[strlen(segment) - 1] == ')') {
    segment++;
    segment[strlen(segment) - 1] = '\0';
  }
  while(segment[0] == '*' || segment[0] == '&') {
    segment++;
  }
  if (segment != original_segment) {
    char* new_segment = (char*) malloc(strlen(segment) + 1);
    strncpy(new_segment, segment, strlen(segment) + 1);
    free(segment);
    segment = new_segment;
  }
  
  char* bracket_index = strchr(segment, '[');
  if (bracket_index != NULL) {
    *bracket_index = '\0';
  }
  if (check_is_func(segment)) {
    char* parenthesis_index = strchr(segment, '(');
    *parenthesis_index = '\0';
  }

  char* san_segment = sanitize_remove_casts(segment);
  utils_free_if_different(segment, san_segment);
  *next_segment = utils_trim_str(san_segment);
  utils_free_if_different(san_segment, *next_segment);
  
  return curr_index;
}

struct list* struct_get_struct_matches(const char* var_ref, const char* root_name,
                                struct list* field_hierarchy) {
  size_t* start_indices;
  size_t num_indices = utils_get_str_occurences(var_ref, root_name, &start_indices);
  struct list* hierarchy_ptrs = list_create();
  for (size_t i = 0; i < num_indices; i++) {
    if (!check_is_struct_root(var_ref, start_indices[i])) {
      int test = 1;
    }
    if (check_is_token_match(var_ref, start_indices[i], strlen(root_name)) &&
        check_is_struct_root(var_ref, start_indices[i])) {
      size_t curr_index = start_indices[i] + strlen(root_name);
      struct list_node *curr_level = field_hierarchy->head;
      struct list_node *last_level = NULL;
      bool is_match = true;
      while (curr_index < strlen(var_ref) &&
             (var_ref[curr_index] == '.' ||
              (var_ref[curr_index] == '-' &&
               (curr_index < strlen(var_ref) - 1 && var_ref[curr_index + 1] == '>')))) {
        if (curr_level == NULL) {
          is_match = false;
          break;
        }
        char* curr_level_name = (char*) curr_level->payload;
        char* segment;
        curr_index = get_struct_segment(var_ref, curr_index, &segment);
        if (strchr(segment, ' ') != NULL && !is_struct_segment_in_expr(curr_level_name, segment)) {
          free(segment);
          is_match = false;
          break;
        } else if (strcmp(curr_level_name, segment) != 0) {
          free(segment);
          is_match = false;
          break;
        }
        free(segment);
        last_level = curr_level;
        curr_level = curr_level->next;
      }

      if (is_match) {
        list_append(hierarchy_ptrs, last_level);
      }
    }
  }
  free(start_indices);

  return hierarchy_ptrs;
}

static bool is_struct_segment_in_expr(const char* curr_level, const char* segment) {
  size_t* match_indices;
  size_t num_matches = utils_get_str_occurences(segment, curr_level, &match_indices);
  for (size_t i = 0; i < num_matches; i++) {
    if (check_is_token_match(segment, match_indices[i], strlen(curr_level))) {
      free(match_indices);
      return true;
    }
  }

  free(match_indices);
  return false;
}

bool struct_has_full_match(struct list* struct_matches, bool is_normal_var) {
  if (is_normal_var && struct_matches->head != NULL) {
    return true;
  }
  
  for (struct list_node* curr = struct_matches->head; curr != NULL; curr = curr->next) {
    if (curr->payload != NULL) {
      struct list_node* hierarchy_level = (struct list_node*) curr->payload;
      if (hierarchy_level->next == NULL) {
        return true;
      }
    }
  }

  return false;
}

struct list_node* struct_get_highest_match(struct list* hierarchy_matches) {
  struct list_node* highest_match = NULL;
  for (struct list_node* curr = hierarchy_matches->head; curr != NULL; curr = curr->next) {
    struct list_node* hierarchy_node = (struct list_node*) curr->payload;
    if (highest_match == NULL ||
        (hierarchy_node != NULL && hierarchy_node->index > highest_match->index)) {
      highest_match = hierarchy_node;
    }
  }

  return highest_match;
}
