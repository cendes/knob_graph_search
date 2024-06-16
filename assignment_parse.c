#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "list.h"
#include "hash_map.h"
#include "database.h"
#include "utils.h"
#include "check_expression.h"
#include "sanitize_expression.h"
#include "token_get.h"
#include "struct_parse.h"
#include "file_search.h"
#include "assignment_parse.h"
#include "func_call_parse.h"
#include "var_search.h"

//static hash_map func_locals_visited = map_create();
static struct list* globals_visited = list_create();

static bool is_out_arg_assignment(const char* var_name, const char** var_ref_arr,
                                  size_t var_ref_arr_len, const char* func_name);

bool assignment_handle_var_assignment(const char* func_name,
                                      const char* var_ref,
                                      const char** var_ref_arr,
                                      size_t var_ref_arr_len,
                                      const char* var_name,
                                      struct list* struct_hierarchy,
                                      bool is_return_assingment,
                                      hash_map func_ptrs,
                                      bool record_match,
                                      struct list** return_hierarchy,
                                      struct list** output_args) { 
  if (strcmp(var_ref, "((struct seq_file *)file->private_data)->private = data;") == 0) {
    int test = 1;
  }
  bool out_arg_assignment;
  const char* assignment_rhs;
  char* assigned_var = assignment_get_assignment_var(func_name, var_ref, var_ref_arr,
                                                     var_ref_arr_len, var_name,
                                                     is_return_assingment,
                                                     &assignment_rhs,
                                                     &out_arg_assignment);
  if (assigned_var == NULL) {
    *output_args = list_create();
    *return_hierarchy = NULL;
    return false;
  }

  if (strcmp(func_name, "rose_parse_national") == 0 && strcmp(assigned_var, "pt") == 0) {
    int test = 1;
  }
  
  struct list* hierarchy_matches;
  if (is_return_assingment) {
    hierarchy_matches = list_copy(struct_hierarchy, NULL);
  } else {
    char* sanitized_assignment_rhs = sanitize_remove_array_indexing(assignment_rhs);
    struct list* struct_matches = struct_get_struct_matches(sanitized_assignment_rhs,
                                                            var_name,
                                                            struct_hierarchy);
    utils_free_if_different(sanitized_assignment_rhs, assignment_rhs);
    if (struct_matches->len == 0) {
      *output_args = list_create();
      *return_hierarchy = NULL;
      return false;
    }
    struct list_node* match_start = struct_get_highest_match(struct_matches);
    hierarchy_matches = list_copy(struct_hierarchy, match_start);
    list_free_nodes(struct_matches);
  }
  

  char* assigned_root;
  struct list* assigned_struct_hierarchy = struct_get_struct_hierarchy(assigned_var, &assigned_root);
  struct_hierarchy = list_combine(assigned_struct_hierarchy, hierarchy_matches);

  //if (var_contains_func_var_visited(func_name, assigned_root, struct_hierarchy,
  //                                  return_hierarchy, output_args)) {
  //if (*output_args == NULL) {
  //   *output_args = list_create();
  //  }
  //  utils_free_if_different(assigned_var, assigned_root);
  //  return false;
    //}

    //var_insert_func_var_visited(func_name, assigned_root, struct_hierarchy, NULL, NULL);
  bool has_match = assignment_get_assigned_var_funcs(func_name, assigned_root,
                                                     struct_hierarchy, var_ref_arr,
                                                     var_ref_arr_len, func_ptrs,
                                                     record_match, return_hierarchy,
                                                     output_args);
  if (out_arg_assignment) {
    assignment_append_out_arg(*output_args, assigned_root, struct_hierarchy);
  }
  //var_remove_func_var_visited(func_name, assigned_root);

  //list_free(assigned_struct_hierarchy); // TODO: what is the issue with this?
  list_free_nodes(hierarchy_matches);
  //list_free_nodes(struct_hierarchy);
  return has_match;
}

char* assignment_get_assignment_var(const char* func_name, const char* var_ref,
                                    const char** var_ref_arr, size_t var_ref_arr_len,
                                    const char* var_name, bool is_return_assignment,
                                    const char** assignment_rhs,
                                    bool* out_arg_assignment) {
  // TODO: handle for loops properly (only get assignment up to ;)
  *out_arg_assignment = false;
  ssize_t eq_index = token_get_eq_index(var_ref);
  if (eq_index < 0 || (!is_return_assignment &&
                       !check_has_var_name(var_ref + eq_index + 1, var_name))) {
    return NULL;
  }
  *assignment_rhs = var_ref + eq_index;

  ssize_t var_end_index = eq_index - 1;
  while (var_end_index >= 0 &&
         (!check_is_valid_varname_char(var_ref[var_end_index]) &&
          var_ref[var_end_index] != '(' && var_ref[var_end_index] != ']')) {
    var_end_index--;
  }
  ssize_t var_start_index = var_end_index;
  while (var_start_index >= 0 &&
         (check_is_valid_varname_char(var_ref[var_start_index]) ||
          utils_char_in_array("*.>][)(", var_ref[var_start_index], 7))) {
    if (var_ref[var_start_index] == '>') {
      if (var_ref[var_start_index - 1] == '-') {
        var_start_index -= 2;
      } else {
        break;
      }
    } else if (var_ref[var_start_index] == ')' || var_ref[var_start_index] == ']') {
      var_start_index = check_recur_with_parenthesis(var_ref, var_start_index - 1,
                                                     var_ref[var_start_index]);  // TODO: peel outer parenthesis and handle for loops
      var_start_index--;
    } else if (var_ref[var_start_index] == '(') {
      break;
    } else {
      var_start_index--;
    }
  }

  var_start_index++;
  var_end_index++;
  size_t assigned_var_len = var_end_index - var_start_index;
  char* assigned_var_name = (char*) malloc(assigned_var_len + 1);
  strncpy(assigned_var_name, var_ref + var_start_index, assigned_var_len);
  assigned_var_name[assigned_var_len] = '\0';

  *out_arg_assignment = is_out_arg_assignment(assigned_var_name, var_ref_arr,
                                              var_ref_arr_len, func_name);
  char* san_var_name = sanitize_extract_varname(assigned_var_name);
  utils_free_if_different(assigned_var_name, san_var_name);

  if (san_var_name[0] == '.') {
    char* struct_name = file_find_struct_name(var_ref_arr[0], atoi(var_ref_arr[2]));
    if (struct_name == NULL) {
      //list_free(*output_var_refs);
      free(san_var_name);
      return NULL;
    } else {
      char* final_var_name = (char*) malloc(strlen(san_var_name) + strlen(struct_name) + 1);
      strncpy(final_var_name, san_var_name, strlen(san_var_name));
      strncpy(final_var_name + strlen(san_var_name), var_name, strlen(var_name) + 1);
      free(san_var_name);
      return final_var_name;
    }
  } else {
    return san_var_name;
  }
}

static bool is_out_arg_assignment(const char* var_name, const char** var_ref_arr,
                                size_t var_ref_arr_len, const char* func_name) {
  if ((strchr(var_name, '*') != NULL || strchr(var_name, '[') != NULL ||
       strstr(var_name, "->") != NULL)) {
    char* san_var_name = sanitize_extract_varname(var_name);
    char* root_var_name = struct_get_root_name(san_var_name);
    if (strcmp(root_var_name, "pt") == 0) {
      int test = 1;
    }
    utils_free_if_both_different(san_var_name, var_name, root_var_name);
    struct list* func_args_name = func_get_curr_func_arg_names(func_name,
                                                               var_ref_arr[0]);

    return check_is_arg_assignment(root_var_name, func_args_name);
  }

  
  return false;
}

bool assignment_get_assigned_var_funcs(const char* func_name,
                                       char* assigned_var,
                                       struct list* struct_hierarchy,
                                       const char** var_ref_arr,
                                       size_t var_ref_arr_len,
                                       hash_map func_ptrs,
                                       bool record_match,
                                       struct list** return_hierarchy,
                                       struct list** output_args) {
  bool has_match = false;
  //struct list* additional_funcs = list_create();
  *output_args = list_create(); // TODO: this leaks memory
  *return_hierarchy = NULL;
  char* root_assignment_name = struct_get_root_name(assigned_var);

  if (assigned_var != NULL) {
    if (strcmp(func_name, "seccomp_attach_filter") == 0 &&
        strcmp(root_assignment_name, "current") == 0) {
      return false;
    }
    if (check_has_operand(root_assignment_name)) {
      // TODO: this is a temporary solution
      size_t var_end = 0;
      while (check_is_valid_varname_char(root_assignment_name[var_end])) {
        var_end++;
      }
      char* actual_assignment_name = (char*) malloc(var_end + 1);
      strncpy(actual_assignment_name, root_assignment_name, var_end);
      actual_assignment_name[var_end] = '\0';
      //free(root_assignment_name);
      root_assignment_name = actual_assignment_name;
    }
    struct func_var_entry* entry = var_get_func_var_entry(func_name,
                                                          root_assignment_name);
    bool is_global = false;
    struct list* assigned_var_refs;
    struct func_var_entry* local_empty_entry = NULL;
    if (entry == NULL) {
      struct list* global_var_refs;
      assigned_var_refs = var_get_local_var_refs(assigned_var, func_name,
                                                 var_ref_arr[0], -1,
                                                 false, &global_var_refs);
      if (assigned_var_refs == NULL) {
        local_empty_entry =
          var_create_func_var_entry(func_name, root_assignment_name);
        local_empty_entry->var_refs = list_create();

        char cmd[256];
        sprintf(cmd, "cscope -d -L1 %s", root_assignment_name);
        struct list* global_definitions = utils_get_cscope_output(cmd);
        if (global_definitions->len == 0) {
          fprintf(stderr, "No variable declaration found: Function %s Variable %s\n",
                  func_name, root_assignment_name);
          list_free(global_var_refs);
          global_var_refs = list_create();
        }
        list_free(global_definitions);
        
        entry = var_create_func_var_entry("<global>", root_assignment_name);
        is_global = true;
        assigned_var_refs = global_var_refs;
      } else {
        entry = var_create_func_var_entry(func_name, root_assignment_name);
      }
      entry->var_refs = assigned_var_refs;
    } else if (entry->var_refs->len == 0) {
      entry = var_get_func_var_entry("<global>", root_assignment_name);
      if (entry == NULL) {
        fprintf(stderr, "No references to variable: %s\n", root_assignment_name);
        return false;
      }
      is_global = true;
      assigned_var_refs = entry->var_refs;
    } else {
      assigned_var_refs = entry->var_refs;
      is_global = false;
    }

    if (!entry->locked) {
      entry->locked = true;
      if (is_global) {
        if (strcmp(root_assignment_name, "patch") == 0) {
          int test = 1;
        }
        fprintf(stderr, "Local variable not found: Function %s, Variable %s\n",
               func_name, root_assignment_name);
        var_get_global_var_refs(root_assignment_name, struct_hierarchy,
                                assigned_var_refs, record_match);
        if (local_empty_entry != NULL) {
          database_write_func_vars_visited_entry(func_name, root_assignment_name,
                                                 local_empty_entry);
        }
        *return_hierarchy = NULL;
        *output_args = list_create();
      } else {
        has_match = var_get_func_refs(root_assignment_name, struct_hierarchy,
                                      assigned_var_refs, func_name, func_ptrs,
                                      record_match,  return_hierarchy, output_args,
                                      NULL);
      }
      entry->locked = false;
    }
    
  /*   if (assigned_var_refs == NULL) { */
  /*     if (!list_contains_str(globals_visited, root_assignment_name)) { */
  /*       has_match = var_find_func_refs(root_assignment_name, struct_hierarchy, */
  /*                                      return_hierarchy, output_args); */
  /*       list_append(globals_visited, root_assignment_name); */
  /*     } */
  /*   } else { */
  /*     has_match = var_get_func_refs(root_assignment_name, struct_hierarchy, */
  /*                                   assigned_var_refs, false, func_name, */
  /*                                   func_ptrs, return_hierarchy, output_args); */
  /*     list_free_nodes(assigned_var_refs); */
  /*   } */
  /* } */
  }
  return has_match;
}

void assignment_append_out_arg(struct list* out_args, char* arg_name,
                               struct list* struct_hierarchy) {
  char* arg_name_cpy = (char*) malloc(strlen(arg_name) + 1);
  strncpy(arg_name_cpy, arg_name, strlen(arg_name) + 1);
  struct output_arg* output_arg = (struct output_arg*) malloc(sizeof(struct output_arg));
  *output_arg = {arg_name_cpy, struct_hierarchy};
  list_append(out_args, output_arg);
}
