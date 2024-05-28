#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"
#include "list.h"
#include "hash_map.h"
#include "check_expression.h"
#include "sanitize_expression.h"
#include "struct_parse.h"
#include "token_get.h"
#include "file_search.h"
#include "assignment_parse.h"
#include "func_call_parse.h"
#include "var_search.h"
#include "call_graph.h"
#include "expand_call_graph.h"


//TODO: optimize reading of multiline by saving multiline expression
//TODO: handle weird dereference cases (pointer arithmetic and struct)
//TODO: properly handle function pointers
//TODO: Eliminate references to array index
//TODO: handle assignments to array or struct literals
//TODO: Properly handle removing casts
//TODO: Properly handle ternary operators in assigments and arguments (generate new expressions)
//TODO: handle function pointers in func variables visited cache
//TODO: create tree database for already visited func variables with different struct hierarchy
//TODO: for returns, check if expression is boolean

static struct list* get_local_var_refs_from_src(struct list* var_refs,
                                                const char* var_name,
                                                const char* func_name,
                                                const char* src_file,
                                                int func_start_line,
                                                int func_end_line);

static bool get_local_ref(const char* var_name, const char* var_ref,
                          const char** var_ref_arr, const char* func_name,
                          bool is_local_var, struct list* local_var_refs,
                          struct list* non_local_refs);

static char* generate_struct_key(struct list* struct_hierarchy);


static hash_map func_vars_visited = map_create();

struct func_var_entry {
  struct list* return_hierarchy;
  struct list* output_args;
};

int main(int argc, char* argv[]) {
  check_out_of_scope = map_create();
  chdir("../linux-5.15.152");

  struct list* struct_hierarchy;
  char* var_name = var_find_knob_var("busy_poll", &struct_hierarchy);

  struct list* return_struct_hierarchy;
  struct list* output_vars;
  struct list* funcs = var_find_func_refs(var_name, struct_hierarchy,
                                          &return_struct_hierarchy, &output_vars);
  struct call_graph* graph = call_graph_create();
  for (struct list_node* curr = funcs->head; curr != NULL; curr = curr->next) {
    printf("%s, ", (char*) curr->payload);
    call_graph_add_root(graph, (char*) curr->payload);
  }
  printf("\n");
  expand_call_graph(graph, funcs);
  call_graph_dump(graph, "busy_poll");
  call_graph_dump_dot(graph, "busy_poll.dot");
  return EXIT_SUCCESS;
}

char* var_find_knob_var(const char* knob, struct list** struct_hierarchy) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L4 =\\ \\\"%s\\\"", knob);
  FILE* f = popen(cmd, "r");
  if (f == NULL) {
    perror("Failed to run cscope query: ");
    return NULL;
  }

  char* result = NULL;
  size_t len = 0;
  int ret = getline(&result, &len, f);
  if (ret < 0) {
    pclose(f);
    free(result);
    perror("Failed to read cscope output: ");
    return NULL;
  }
  pclose(f);

  char** result_arr;
  utils_split_str(result, &result_arr);
  free(result);
  
  char* file_path = result_arr[0];
  int line_num = atoi(result_arr[2]);
  char* var_line = utils_read_file_line(file_path, line_num);
  utils_free_str_arr(result_arr);
  
  char** var_line_arr;
  utils_split_str(var_line, &var_line_arr);
  free(var_line);
  
  char* trimmed_var_name = utils_trim_str(var_line_arr[1]);
  char* var_name = trimmed_var_name;
  utils_truncate_str(var_name, -1);
  if (var_name[0] == '&'){
    var_name++;
  }
  if (var_name != trimmed_var_name) {
    char* new_var_name = (char*) malloc(strlen(var_name) + 1);
    strncpy(new_var_name, var_name, strlen(var_name) + 1);
    utils_free_if_different(trimmed_var_name, var_line_arr[1]);
    var_name = new_var_name;
  }
  printf("%s\n", var_name);

  char* root_var_name;
  *struct_hierarchy = struct_get_struct_hierarchy(var_name, &root_var_name);

  utils_free_if_both_different(var_name, var_line_arr[1], root_var_name);
  if (root_var_name == var_line_arr[1]) {
    root_var_name = (char*) malloc(strlen(var_line_arr[1]) + 1);
    strncpy(root_var_name, var_line_arr[1], strlen(var_line_arr[1]) + 1);
  }
  utils_free_str_arr(var_line_arr);
  return root_var_name;
}

struct list* var_find_func_refs(const char* var_name, struct list* struct_hierarchy,
                                struct list** return_struct_hierarchy,
                                struct list** output_vars) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L0 %s", var_name);
  struct list* var_refs = utils_get_cscope_output(cmd);

  hash_map func_ptrs = map_create();
  struct list* funcs = var_get_func_refs(var_name, struct_hierarchy, var_refs,
                                         true, NULL, func_ptrs,
                                         return_struct_hierarchy, output_vars);

  map_free(func_ptrs);
  list_free_nodes(var_refs);
  return funcs;
}

struct list* var_get_func_refs(const char* var_name, struct list* struct_hierarchy,
                               struct list* var_refs, bool is_global,
                               const char* func_name, hash_map func_ptrs,
                               struct list** return_struct_hierarchy,
                               struct list** output_vars) {
  //if (func_name != NULL &&
  //    var_contains_func_var_visited(func_name, var_name, return_struct_hierarchy,
  //                                  output_vars)) {
  //  return list_create();
  //}
  
  struct list* funcs = list_create();
  *output_vars = list_create();
  *return_struct_hierarchy = NULL;
  bool get_func_from_ref = func_name == NULL;

  for (struct list_node* var_ref_node = var_refs->head; var_ref_node != NULL;
       var_ref_node = var_ref_node->next) {
    char* var_ref = (char*) var_ref_node->payload;
    printf("%s\n", var_ref);
    const char** var_ref_arr;
    size_t var_ref_arr_len = utils_split_str(var_ref, (char***) &var_ref_arr);
    if (get_func_from_ref) {
      func_name = var_ref_arr[1];
    }
    if (strstr(var_ref, "include/linux/module.h within_module_core 571 return (unsigned long)mod->core_layout.base <= addr &&") != NULL) {
      int test = 1;
    }
    char* san_var_ref = sanitize_remove_casts(var_ref);
    utils_free_if_different(var_ref, san_var_ref);
    char* full_var_ref = file_get_multiline_expr(san_var_ref, var_ref_arr);
    utils_free_if_different(san_var_ref, full_var_ref);
    var_ref = full_var_ref;

    if (strcmp(func_name, "devinet_init_net") == 0) {
      int test = 1;
    }
    
    if (strcmp(func_name, "<global>") != 0 &&
        (!is_global || !map_contains(check_out_of_scope, func_name) ||
         !list_contains_str((struct list*) map_get(check_out_of_scope, func_name), var_name))
      && check_is_ref(var_ref, var_name, func_name, is_global) &&
        !check_is_asm_block(var_ref)) {
      printf("Function: %s Variable: %s Struct Hierarchy: ", func_name, var_name);
      for (struct list_node* curr = struct_hierarchy->head; curr != NULL; curr = curr->next) {
        printf("%s, ", (char*) curr->payload);
      }
      printf("\n");
      // TODO: remove false positives for function calls and assignments
      struct list* additional_funcs;
      struct list* additional_output_args;
      struct list* return_hierarchy;
      if (check_is_func(var_ref) && !check_is_var_declaration(func_name, var_ref)) {
        additional_funcs = func_handle_func_call(var_name, struct_hierarchy,
                                                 var_ref, var_ref_arr,
                                                 var_ref_arr_len, func_name,
                                                 func_ptrs, &return_hierarchy,
                                                 &additional_output_args);
      } else {
        additional_funcs = assignment_handle_var_assignment(func_name, var_ref,
                                                            var_ref_arr,
                                                            var_ref_arr_len,
                                                            var_name,
                                                            struct_hierarchy,
                                                            false, func_ptrs,
                                                            &return_hierarchy,
                                                            &additional_output_args);
      }
      var_func_extend_unique(funcs, additional_funcs);
      var_out_arg_extend_unique(*output_vars, additional_output_args); // TODO: properly free additional_output_args

      struct list_node* return_match_node;
      enum TokenReturnType return_match_type =
        token_get_return_match_node(var_ref, (const char**) var_ref_arr, var_name,
                                    struct_hierarchy, func_name,
                                    &return_match_node);
      if (return_match_type == VAR_RETURN) {
        *return_struct_hierarchy = list_copy(struct_hierarchy, return_match_node);
      } else if (return_hierarchy != NULL) {
        *return_struct_hierarchy = return_hierarchy;
      }

      struct list* struct_matches = struct_get_struct_matches(var_ref, var_name, struct_hierarchy);
      if (!list_contains_str(funcs, func_name) &&
          struct_has_full_match(struct_matches, struct_hierarchy->len == 0)) { // TODO: check this
        char* func_match = (char*) malloc(strlen(func_name) + 1);
        strncpy(func_match, func_name, strlen(func_name) + 1);
        if (func_match == NULL) {
          int test = 1;
        }
        list_append(funcs, func_match);
      }
      list_free_nodes(struct_matches);
    }
    utils_free_str_arr((char**) var_ref_arr);
    free(var_ref);
  }

  return funcs;
}

struct list* var_get_local_var_refs(const char* var_name, const char* func_name,
                                    const char** statement_arr, int statement_arr_len,
                                    bool is_func_declaration) {
  const char* original_var_name = var_name;
  var_name = struct_get_root_name(var_name);
  char cmd[256];
  sprintf(cmd, "cscope -d -L0 %s", var_name);
  struct list* var_refs = utils_get_cscope_output(cmd);

  bool is_local_var = false;
  struct list* local_var_refs = list_create();
  struct list* src_file_refs = list_create();
  struct list* non_local_refs = list_create();
  struct list* non_src_refs = list_create();
  for (struct list_node* var_ref_node = var_refs->head; var_ref_node != NULL;
       var_ref_node = var_ref_node->next) {
    const char* var_ref = (const char*) var_ref_node->payload;
    char** var_ref_arr;
    utils_split_str(var_ref, &var_ref_arr);
    if (strcmp(var_ref_arr[1], func_name) == 0) {
      is_local_var = get_local_ref(var_name, var_ref, (const char**) var_ref_arr,
                                   func_name, is_local_var, local_var_refs,
                                   non_local_refs);
    } else {
      list_append(non_local_refs, var_ref);
    }

    if (is_func_declaration && strcmp(var_ref_arr[0], statement_arr[0]) == 0) {
      list_append(src_file_refs, var_ref);
    } else {
      list_append(non_src_refs, var_ref);
    }
    utils_free_str_arr(var_ref_arr);
  }
  list_free_nodes(var_refs);

  if (is_local_var ||
      (utils_str_in_array((const char**) statement_arr, "#define", statement_arr_len) &&
       local_var_refs->len > 0)) {
    list_free(non_local_refs);
    list_free_nodes(src_file_refs);
    list_free_nodes(non_src_refs);
    utils_free_if_different((char*) var_name, original_var_name);
    return local_var_refs;
  } else if (local_var_refs->len == 0) {
    list_free_nodes(local_var_refs);
    list_free_nodes(non_local_refs);
    list_free(non_src_refs);

    ssize_t func_start_line;
    ssize_t func_end_line = 0;
    if (is_func_declaration) {
      func_start_line = atoi(statement_arr[2]);
      func_end_line = file_get_func_end_line(statement_arr[0], func_start_line);
    } else {
      func_end_line = file_get_func_from_src(statement_arr[0], func_name, &func_start_line);
    }

    if (func_end_line < 0) {
      list_free(src_file_refs);
      utils_free_if_different((char*) var_name, original_var_name);
      return NULL;
    } else {
      local_var_refs = get_local_var_refs_from_src(src_file_refs, var_name, func_name,
                                                   statement_arr[0], func_start_line,
                                                   func_end_line);
      list_free_nodes(src_file_refs);
      utils_free_if_different((char*) var_name, original_var_name);
      return local_var_refs;
    }
  } else {
    list_free(local_var_refs);
    list_free(non_local_refs);
    list_free_nodes(src_file_refs);
    list_free_nodes(non_src_refs);
    utils_free_if_different((char*) var_name, original_var_name);
    return NULL;
  }
}

static struct list* get_local_var_refs_from_src(struct list* var_refs, const char* var_name,
                                                const char* func_name, const char* src_file,
                                                int func_start_line, int func_end_line) {
  struct list* local_var_refs = list_create();
  struct list* non_local_refs = list_create();
  bool is_local_var = false;
  for (struct list_node* var_ref_node = var_refs->head; var_ref_node != NULL;
       var_ref_node = var_ref_node->next) {
    const char* var_ref = (const char*) var_ref_node->payload;
    char** var_ref_arr;
    utils_split_str(var_ref, (char***) &var_ref_arr);
    int ref_line = atoi(var_ref_arr[2]);
    if (strcmp(var_ref_arr[0], src_file) == 0 && func_start_line <= ref_line &&
        func_end_line >= ref_line) {
      is_local_var = get_local_ref(var_name, var_ref, (const char**) var_ref_arr,
                                   func_name, is_local_var, local_var_refs,
                                   non_local_refs);
    } else {
      list_append(non_local_refs, var_ref);
    }
    utils_free_str_arr(var_ref_arr);
  }
  //list_free_nodes(var_refs);
  list_free(non_local_refs);

  if (is_local_var) {
    return local_var_refs;
  } else {
    list_free(local_var_refs);
    return NULL;
  }
}

static bool get_local_ref(const char* var_name, const char* var_ref, const char** var_ref_arr,
                          const char* func_name, bool is_local_var,
                          struct list* local_var_refs, struct list* non_local_refs) {
  const char* full_var_ref = file_get_multiline_expr(var_ref, var_ref_arr); // TODO: optimize this
  if (!is_local_var) {
    is_local_var = check_is_var_declaration(var_name, full_var_ref);
    if (is_local_var) {
      list_append(non_local_refs, var_ref);
      return true;
    }
  }

  if (check_is_ref(full_var_ref, var_name, func_name, false)) {
    list_append(local_var_refs, var_ref);
  }

  utils_free_if_different((char*) full_var_ref, var_ref);
  return is_local_var;
}

void var_func_extend_unique(struct list *funcs, struct list* additional_funcs) {
  for (struct list_node* additional_func = additional_funcs->head;
       additional_func != NULL; additional_func = additional_func->next) {
    if (!list_contains_str(funcs, (char*) additional_func->payload)) {
      //char* func = (char*) malloc(strlen((char*) additional_func->payload) + 1);
      //strncpy(func, (char*) additional_func->payload, strlen((char*) additional_func->payload) + 1);
      list_append(funcs, additional_func->payload);
    } else {
      free(additional_func->payload); // TODO: check the safety of this
    }
  }

  // TODO: check the safety of this
  list_free_nodes(additional_funcs);
}

void var_out_arg_extend_unique(struct list* out_args, struct list* additional_out_args) {
  for (struct list_node* additional_out_arg = additional_out_args->head;
       additional_out_arg != NULL; additional_out_arg = additional_out_arg->next) {
    struct output_arg* curr_out_arg = (struct output_arg*) additional_out_arg->payload;
    if (!func_list_contains_output_arg(out_args, curr_out_arg)) {
      list_append(out_args, curr_out_arg);
    } else {
      //func_free_out_arg(curr_out_arg);
    }
  }

  //list_free_nodes(additional_out_args);
}

void var_insert_func_var_visited(const char* func, const char* var,
                                 struct list* struct_hierarchy,
                                 struct list* return_hierarchy,
                                 struct list* output_args) {
  // TODO: handle function pointers
  struct func_var_entry* entry = (struct func_var_entry*) malloc(sizeof(struct func_var_entry));
  *entry = {return_hierarchy, output_args};
  hash_map var_map;
  if (map_contains(func_vars_visited, func)) {
    var_map = (hash_map) map_get(func_vars_visited, func);
  } else {
    var_map = map_create();
    map_insert(func_vars_visited, func, var_map);
  }

  map_insert(var_map, var, entry);

  //hash_map hierarchy_map;
  //if (map_contains(var_map, var)) {
  //  hierarchy_map = (hash_map) map_get(var_map, var);
  //} else {
  //  hierarchy_map = map_create();
  //  map_insert(var_map, var, hierarchy_map);
  //}

  //char* struct_key = generate_struct_key(struct_hierarchy);
  //map_insert(hierarchy_map, struct_key, entry);
}

static char* generate_struct_key(struct list* struct_hierarchy) {
  char* struct_key = (char*) malloc(256);
  size_t curr_index = 0;
  for (struct list_node* curr = struct_hierarchy->head; curr != NULL; curr = curr->next) {
    char* curr_segment = (char*) curr->payload;
    strncpy(struct_key + curr_index, curr_segment, strlen(curr_segment));
    curr_index += strlen(curr_segment);
    struct_key[curr_index] = '.';
    curr_index++;
  }
  struct_key[curr_index] = '\0';
  return struct_key;
}

bool var_contains_func_var_visited(const char* func, const char* var,
                                   struct list* struct_hierarchy,
                                   struct list** return_hierarchy,
                                   struct list** output_args) {
  if (!map_contains(func_vars_visited, func)) {
    return false;
  }

  hash_map var_map = (hash_map) map_get(func_vars_visited, func);
  if (!map_contains(var_map, var)) {
    return false;
  }

  //hash_map hierarchy_map = (hash_map) map_get(var_map, var);
  //char* struct_key = generate_struct_key(struct_hierarchy);
  //if (!map_contains(hierarchy_map, struct_key)) {
  //  free(struct_key);
  //  return false;
  //}

  struct func_var_entry* entry = (struct func_var_entry*) map_get(var_map, var);
  //free(struct_key);
  *return_hierarchy = entry->return_hierarchy;
  if (output_args != NULL) {
    *output_args = entry->output_args;
  }
  return true;
}

void var_remove_func_var_visited(const char* func, const char* var) {
  if (map_contains(func_vars_visited, func)) {
    hash_map var_map = (hash_map) map_get(func_vars_visited, func);
    if (map_contains(var_map, var)) {
      map_remove(var_map, var);
    }
  }
}
