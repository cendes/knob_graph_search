#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "hash_map.h"
#include "call_graph.h"
#include "utils.h"
#include "check_expression.h"
#include "struct_parse.h"
#include "func_call_parse.h"
#include "assignment_parse.h"
#include "file_search.h"
#include "var_search.h"

#define MAX_DEPTH 10

// TODO: Fix issue with fake recursive calls for macros

static const char* FUNCS_TO_IGNORE[] = {"main", "test", "init", "module_init", "module_exit", "MODULE_LICENSE"};

static void get_func_callers(struct call_graph* graph, const char* func_name,
                             const char* func_alias_root,
                             struct list* struct_hierarchy, size_t curr_depth);

static void get_callers_in_refs(struct call_graph* graph, const char* func_name,
                                const char* func_alias_root,
                                struct list* struct_hierarchy,
                                struct list* func_refs, size_t curr_depth);

static void check_func_calls(struct call_graph* graph, const char* func_name,
                            const char* func_alias_root,
                            struct list* struct_hierarchy, const char* caller_name,
                             const char* func_ref, size_t curr_depth);

void expand_call_graph(struct call_graph* graph, struct list* funcs) {
  for (struct list_node* curr = funcs->head; curr != NULL; curr = curr->next) {
    char* func_name = (char*) curr->payload;
    get_func_callers(graph, func_name, func_name, NULL, 0);
  }
}

static void get_func_callers(struct call_graph* graph, const char* func_name,
                             const char* func_alias_root,
                             struct list* struct_hierarchy, size_t curr_depth) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L0 %s", func_alias_root);
  struct list* func_refs = utils_get_cscope_output(cmd);
  get_callers_in_refs(graph, func_name, func_alias_root, struct_hierarchy,
                      func_refs, curr_depth);
}

static void get_callers_in_refs(struct call_graph* graph, const char* func_name,
                                const char* func_alias_root,
                                struct list* struct_hierarchy,
                                struct list* func_refs, size_t curr_depth) {
  if (curr_depth >= MAX_DEPTH ||
      utils_str_in_array(FUNCS_TO_IGNORE, func_name, UTILS_SIZEOF_ARR(FUNCS_TO_IGNORE))) {
    return;
  }
  if (strcmp(func_name, "SYSCALL_DEFINE3") == 0) {
    int test = 1;
  }
  for (struct list_node* curr_ref = func_refs->head; curr_ref != NULL; curr_ref = curr_ref->next) {
    char* func_ref = (char*) curr_ref->payload;
    char** func_ref_arr;
    size_t func_ref_arr_len = utils_split_str(func_ref, &func_ref_arr);
    func_ref = file_get_multiline_expr(func_ref, (const char**) func_ref_arr, false);
    if (!check_is_var_declaration(func_alias_root, func_ref)) {
      if (check_is_func(func_ref)) {
        if (strcmp(func_ref_arr[1], "<global>") == 0) {
          continue;
        }
        check_func_calls(graph, func_name, func_alias_root, struct_hierarchy,
                         func_ref_arr[1], func_ref, curr_depth);
      } else {
       /*  bool out_arg_assignment; */
    /*     char* func_ptr_var = assignment_get_assignment_var(func_ref_arr[1], */
    /*                                                        func_ref, */
    /*                                                        (const char**) func_ref_arr, */
    /*                                                        func_ref_arr_len, */
    /*                                                        func_alias_root, */
    /*                                                        false, */
    /*                                                        &out_arg_assignment); */
    /*     if (func_ptr_var != NULL) { */
    /*       char* func_ptr_root; */
    /*       struct list* func_ptr_hierarchy = struct_get_struct_hierarchy(func_ptr_var, &func_ptr_root); */
    /*       printf("Function pointer assignemnt: %s = %s\n", func_ptr_var, func_name); */
    /*       struct list* local_var_refs = var_get_local_var_refs(func_ptr_root, */
    /*                                                            func_ref_arr[1], */
    /*                                                            (const char**) func_ref_arr, */
    /*                                                            func_ref_arr_len, */
    /*                                                            false); */
    /*       if (local_var_refs == NULL) { */
    /*         get_func_callers(graph, func_name, func_ptr_root, func_ptr_hierarchy); */
    /*       } else { */
    /*         get_callers_in_refs(graph, func_name, func_ptr_root, */
    /*                             func_ptr_hierarchy, local_var_refs); */
    /*       } */
    /*     } */
    /*   } */
      } 
    }
  }
}

static void check_func_calls(struct call_graph* graph, const char* func_name,
                             const char* func_alias_root,
                             struct list* struct_hierarchy, const char* caller_name,
                             const char* func_ref, size_t curr_depth) {
  struct list* func_calls;
  struct list* funcs_start;
  struct list* var_args_indices;
  struct list* args_struct_matches;
  struct list* args_range;
  struct list* passed_hierarchy = struct_hierarchy == NULL ? list_create() : struct_hierarchy;
  struct list* call_args = func_get_func_call_args(func_alias_root, passed_hierarchy,
                                                   func_ref, &func_calls, &funcs_start,
                                                   &var_args_indices,
                                                   &args_struct_matches, &args_range);
  struct list_node* curr_var_args_indices = var_args_indices->head;
  struct list_node* curr_call_args = call_args->head;
  for (struct list_node* curr_call = func_calls->head; curr_call != NULL; curr_call = curr_call->next) {
    char* func_call_name = (char*) curr_call->payload;
    if (struct_hierarchy == NULL) {
      if (strcmp(func_alias_root, func_call_name) == 0 &&
          !call_graph_contains_call(graph, func_name, caller_name)) {
        call_graph_insert(graph, func_name, caller_name);
        printf("Node inserted: %s -> %s\n", func_name, caller_name);
        get_func_callers(graph, caller_name, caller_name, NULL, curr_depth + 1);
      }
    } else {
      struct list* call_matches = struct_get_struct_matches(func_call_name,
                                                            func_alias_root,
                                                            struct_hierarchy);
      if (struct_has_full_match(call_matches, struct_hierarchy->len == 0) &&
          !call_graph_contains_call(graph, func_name, caller_name)) {
        list_free_nodes(call_matches);
        call_graph_insert(graph, func_name, caller_name);
        printf("Node inserted: %s(alias %s) -> %s\n", func_name, func_alias_root, caller_name);
        get_func_callers(graph, caller_name, caller_name, NULL, curr_depth + 1);
      }
      //list_free_nodes(call_matches);
    }
  }
}
