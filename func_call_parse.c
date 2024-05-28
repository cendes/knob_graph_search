#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "hash_map.h"
#include "utils.h"
#include "check_expression.h"
#include "token_get.h"
#include "sanitize_expression.h"
#include "file_search.h"
#include "struct_parse.h"
#include "var_search.h"
#include "assignment_parse.h"
#include "func_call_parse.h"

static hash_map visited_func_ptr_args = map_create();

hash_map visited_func_args_decl = map_create();

hash_map visited_func_decls = map_create();

static struct list* get_func_args(const char* var_ref,
                                  size_t args_start_index,
                                  struct list** args_range);

static void append_arg(struct list* args_list, struct list* args_range,
                       const char* var_ref, size_t arg_start, size_t arg_end);

static struct list* get_func_args_declaration(const char* func_name,
                                              struct list* func_args,
                                              char*** func_declaration_arr,
                                              size_t* func_declaration_arr_len);

static struct list* get_func_declarations(const char* func_name,
                                          struct list** func_declarations_arr,
                                          struct list** func_declarations_arr_len);

static struct list* handle_memcpy(const char* var_name, const char** var_ref_arr,
                                  size_t var_ref_arr_len,
                                  const char* func_name, struct list* func_call_args,
                                  struct list* struct_hierarchy,
                                  struct list_node* src_struct_match,
                                  hash_map func_ptrs,
                                  char** assigned_root_name,
                                  struct list** assigned_hierarchy,
                                  struct list** return_hierarchy,
                                  struct list** output_args);

static char* get_ptr_from_func_return(const char* func_call,
                                      const char** var_ref_arr,
                                      size_t var_ref_arr_len, hash_map func_ptrs,
                                      struct list** return_hierarchy);

static hash_map handle_func_ptrs_passed(struct list* func_call_args,
                                        struct list* func_arg_names,
                                        struct list* func_ptr_args,
                                        hash_map func_ptrs);

static struct list* handle_output_args(const char* func_name,
                                       struct list* func_arg_names,
                                       const char* func_call,
                                       struct list* func_call_args,
                                       struct list* call_arg_names,
                                       struct list* call_output_args,
                                       const char** var_ref_arr,
                                       size_t var_ref_arr_len,
                                       hash_map func_ptrs,
                                       struct list** additional_output_args,
                                       struct list** return_hierarchy);

static ssize_t get_func_arg_index(struct list_node* args_range, size_t func_start,
                                  size_t* arg_idx);

struct list* func_handle_func_call(const char* var_name,
                                   struct list* struct_hierarchy,
                                   const char* var_ref, const char** var_ref_arr,
                                   size_t var_ref_arr_len, const char* func_name,
                                   hash_map func_ptrs,
                                   struct list** return_struct_hierarchy,
                                   struct list** output_vars) {
  if (strcmp(func_name, "get_boot_seed") == 0) {
    int test = 1;
  }
  struct list* funcs = list_create();
  *return_struct_hierarchy = NULL;
  *output_vars = list_create();
  struct list* calling_func_args = func_get_curr_func_arg_names(func_name);

  struct list* func_calls;
  struct list* funcs_start;
  struct list* var_args_indices;
  struct list* struct_matches;
  struct list* args_range;
  struct list* func_call_args = func_get_func_call_args(var_name, struct_hierarchy,
                                                        var_ref, &func_calls,
                                                        &funcs_start,
                                                        &var_args_indices,
                                                        &struct_matches,
                                                        &args_range);

  struct list_node* curr_call_args = func_call_args->head;
  struct list_node* curr_func_start = funcs_start->head;
  struct list_node* curr_args_indices = var_args_indices->head;
  struct list_node* curr_struct_matches = struct_matches->head;
  struct list_node* curr_args_range = args_range->head;
  for (struct list_node* curr_call = func_calls->head; curr_call != NULL;
       curr_call = curr_call->next) {
    char* func_call = (char*) curr_call->payload;
    if (strcmp(func_call, "get_boot_seed") == 0) {
      int test = 1;
    }
    if (map_contains(func_ptrs, func_call)) {
      curr_call->payload = map_get(func_ptrs, func_call);
      //free(func_call);
      func_call = (char*) curr_call->payload;
    }

    struct list* args_indices = (struct list*) curr_args_indices->payload;
    struct list* args_struct_matches = (struct list*) curr_struct_matches->payload;
    if (strcmp(func_call, "pr_err") == 0) {
      int test = 1;
    }
    
    struct list* curr_func_return_hierarchy = NULL;
    struct list* additional_output_args;
    // TODO: check functions visited cache
    if (strcmp(func_call, "memcpy") == 0) {
      if (list_contains_val(args_indices, 1)) {
        struct list_node* src_struct_match;
        if (list_contains_val(args_indices, 0)) {
          src_struct_match = (struct list_node*) args_struct_matches->head->next->payload;
        } else {
          src_struct_match = (struct list_node*) args_struct_matches->head->payload;
        }
        char* assigned_root_name;
        struct list* assigned_hierarchy;
        struct list* additional_funcs = handle_memcpy(var_name, var_ref_arr,
                                                      var_ref_arr_len, func_name,
                                                      (struct list*) curr_call_args->payload,
                                                      struct_hierarchy, src_struct_match,
                                                      func_ptrs,
                                                      &assigned_root_name,
                                                      &assigned_hierarchy,
                                                      &curr_func_return_hierarchy,
                                                      &additional_output_args);
        if (additional_funcs != NULL) {
          var_func_extend_unique(funcs, additional_funcs);
        }
        if (check_is_arg_assignment(assigned_root_name, calling_func_args)) {
          assignment_append_out_arg(additional_output_args, (char*) var_name, assigned_hierarchy);
        }
        var_out_arg_extend_unique(*output_vars, additional_output_args);
      }
    } else {
      struct list* func_arg_names;
      struct list* func_ptr_args;
      char** func_declaration_arr;
      size_t func_declaration_arr_len;
      if (map_contains(visited_func_decls, func_call)) {
        if (!map_contains(visited_func_args_decl, func_call)) {
          continue;
        }
        
        char* func_declaration = (char*) map_get(visited_func_decls, func_call);
        struct list* func_arg_decls = (struct list*) map_get(visited_func_args_decl, func_call);
        func_declaration_arr_len = utils_split_str(func_declaration, &func_declaration_arr);
        func_arg_names = func_get_func_args_name(func_call, func_arg_decls,
                                                 (const char**) func_declaration_arr,
                                                 func_declaration_arr_len);
        if (map_contains(visited_func_ptr_args, func_call)) {
          func_ptr_args = (struct list*) map_get(visited_func_ptr_args, func_call);
        } else {
          func_ptr_args = list_create();
        }
      } else {
        func_arg_names = func_extract_func_arg_names(func_call,
                                                     (struct list*) curr_call_args->payload,
                                                     &func_ptr_args,
                                                     &func_declaration_arr,
                                                     &func_declaration_arr_len);
      }
      
      if (func_arg_names->len == 0) {
        list_free(func_arg_names);
        list_free(func_ptr_args);
        continue;
      }

      // TODO: this could be more memory efficient if we only got them for visited args
      struct list* func_arg_refs = func_get_func_args_refs(func_call, func_arg_names,
                                                           args_indices,
                                                           (const char**) func_declaration_arr,
                                                           func_declaration_arr_len,
                                                           true);

      hash_map func_ptrs_passed =
        handle_func_ptrs_passed((struct list*) curr_call_args->payload,
                                func_arg_names, func_ptr_args, func_ptrs);

      struct list* func_args_range = (struct list*) curr_args_range->payload;
      struct list_node* curr_arg_struct_match = args_struct_matches->head;
      struct list_node* curr_func_arg_range = func_args_range->head;
      struct list_node* curr_var_refs = func_arg_refs->head;
      for (struct list_node* curr_arg_index = args_indices->head;
           curr_arg_index != NULL; curr_arg_index = curr_arg_index->next) {
        size_t arg_index = (size_t) curr_arg_index->payload;
        char* curr_arg_name = (char*) list_get(func_arg_names, arg_index);
        struct list* curr_arg_refs = (struct list*) curr_var_refs->payload;
        struct list_node* arg_struct_match =
          (struct list_node*) curr_arg_struct_match->payload;
        struct list* arg_struct_hierarchy = list_copy(struct_hierarchy, arg_struct_match);
        struct list* return_var_hierarchy;
        struct list* output_args;
        char* func_var_code = (char*) malloc(256);
        sprintf(func_var_code, "%s,%s", func_call, curr_arg_name);
        if (!var_contains_func_var_visited(func_name, func_var_code,
                                           arg_struct_hierarchy,
                                           &return_var_hierarchy, &output_args)) {
          var_insert_func_var_visited(func_name, func_var_code,
                                      arg_struct_hierarchy, NULL, NULL);
          struct list* additional_funcs = var_get_func_refs(curr_arg_name,
                                                            arg_struct_hierarchy,
                                                            curr_arg_refs, false,
                                                            func_call,
                                                            func_ptrs_passed,
                                                            &return_var_hierarchy,
                                                            &output_args);
          //var_insert_func_var_visited(func_name, func_var_code,
          //                            arg_struct_hierarchy, return_var_hierarchy,
          //                           output_args);
          var_remove_func_var_visited(func_name, func_var_code);
          free(func_var_code);
          var_func_extend_unique(funcs, additional_funcs);
          list_free_nodes(arg_struct_hierarchy);
          list_free_nodes(curr_arg_refs);
        } else {
          list_free(curr_arg_refs); 
        }
        
        if (output_args == NULL) {
          output_args = list_create();
        }
        
        //map_free(func_ptrs_passed); // TODO: maybe only free the payload?
        struct list* additional_funcs = handle_output_args(func_name,
                                                           calling_func_args,
                                                           func_call,
                                                           (struct list*) curr_call_args->payload,
                                                           func_arg_names,
                                                           output_args,
                                                           var_ref_arr,
                                                           var_ref_arr_len,
                                                           func_ptrs,
                                                           &additional_output_args,
                                                           &return_var_hierarchy);
        //list_custom_free(output_args, &func_free_out_arg);
        var_func_extend_unique(funcs, additional_funcs);
        var_out_arg_extend_unique(*output_vars, additional_output_args);
        if (return_var_hierarchy != NULL) {
          struct list* additional_output_args;
          additional_funcs = assignment_handle_var_assignment(func_name,
                                                              var_ref,
                                                              var_ref_arr,
                                                              var_ref_arr_len,
                                                              var_name,
                                                              return_var_hierarchy,
                                                              true, func_ptrs,
                                                              &curr_func_return_hierarchy,
                                                              &additional_output_args);
          var_func_extend_unique(funcs, additional_funcs);
          var_out_arg_extend_unique(*output_vars, additional_output_args);
          
          size_t arg_idx;
          ssize_t func_idx = get_func_arg_index(curr_args_range->next,
                                                (size_t) curr_func_start->payload,
                                                &arg_idx);
          if (func_idx >= 0) {
            struct list* super_func_args =
              (struct list*) list_get(var_args_indices, func_idx);
            list_append(super_func_args, (void*) arg_idx);
            struct list_node* curr_segment = struct_hierarchy->head;
            struct list_node* prev_segment = NULL;
            struct list_node* return_segment = return_var_hierarchy->head;
            while (curr_segment != NULL && return_segment != NULL &&
                   strcmp((char*) curr_segment->payload,
                          (char*) return_segment->payload) == 0) {
              curr_segment = curr_segment->next;
              prev_segment = curr_segment;
              return_segment = return_segment->next;
            }
            struct list* arg_struct_matches =
              (struct list*) list_get(struct_matches, func_idx);
            list_append(arg_struct_matches, prev_segment);
          } else {
            *return_struct_hierarchy = return_var_hierarchy;
          }
        }
        curr_arg_struct_match = curr_arg_struct_match->next;
        curr_func_arg_range = curr_func_arg_range->next;
        curr_var_refs = curr_var_refs->next;
      }
      list_free(func_args_range);
      list_free_nodes(func_arg_refs);
      list_free_nodes(func_arg_names); // TODO: why can't I list_free this???
      //list_free_nodes(func_ptr_args);
    }

    if (curr_func_return_hierarchy != NULL) {
      *return_struct_hierarchy = curr_func_return_hierarchy;
    }    

    curr_call_args = curr_call_args->next;
    curr_func_start = curr_func_start->next;
    curr_args_indices = curr_args_indices->next;
    curr_struct_matches = curr_struct_matches->next;
    curr_args_range = curr_args_range->next;
    list_free_nodes(args_struct_matches);
    list_free_nodes(args_indices);
  }
  list_free_nodes(func_calls);
  list_free_nodes(funcs_start);
  list_free_nodes(var_args_indices);
  list_free_nodes(struct_matches);
  list_free_nodes(args_range);
  list_free_nodes(func_call_args);

  return funcs;
}

struct list* func_get_curr_func_arg_names(const char* func_name) {
  char** func_declaration_arr;
  size_t func_declaration_arr_len; 
  if (map_contains(visited_func_decls, func_name)) {
    char* func_declaration = (char*) map_get(visited_func_decls, func_name);
    func_declaration_arr_len = utils_split_str(func_declaration, &func_declaration_arr);
    struct list* args_declaration = (struct list*) map_get(visited_func_args_decl, func_name);
    return func_get_func_args_name(func_name, args_declaration, (const char**) func_declaration_arr,
                                   func_declaration_arr_len);
  } else {
    struct list* func_ptr_args;
    return func_extract_func_arg_names(func_name, NULL, &func_ptr_args,
                                       &func_declaration_arr,
                                       &func_declaration_arr_len);
  }
}

struct list* func_get_func_call_args(const char* var_name,
                                     struct list* struct_hierarchy,
                                     const char* var_ref, struct list** funcs,
                                     struct list** funcs_start,
                                     struct list** var_args_indices,
                                     struct list** args_struct_matches,
                                     struct list** args_range) {
  struct list* args = list_create();
  *funcs = list_create();
  *funcs_start = list_create();
  *var_args_indices = list_create();
  *args_struct_matches = list_create();
  *args_range = list_create();

  size_t* args_start_indices;
  size_t num_start_indices = utils_get_char_occurences(var_ref, '(',
                                                       &args_start_indices);
  for (size_t i = 0; i < num_start_indices; i++) {
    char* func_name = token_get_func_name(var_ref, args_start_indices[i]);
    if (func_name == NULL) {
      continue;
    }

    struct list* func_args_range;
    struct list* args_list = get_func_args(var_ref, args_start_indices[i],
                                           &func_args_range);
    struct list* var_arg_indices = list_create();
    struct list* arg_struct_matches = list_create();
    for (struct list_node* curr_arg = args_list->head; curr_arg != NULL;
         curr_arg = curr_arg->next) {
      char* arg = (char*) curr_arg->payload;
      char* var_name_ptr = strstr(arg, var_name);
      size_t var_name_index = var_name_ptr - arg;
      if (var_name_ptr != NULL && !check_is_func(arg) &&
          check_is_token_match(arg, var_name_index, strlen(var_name))) {
        struct list* struct_matches = struct_get_struct_matches(arg, var_name, struct_hierarchy);
        if (struct_matches->len > 0) {
          list_append(var_arg_indices, (void*) curr_arg->index);
          list_append(arg_struct_matches, struct_get_highest_match(struct_matches));
        }
        list_free_nodes(struct_matches);
      }
    }
    list_insert(args, args_list);
    list_insert(*funcs, func_name);
    list_insert(*funcs_start, (void*) (args_start_indices[i] - 1));
    list_insert(*var_args_indices, var_arg_indices);
    list_insert(*args_struct_matches, arg_struct_matches);
    list_insert(*args_range, func_args_range);
  }
  free(args_start_indices);

  return args;
}

static struct list* get_func_args(const char* var_ref,
                                  size_t args_start_index,
                                  struct list** args_range) {
  struct list* args_list = list_create();
  *args_range = list_create();

  size_t curr_index = args_start_index + 1;
  size_t expr_start = curr_index;
  while (curr_index < strlen(var_ref) && var_ref[curr_index] != ')') {
    if (var_ref[curr_index] == ',') {
      append_arg(args_list, *args_range, var_ref, expr_start, curr_index);
      expr_start = curr_index + 1;
    } else if (var_ref[curr_index] == '(' || var_ref[curr_index] == '[') {
      curr_index = check_recur_with_parenthesis(var_ref, curr_index + 1,
                                                var_ref[curr_index]);
    }
    curr_index++;
  }
  append_arg(args_list, *args_range, var_ref, expr_start, curr_index);

  return args_list;
}

static void append_arg(struct list* args_list, struct list* args_range,
                       const char* var_ref, size_t arg_start, size_t arg_end) {
  size_t arg_len = arg_end - arg_start;
  if (arg_len == 0) {
    return;
  }
  
  char* arg = (char*) malloc(arg_len + 1);
  strncpy(arg, var_ref + arg_start, arg_len);
  arg[arg_len] = '\0';
  char* untrimmed_arg = arg;
  arg = utils_trim_str(untrimmed_arg);
  utils_free_if_different(untrimmed_arg, arg);
  list_append(args_list, arg);
  
  struct index_range* arg_range =
    (struct index_range*) malloc(sizeof(struct index_range));
  *arg_range = {arg_start, arg_end - 1};
  list_append(args_range, arg_range);
}

struct list* func_extract_func_arg_names(const char* func_name,
                                         struct list* func_args,
                                         struct list** func_ptr_args,
                                         char*** func_declaration_arr,
                                         size_t* func_declaration_arr_len) {
  struct list* args_declaration = get_func_args_declaration(func_name, func_args,
                                                            func_declaration_arr,
                                                            func_declaration_arr_len);
  if (args_declaration == NULL || func_declaration_arr == NULL) {
    *func_ptr_args = list_create();
    return list_create();
  }

  if (strcmp(func_name, "init_header") == 0) {
    int test = 1;
  }
  if (strcmp(func_name, "pr_err") == 0) {
    int test = 1;
  }
  map_insert(visited_func_args_decl, func_name, args_declaration);
  

  *func_ptr_args = list_create();
  for (struct list_node* curr = args_declaration->head; curr != NULL;
       curr = curr->next) {
    if (check_is_func_ptr((char*) curr->payload)) {
      list_append(*func_ptr_args, (void*) curr->index);
    }
  }

  struct list* func_arg_names = func_get_func_args_name(func_name, args_declaration,
                                                        (const char**) *func_declaration_arr,
                                                        *func_declaration_arr_len);
  
  if ((*func_ptr_args)->len > 0) {
    map_insert(visited_func_ptr_args, func_name, *func_ptr_args);
  }
  return func_arg_names;
}


static struct list* get_func_args_declaration(const char* func_name,
                                              struct list* func_args,
                                              char*** func_declaration_arr,
                                              size_t* func_declaration_arr_len) {
  if (strcmp(func_name, "should_fail_usercopy") == 0) {
    int test = 1;
  }
  struct list* func_declarations_arr;
  struct list* func_declarations_arr_len;
  struct list* func_declarations = get_func_declarations(func_name,
                                                         &func_declarations_arr,
                                                         &func_declarations_arr_len);
  if (func_declarations->len == 0) {
    list_free(func_declarations);
    list_free(func_declarations_arr);
    *func_declaration_arr = NULL;
    *func_declaration_arr_len = 0;
    return NULL;
  }

  struct list* args_declaration = NULL;
  *func_declaration_arr = NULL;
  *func_declaration_arr_len = 0;

  struct list_node* curr_declaration;
  struct list_node* curr_declaration_arr = func_declarations_arr->head;
  struct list_node* curr_declaration_arr_len = func_declarations_arr_len->head;
  for (curr_declaration = func_declarations->head; curr_declaration != NULL;
       curr_declaration = curr_declaration->next) {
    char* func_declaration = (char*) curr_declaration->payload;
    
    size_t args_start_index = strchr(func_declaration, '(') - func_declaration;
    struct list* args_range;
    args_declaration = get_func_args(func_declaration, args_start_index, &args_range);
    list_free(args_range);

    size_t num_declaration_args;
    if (args_declaration->len == 1 &&
        strcmp((char*) args_declaration->head->payload, "void") == 0) {
      num_declaration_args = 0;
    } else {
      num_declaration_args = args_declaration->len;
    }

    if ((func_args == NULL || num_declaration_args == func_args->len) &&
        (strstr(func_declaration, "#define") != NULL ||
         check_has_arg_names(args_declaration))) {
      map_insert(visited_func_decls, func_name, func_declaration);
      if (num_declaration_args == 0) {
        list_free(args_declaration);
        args_declaration = NULL;
        utils_free_str_arr((char**) curr_declaration_arr->payload);
      } else {
        *func_declaration_arr = (char**) curr_declaration_arr->payload;
        *func_declaration_arr_len = (size_t) curr_declaration_arr_len->payload;
      }
      break;
    } else {
      list_free(args_declaration);
      args_declaration = NULL;
      free(func_declaration);
      utils_free_str_arr((char**) curr_declaration_arr->payload);
    }
    curr_declaration_arr = curr_declaration_arr->next;
    curr_declaration_arr_len = curr_declaration_arr_len->next;
  }

  if (curr_declaration != NULL) {
    curr_declaration_arr = curr_declaration_arr->next;
    for (curr_declaration = curr_declaration->next; curr_declaration != NULL;
         curr_declaration = curr_declaration->next) {
      free(curr_declaration->payload);
      utils_free_str_arr((char**) curr_declaration_arr->payload);
      curr_declaration_arr = curr_declaration_arr->next;
    }
  }
  list_free_nodes(func_declarations);
  list_free_nodes(func_declarations_arr);
  list_free_nodes(func_declarations_arr_len);
  
  return args_declaration;
}

static struct list* get_func_declarations(const char* func_name,
                                          struct list** func_declarations_arr,
                                          struct list** func_declarations_arr_len) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L0 %s", func_name);
  struct list* func_refs = utils_get_cscope_output(cmd);

  if (strcmp(func_name, "pr_alert") == 0) {
    int test = 1;
  }

  struct list* extern_declarations = list_create();
  struct list* extern_declarations_arr = list_create();
  struct list* extern_declarations_arr_len = list_create();
  struct list* header_declarations = list_create();
  struct list* header_declarations_arr = list_create();
  struct list* header_declarations_arr_len = list_create();
  struct list* func_declarations = list_create();
  *func_declarations_arr = list_create();
  *func_declarations_arr_len = list_create();
  for (struct list_node* curr = func_refs->head; curr != NULL; curr = curr->next) {
    char* func_ref = (char*) curr->payload;
    char** func_ref_arr;
    if (strstr(func_ref, "kernel/sched/completion.c complete 28 void complete(struct completion *x)") != NULL) {
      int test = 1;
    }
    size_t func_ref_arr_len = utils_split_str(func_ref, &func_ref_arr);
    char* full_func_ref = file_get_multiline_expr(func_ref,
                                                  (const char**) func_ref_arr);
    utils_free_if_different(func_ref, full_func_ref);
    func_ref = full_func_ref;

    if (strcmp(func_ref, "kernel/rcu/refscale.c VERBOSE_SCALEOUT 47 do { if  pr_alert(\"\" SCALE_FLAG s, scale_type, ## x); } while (0)") == 0) {
      int test = 1;
    }

    if (check_is_func(func_ref) && check_is_var_declaration(func_name, func_ref)) { // TODO: Bug in check is var declaration
      if (check_is_extern(func_ref)) {
        list_append(extern_declarations, full_func_ref);
        list_append(extern_declarations_arr, func_ref_arr);
        list_append(extern_declarations_arr_len, (void*) func_ref_arr_len);
      } else if (strstr(func_ref_arr[0], ".h")) {
        list_append(header_declarations, full_func_ref);
        list_append(header_declarations_arr, func_ref_arr);
        list_append(header_declarations_arr_len, (void*) func_ref_arr_len);
      } else {
        list_append(func_declarations, full_func_ref);
        list_append(*func_declarations_arr, func_ref_arr);
        list_append(*func_declarations_arr_len, (void*) func_ref_arr_len);
      }
    } else {
      free(func_ref);
      utils_free_str_arr(func_ref_arr);
    }
  }

  void (*free_str_arr_ptr)(void*) = (void (*)(void*) )&utils_free_str_arr;
  if (func_declarations->len == 0) {
    if (header_declarations->len > 0) {
      list_free(func_declarations);
      list_custom_free(*func_declarations_arr, free_str_arr_ptr);
      list_free_nodes(*func_declarations_arr_len);
      func_declarations = header_declarations;
      *func_declarations_arr = header_declarations_arr;
      *func_declarations_arr_len = header_declarations_arr_len;
      list_free(extern_declarations);
      list_custom_free(extern_declarations_arr, free_str_arr_ptr);
      list_free_nodes(extern_declarations_arr_len);
    } else if (extern_declarations->len > 0) {
      list_free(func_declarations);
      list_custom_free(*func_declarations_arr, free_str_arr_ptr);
      list_free_nodes(*func_declarations_arr_len);
      func_declarations = extern_declarations;
      *func_declarations_arr = extern_declarations_arr;
      *func_declarations_arr_len = extern_declarations_arr_len;
      list_free(header_declarations);
      list_custom_free(header_declarations_arr, free_str_arr_ptr);
      list_free_nodes(header_declarations_arr_len);
    }
  } else {
    list_free(header_declarations);
    list_custom_free(header_declarations_arr, free_str_arr_ptr);
    list_free_nodes(header_declarations_arr_len);
    list_free(extern_declarations);
    list_custom_free(extern_declarations_arr, free_str_arr_ptr);
    list_free_nodes(extern_declarations_arr_len);
  }

  list_free_nodes(func_refs);
  return func_declarations;
}

struct list* func_get_func_args_name(const char* func_name,
                                     struct list* args_declaration,
                                     const char** statement_arr,
                                     size_t statement_arr_len) {
  struct list* func_arg_names = list_create();

  for (struct list_node* curr = args_declaration->head; curr != NULL;
       curr = curr->next) {
    char* san_arg_declaration = utils_trim_str((char*) curr->payload);
    if (strstr(san_arg_declaration, "...") != NULL) {
      utils_free_if_different(san_arg_declaration, curr->payload);
      list_free_nodes(func_arg_names); // TODO: find a way of freeing this properly
      return list_create();
    }
    char* arg_name;
    if (utils_str_in_array((const char**) statement_arr, "#define",
                           statement_arr_len) ||
        strchr(san_arg_declaration, ' ') == NULL) {
      arg_name = san_arg_declaration;
    } else {
      if (check_is_func_ptr(san_arg_declaration)) {
        arg_name = token_get_func_ptr_name(san_arg_declaration);
      } else {
        char** arg_declaration_arr;
        size_t num_tokens = utils_split_str(san_arg_declaration, &arg_declaration_arr);
        arg_name = sanitize_extract_varname(arg_declaration_arr[num_tokens - 1]); // TODO: this could be an issue
        utils_free_str_arr(arg_declaration_arr);
      }
    }

    if (strlen(arg_name) == 0 || !check_is_valid_varname(arg_name)) {
      utils_free_if_both_different(san_arg_declaration, curr->payload, arg_name);
      //free(arg_name);
      list_free_nodes(func_arg_names); // TODO: find a way of freeing this properly
      return list_create();
    }

    list_append(func_arg_names, arg_name);
    utils_free_if_both_different(san_arg_declaration, curr->payload, arg_name);
  }

  return func_arg_names;
}

struct list* func_get_func_args_refs(const char* func_name,
                                     struct list* func_arg_names,
                                     struct list* var_args_indices,
                                     const char** statement_arr,
                                     size_t statement_arr_len,
                                     bool is_func_declaration) {
  struct list* func_arg_refs = list_create();
  for (struct list_node* curr = var_args_indices->head; curr != NULL; curr = curr->next) {
    size_t curr_arg_index = (size_t) curr->payload;
    char* arg_name = (char*) list_get(func_arg_names, curr_arg_index);
    struct list* arg_refs;
    arg_refs = var_get_local_var_refs(arg_name, func_name,
                                      (const char**) statement_arr,
                                      statement_arr_len, is_func_declaration);
    if (arg_refs == NULL) {
      arg_refs = list_create();
    }
    list_append(func_arg_refs, arg_refs);
  }

  return func_arg_refs;
}

static struct list* handle_memcpy(const char* var_name, const char** var_ref_arr,
                                  size_t var_ref_arr_len,
                                  const char* func_name, struct list* func_call_args,
                                  struct list* struct_hierarchy,
                                  struct list_node* src_struct_match,
                                  hash_map func_ptrs,
                                  char** assigned_root_name,
                                  struct list** assigned_hierarchy,
                                  struct list** return_hierarchy,
                                  struct list** output_args) {
  char* dest_var = (char*) func_call_args->head->payload;
  //char* actual_dest;
  if (check_is_func(dest_var)) {
    *assigned_root_name = get_ptr_from_func_return(dest_var, var_ref_arr,
                                                   var_ref_arr_len, func_ptrs,
                                                   assigned_hierarchy);
  } else {
    *assigned_hierarchy = struct_get_struct_hierarchy(dest_var, assigned_root_name);
    struct list* matched_hierarchy = list_copy(struct_hierarchy, src_struct_match);
    struct list* final_hierarchy = list_combine(*assigned_hierarchy, matched_hierarchy);
    list_free_nodes(matched_hierarchy);
    list_free_nodes(*assigned_hierarchy);
    *assigned_hierarchy = final_hierarchy;
  }

  if (*assigned_root_name != NULL) {
    if (!var_contains_func_var_visited(func_name, *assigned_root_name,
                                       *assigned_hierarchy, return_hierarchy,
                                       output_args)) {
      var_insert_func_var_visited(func_name, *assigned_root_name,
                                  *assigned_hierarchy, NULL, NULL);
      struct list* funcs = assignment_get_assigned_var_funcs(func_name,
                                                             *assigned_root_name,
                                                             *assigned_hierarchy,
                                                             var_ref_arr,
                                                             var_ref_arr_len,
                                                             func_ptrs,
                                                             return_hierarchy,
                                                             output_args);
      //var_insert_func_var_visited(func_name, *assigned_root_name,
      //                            *assigned_hierarchy, *return_hierarchy,
      //                            *output_args);
      var_remove_func_var_visited(func_name, *assigned_root_name);
      return funcs;
    } else {
      return NULL;
    }
  } else {
    *return_hierarchy = NULL;
    *output_args = list_create();
    return NULL;
  }
}

static char* get_ptr_from_func_return(const char* func_call, const char** var_ref_arr,
                                      size_t var_ref_arr_len, hash_map func_ptrs,
                                      struct list** return_hierarchy) {
  char* out_func_name = token_find_func_name(func_call);
  size_t args_start_index = strchr(func_call, '(') - func_call;
  struct list* args_range;
  struct list* arg_args = get_func_args(func_call, args_start_index, &args_range);
  list_free(args_range);

  for (struct list_node* curr = arg_args->head; curr != NULL; curr = curr->next) {
    char* arg_arg = (char*) curr->payload;
    struct list* arg_refs = var_get_local_var_refs(arg_arg, out_func_name,
                                                   var_ref_arr, var_ref_arr_len,
                                                   false);
    struct list* arg_return_hierarchy;
    struct list* output_args;
    struct list* funcs = var_get_func_refs(arg_arg, list_create(), arg_refs,
                                           false, out_func_name, func_ptrs,
                                           &arg_return_hierarchy, &output_args);
    list_free(funcs);
    list_free(output_args);
    list_free(arg_refs);
    if (return_hierarchy != NULL) {
      free(out_func_name);
      for (struct list_node* n = curr->next; n != NULL; n = n->next) {
        free(n->payload);
      }
      list_free_nodes(arg_args);
        
      char* root_name;
      struct list* assigned_hierarchy = struct_get_struct_hierarchy(arg_arg, &root_name);
      utils_free_if_different(root_name, arg_arg);
      *return_hierarchy = list_combine(assigned_hierarchy, arg_return_hierarchy);
      list_free_nodes(arg_return_hierarchy);
      list_free_nodes(assigned_hierarchy);
      return arg_arg;
    } else {
      free(arg_arg);
    }
  }

  free(out_func_name);
  list_free_nodes(arg_args);
  *return_hierarchy = NULL;
  return NULL;
}

static hash_map handle_func_ptrs_passed(struct list* func_call_args,
                                        struct list* func_arg_names,
                                        struct list* func_ptr_args,
                                        hash_map func_ptrs) {
  hash_map func_ptrs_passed = map_create();
  for (struct list_node* curr_func_ptr = func_ptr_args->head; curr_func_ptr != NULL;
       curr_func_ptr = curr_func_ptr->next) {
    size_t func_ptr_idx = (size_t) curr_func_ptr->payload;
    char* func_ptr_var = (char*) list_get(func_call_args, func_ptr_idx);
    if (strcmp(func_ptr_var, "NULL") == 0 || utils_isnumeric(func_ptr_var)) {
      continue;
    }
    
    char* func_ptr_arg_name = (char*) list_get(func_arg_names, func_ptr_idx);
    if (map_contains(func_ptrs, func_ptr_var)) {
      char* func_ptr_passed_name = (char*) map_get(func_ptrs, func_ptr_var);
      map_insert(func_ptrs_passed, func_ptr_arg_name, func_ptr_passed_name);
    } else {
      map_insert(func_ptrs_passed, func_ptr_arg_name, func_ptr_var);
    }
  }

  return func_ptrs_passed;
}

static struct list* handle_output_args(const char* func_name,
                                       struct list* func_arg_names,
                                       const char* func_call,
                                       struct list* func_call_args,
                                       struct list* call_arg_names,
                                       struct list* call_output_args,
                                       const char** var_ref_arr,
                                       size_t var_ref_arr_len,
                                       hash_map func_ptrs,
                                       struct list** additional_output_args,
                                       struct list** return_hierarchy) {

  *additional_output_args = list_create();
  struct list* funcs = list_create();
  
  for (struct list_node* curr = call_output_args->head; curr != NULL; curr = curr->next) {
    struct output_arg* curr_out_arg = (struct output_arg*) curr->payload;
    ssize_t out_arg_index = list_find_str(call_arg_names, curr_out_arg->name);
    char* call_arg = (char*) list_get(func_call_args, out_arg_index);
    if (strcmp(call_arg, "NULL") == 0 || utils_isnumeric(call_arg)) {
      continue;
    }
    
    char* call_arg_root;
    struct list* call_arg_hierarchy = struct_get_struct_hierarchy(call_arg, &call_arg_root);
    struct list* struct_hierarchy = list_combine(call_arg_hierarchy, curr_out_arg->struct_hierarchy);
    struct list* return_var_hierarchy;
    struct list* new_output_args;
    if (!var_contains_func_var_visited(func_name, call_arg_root, struct_hierarchy,
                                       &return_var_hierarchy, &new_output_args)) {
      var_insert_func_var_visited(func_name, call_arg_root, struct_hierarchy,
                                  NULL, NULL);
      struct list* additional_funcs =
        assignment_get_assigned_var_funcs(func_name, call_arg_root, struct_hierarchy,
                                          var_ref_arr, var_ref_arr_len, func_ptrs,
                                          &return_var_hierarchy, &new_output_args);
      var_func_extend_unique(funcs, additional_funcs);
      //var_insert_func_var_visited(func_name, call_arg_root, struct_hierarchy,
      //                            return_var_hierarchy, new_output_args);
      var_remove_func_var_visited(func_name, call_arg_root);
    }
    if (return_var_hierarchy != NULL) {
      *return_hierarchy = return_var_hierarchy;
    }
    if (new_output_args != NULL) {
      var_out_arg_extend_unique(*additional_output_args, new_output_args);
    }
  }

  return funcs;
}

void func_free_out_arg(void* void_out_arg) {
  struct output_arg* output_arg = (struct output_arg*) void_out_arg;
  free(output_arg->name);
  list_free_nodes(output_arg->struct_hierarchy);
}

static ssize_t get_func_arg_index(struct list_node* args_range, size_t func_start,
                                  size_t* arg_idx) {
  for (struct list_node* curr_func = args_range; curr_func != NULL;
       curr_func = curr_func->next) {
    struct list* func_args_range = (struct list*) curr_func->payload;
    for (struct list_node* curr_arg = func_args_range->head; curr_arg != NULL;
         curr_arg = curr_arg->next) {
      struct index_range* arg_range = (struct index_range*) curr_arg->payload;
      if (func_start >= arg_range->start && func_start <= arg_range->end) {
        *arg_idx = curr_arg->index;
        return curr_func->index;
      }
    }
  }

  return -1;
}

bool func_list_contains_output_arg(struct list* out_args, struct output_arg* out_arg) {
  for (struct list_node* curr = out_args->head; curr != NULL; curr = curr->next) {
    struct output_arg* curr_out_arg = (struct output_arg*) curr->payload;
    if (strcmp(curr_out_arg->name, out_arg->name) == 0) {
      return true;
    }
  }

  return false;
}
