#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "utils.h"
#include "list.h"
#include "hash_map.h"
#include "database.h"
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
//TODO: handle assignments to array or struct litxerals
//TODO: Properly handle removing casts
//TODO: Properly handle ternary operators in assigments and arguments (generate new expressions)
//TODO: handle function pointers in func variables visited cache
//TODO: create tree database for already visited func variables with different struct hierarchy
//TODO: for returns, check if expression is boolean

// TODO: SOLVE ALREADY INSERTED ROOT BUG

struct func_ret_entry {
  struct list* return_hierarchy;
  struct list* output_args;
};

struct visited_func_ret_entry {
  struct list* return_hierarchies;
  struct list* output_args;
};

static hash_map visited_funcs_ret = map_create();

void start_knob_var_search(const char* var_name, struct list* struct_hierarchy);

static struct list* get_local_var_refs_from_src(struct list* var_refs,
                                                const char* var_name,
                                                const char* func_name,
                                                const char* src_file,
                                                size_t func_start_line,
                                                size_t func_end_line);

static bool get_local_ref(const char* var_name, const char* var_ref,
                          const char** var_ref_arr, const char* func_name,
                          bool is_local_var, struct list* local_var_refs,
                          size_t* num_invalid_refs);

static void handle_entry_point_return(hash_map func_ret_map, bool record_match);

static void insert_func_ret_hierarchy(hash_map func_ret_map, const char* func_name,
                                      const char* src_file, struct list* return_hierarchy);

static void insert_func_ret_output_args(hash_map func_ret_map, const char* func_name,
                                        const char* src_file, struct list* output_args);

static bool func_ret_hierarchy_visited(const char* func_entry_key,
                                       struct list* return_hierarchy);

//static char* generate_struct_key(struct list* struct_hierarchy);


static hash_map func_vars_visited = map_create();

struct call_graph* call_graph = call_graph_create();

int main(int argc, char* argv[]) {
  if (argc < 3) {
    fprintf(stderr, "Usage: ./knob_search KNOB_NAME LINUX_SOURCE_DIR [OUPUT_DIR]\n");
    return EXIT_FAILURE;
  }
  char* knob_name = argv[1];
  char* linux_src_dir = argv[2];
  char* output_dir;
  if (argc >= 4) {
    output_dir = argv[3];
  } else {
    output_dir = ".";
  }

  fprintf(stderr, "######### Error report for knob %s ##########\n", knob_name);
  printf("Reading database...\n");
  func_vars_visited = database_read_func_vars_visited("func_vars_visited");
  func_load_visited_func_decls("visited_func_decls");
  database_read_macros_return_range("macros_return_ranges");
  
  check_out_of_scope = map_create();
  char cwd[4096];
  getcwd(cwd, 4096);
  int ret = chdir(linux_src_dir);
  if (ret < 0) {
    perror("Could not find Linux souce code directory: ");
    return EXIT_FAILURE;
  }
  

  struct list* struct_hierarchy;
  char* var_name = var_find_knob_var(knob_name, &struct_hierarchy);
  if (var_name == NULL) {
    fprintf(stderr, "Could not find variable for knob %s\n", knob_name);
    return EXIT_SUCCESS;
  }
  start_knob_var_search(var_name, struct_hierarchy);
  
  char filename[4096];
  sprintf(filename, "%s/%s/partial_graph_%s.dot", cwd, output_dir, knob_name);
  call_graph_dump_dot(call_graph, filename);
  
  expand_call_graph(call_graph, call_graph->entrypoints);

  sprintf(filename, "%s/%s/%s", cwd, output_dir, knob_name);
  call_graph_dump(call_graph, filename);
  sprintf(filename, "%s/%s/%s.dot", cwd, output_dir, knob_name);
  call_graph_dump_dot(call_graph, filename);
  return EXIT_SUCCESS;
}

char* var_find_knob_var(const char* knob, struct list** struct_hierarchy) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L4 \\\"%s\\\"", knob);
  struct list* results = utils_get_cscope_output(cmd);
  for (struct list_node* curr = results->head; curr != NULL; curr = curr->next) {
    char* result = (char*) curr->payload;
    if (strstr(result, ".procname") != NULL) {
      char** result_arr;
      utils_split_str(result, &result_arr);
      free(result);
    
      char* file_path = result_arr[0];
      int line_num = atoi(result_arr[2]);
      char* var_line = file_get_line(file_path, line_num + 1);
      utils_free_str_arr(result_arr);
      if (strstr(var_line, ".data") != NULL) {
        size_t var_start = 0;
        while (var_line[var_start] != '=') {
          var_start++;
        }
        var_start++;
        while (isspace(var_line[var_start])) {
          var_start++;
        }

        char* trimmed_var_name = utils_trim_str(var_line + var_start);
        char* var_name = trimmed_var_name;
        utils_truncate_str(var_name, -1);
        if (strcmp(var_name, "NULL") != 0) {
          if (var_name[0] == '&'){
            var_name++;
          }
          if (var_name != trimmed_var_name) {
            char* new_var_name = (char*) malloc(strlen(var_name) + 1);
            strncpy(new_var_name, var_name, strlen(var_name) + 1);
            utils_free_if_different(trimmed_var_name, var_line + var_start);
            var_name = new_var_name;
          }
          printf("%s\n", var_name);
          
          char* root_var_name;
          *struct_hierarchy = struct_get_struct_hierarchy(var_name, &root_var_name);
          
          utils_free_if_both_different(var_name, var_line + var_start, root_var_name);
          //if (root_var_name == var_line_arr[1]) {
          //  root_var_name = (char*) malloc(strlen(var_line_arr[1]) + 1);
          //  strncpy(root_var_name, var_line_arr[1], strlen(var_line_arr[1]) + 1);
          //}
          //utils_free_str_arr(var_line_arr);
          return root_var_name;
        }
      }
    }
  }

  return NULL;
}

void start_knob_var_search(const char* var_name, struct list* struct_hierarchy) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L0 %s", var_name);
  struct list* var_refs = utils_get_cscope_output(cmd);
  //struct list* leaf_funcs = list_create();
  //for (struct list_node* curr = var_refs->head; curr != NULL; curr = curr->next) {
  //  char* var_ref = (char*) curr->payload;
  //  char** var_ref_arr;
  //  size_t var_ref_arr_len = utils_split_str(var_ref, (char***) &var_ref_arr);
  //  if (strcmp(var_ref_arr[1], "<global>") != 0) {
  //    char* leaf_func = (char*) malloc(strlen(var_ref_arr[1]) + 1);
  //    strncpy(leaf_func, var_ref_arr[1], strlen(var_ref_arr[1]) + 1);
  //    list_append(leaf_funcs, leaf_func);
  //  }
  //  utils_free_str_arr(var_ref_arr);
  //}

  hash_map func_ptrs = map_create();
  struct list* return_struct_hierarchy;
  struct list* output_vars;

  struct func_var_entry* entry = var_create_func_var_entry("<global>", var_name);
  entry->locked = true;
  entry->var_refs = var_refs;
  var_get_global_var_refs(var_name, struct_hierarchy, var_refs, true);
  list_free(struct_hierarchy);
  map_free(func_ptrs);

  //struct list* actual_leaf_funcs = list_create();
  //for (struct list_node* curr_func = leaf_funcs->head; curr_func != NULL;
  //     curr_func = curr_func->next) {
  //  char* leaf_func = (char*) curr_func->payload;
  //  if (map_contains(call_graph->nodes, leaf_func)) {
  //    list_append(actual_leaf_funcs, leaf_func);
  //  } else {
  //    free(leaf_func);
  //  }
  //}
  //list_free_nodes(leaf_funcs);

  //return actual_leaf_funcs;
}

void var_get_global_var_refs(const char* var_name, struct list* struct_hierarchy,
                             struct list* var_refs, bool record_match) {
  if (strcmp(var_name, "p") == 0) {
    int test = 1;
  }
  //char cmd[256];
  //sprintf(cmd, "cscope -d -L0 %s", var_name);
  //struct list* var_refs = utils_get_cscope_output(cmd);
  hash_map func_ptrs = map_create();
  
  struct func_var_entry* entry = var_get_func_var_entry("<global>", var_name);
  
  entry->locked = true;
  struct list* return_struct_hierarchy;
  struct list* output_vars;
  hash_map func_ret_map;
  var_get_func_refs(var_name, struct_hierarchy, var_refs, NULL, func_ptrs,
                    record_match, &return_struct_hierarchy, &output_vars,
                    &func_ret_map);
  entry->locked = false;
  handle_entry_point_return(func_ret_map, record_match);
  // TODO: actually handle the output args
  //list_custom_free(*output_vars, &func_free_out_arg);
  //*output_vars = list_create();

  map_free(func_ptrs);
  //list_free_nodes(var_refs);
}

bool var_get_func_refs(const char* var_name, struct list* struct_hierarchy,
                       struct list* var_refs, const char* func_name,
                       hash_map func_ptrs, bool record_match,
                       struct list** return_struct_hierarchy,
                       struct list** output_vars, hash_map* func_ret_map) {
  
  bool has_match = false;
  *output_vars = list_create();
  *return_struct_hierarchy = NULL;
  if (func_ret_map != NULL) {
    *func_ret_map = map_create();
  }
  bool is_global = func_name == NULL;

  const char* entry_func = func_name == NULL ? "<global>" : func_name;
  struct func_var_entry* entry = var_get_func_var_entry(entry_func, var_name);
  //if (func_name == NULL) {
  //  entry = var_get_func_var_entry("<global>", var_name);
  //} else {
  //  entry = var_get_func_var_entry(func_name, var_name);
  //}
  struct list* full_var_refs = entry->full_var_refs;

  struct list* new_full_var_refs;
  struct list_node* curr_full_var_ref;
  if (full_var_refs == NULL) {
    new_full_var_refs = list_create();
  } else {
    curr_full_var_ref = full_var_refs->head;
  }
  
  for (struct list_node* var_ref_node = var_refs->head; var_ref_node != NULL;
       var_ref_node = var_ref_node->next) {
    char* var_ref = (char*) var_ref_node->payload;
    //printf("%s\n", var_ref);
    const char** var_ref_arr;
    size_t var_ref_arr_len = utils_split_str(var_ref, (char***) &var_ref_arr);
    if (is_global) {
      func_name = var_ref_arr[1];
    }

    if (full_var_refs == NULL) {
      //char* san_var_ref = sanitize_remove_casts(var_ref);
      //utils_free_if_different(var_ref, san_var_ref);
      char* full_var_ref = file_get_multiline_expr(var_ref, var_ref_arr, false);
      if (strstr(full_var_ref, "mm/highmem.c page_slot 715 return &page_address_htable[hash_ptr(page, PA_HASH_ORDER)];") != NULL) {
        int test = 1;
      }
      //utils_free_if_both_different(san_var_ref, full_var_ref, var_ref);
      list_append(new_full_var_refs, full_var_ref);
      //char* original_var_ref = var_ref;
      var_ref = full_var_ref;
    } else {
      var_ref = (char*) curr_full_var_ref->payload;
      curr_full_var_ref = curr_full_var_ref->next;
    }

    if (strcmp(func_name, "devinet_init_net") == 0) {
      int test = 1;
    }

    if (strstr(var_ref, "asm ") != NULL || strstr(var_ref, "asm(") != NULL || strstr(var_ref, "__asm__") != NULL) {
      int test = 1;
    }

    if (strstr(var_ref, "include/linux/user-return-notifier.h clear_user_return_notifier 46 static inline void clear_user_return_notifier(struct task_struct *p) {}") != NULL) {
      int test = 1;
    }
    
    if (strcmp(func_name, "<global>") != 0 &&
        (!is_global || !map_contains(check_out_of_scope, func_name) ||
         !list_contains_str((struct list*) map_get(check_out_of_scope, func_name), var_name))
      && check_is_ref(var_ref, var_name, func_name, is_global) &&
        !check_is_asm_block(var_ref)) {
      //printf("Function: %s Variable: %s Struct Hierarchy: ", func_name, var_name);
      //for (struct list_node* curr = struct_hierarchy->head; curr != NULL; curr = curr->next) {
      //  printf("%s, ", (char*) curr->payload);
      //}
      //printf("\n");
      // TODO: remove false positives for function calls and assignments
      struct list* additional_funcs;
      struct list* additional_output_args;
      struct list* return_hierarchy;
      struct list* call_return_hierarchy;
      bool has_func_call;
      if (check_is_func(var_ref) && !check_is_var_declaration(func_name, var_ref)) {
        has_func_call = true;
        has_match |= func_handle_func_call(var_name, struct_hierarchy,
                                           var_ref, var_ref_arr,
                                           var_ref_arr_len, func_name,
                                           func_ptrs, record_match,
                                           &return_hierarchy,
                                           &additional_output_args,
                                           &call_return_hierarchy);
      } else {
        has_func_call = false;
        has_match |= assignment_handle_var_assignment(func_name, var_ref,
                                                      var_ref_arr,
                                                      var_ref_arr_len,
                                                      var_name,
                                                      struct_hierarchy,
                                                      false, func_ptrs,
                                                      record_match,
                                                      &return_hierarchy,
                                                      &additional_output_args);
      }
      if (has_match) {
        int test = 1;
      }
      //var_func_extend_unique(funcs, additional_funcs);
      var_out_arg_extend_unique(*output_vars, additional_output_args); // TODO: properly free additional_output_args

      struct list_node* return_match_node;
      enum TokenReturnType return_match_type =
        token_get_return_match_node(var_ref, (const char**) var_ref_arr, var_name,
                                    struct_hierarchy, func_name,
                                    &return_match_node);

      if (return_hierarchy != NULL) {
        int test = 1;
      }
      struct list* curr_return_hierarchy;
      if (return_match_type == VAR_RETURN || return_match_type == FUNC_RETURN) {
        assert((has_func_call || return_match_type == VAR_RETURN) &&
               "var_get_func_refs: got function return match type without function call");
          
        if (return_match_type == VAR_RETURN) {
          if (return_hierarchy != NULL) {
            int test = 1;
          }
          struct list* var_return_hierarchy = list_copy(struct_hierarchy, return_match_node);
          if (return_hierarchy != NULL && return_hierarchy->len < var_return_hierarchy->len) {
            curr_return_hierarchy = return_hierarchy;
            list_free_nodes(var_return_hierarchy);
          } else {
            curr_return_hierarchy = var_return_hierarchy;
            list_free_nodes(return_hierarchy);
          }
        }

        if (return_match_type == FUNC_RETURN ||
            (has_func_call && call_return_hierarchy != NULL &&
             call_return_hierarchy->len < curr_return_hierarchy->len)) {
          curr_return_hierarchy = call_return_hierarchy;
        }
      } else {
        //*return_struct_hierarchy = return_hierarchy;
        curr_return_hierarchy = return_hierarchy;
      }

      if (*return_struct_hierarchy == NULL ||
          (curr_return_hierarchy != NULL &&
           curr_return_hierarchy->len < (*return_struct_hierarchy)->len)) {
        if (*return_struct_hierarchy != NULL) {
          int test = 1;
        }
        *return_struct_hierarchy = curr_return_hierarchy;
      }
      
      if (func_ret_map != NULL) {
        if (*return_struct_hierarchy != NULL) {
          insert_func_ret_hierarchy(*func_ret_map, func_name, var_ref_arr[0], *return_struct_hierarchy);
        }
        insert_func_ret_output_args(*func_ret_map, func_name, var_ref_arr[0], additional_output_args);
        /* if (has_match) { */
        /*   if (!list_contains_str(call_graph->entrypoints, func_name)) { */
        /*       char* entrypoint_func = (char*) malloc(strlen(func_name) + 1); */
        /*       strncpy(entrypoint_func, func_name, strlen(func_name) + 1); */
        /*       list_append(call_graph->entrypoints, entrypoint_func); */
        /*   } */
        /*   has_match = false; */
        /* } */
      }

      if (!record_match) {
        int test = 1;
      }
      struct list* struct_matches = struct_get_struct_matches(var_ref, var_name, struct_hierarchy);
      if (record_match && struct_has_full_match(struct_matches, struct_hierarchy->len == 0)) {
        char* func_match = (char*) malloc(strlen(func_name) + 1);
        strncpy(func_match, func_name, strlen(func_name) + 1);
        call_graph_add_root(call_graph, func_match);
        has_match = true;
      }
      
      if (func_ret_map != NULL && has_match) {
        if (!list_contains_str(call_graph->entrypoints, func_name)) {
          char* entrypoint_func = (char*) malloc(strlen(func_name) + 1);
          strncpy(entrypoint_func, func_name, strlen(func_name) + 1);
          list_append(call_graph->entrypoints, entrypoint_func);
        }
        has_match = false;
      }
      list_free_nodes(struct_matches);
      //list_free_nodes(additional_output_args);
      utils_free_str_arr((char**) var_ref_arr);
    }
    //utils_free_str_arr((char**) var_ref_arr);
    //free(var_ref);
    //utils_free_if_different(var_ref, original_var_ref);
  }

  if (full_var_refs == NULL) {
    entry->full_var_refs = new_full_var_refs;
    database_write_func_vars_visited_entry(entry_func, var_name, entry);
  }
  
  return has_match;
}

struct list* var_get_local_var_refs(const char* var_name, const char* func_name,
                                    const char* func_src_file,
                                    ssize_t func_start_line,
                                    bool is_define,
                                    struct list** global_var_refs) {
  if (strcmp(var_name, "ptsid") == 0 && strcmp(func_name, "selinux_setprocattr") == 0) {
    int test = 1;
  }
  const char* original_var_name = var_name;
  var_name = struct_get_root_name(var_name);
  char cmd[256];
  sprintf(cmd, "cscope -d -L0 %s", var_name);
  struct list* var_refs = utils_get_cscope_output(cmd);

  bool is_local_var = false;
  size_t num_local_refs = 0;
  size_t num_invalid_refs = 0;
  struct list* local_var_refs = list_create();
  struct list* src_file_refs = list_create();
  struct list* non_local_refs = list_create();
  struct list* non_src_refs = list_create();
  for (struct list_node* var_ref_node = var_refs->head; var_ref_node != NULL;
       var_ref_node = var_ref_node->next) {
    const char* var_ref = (const char*) var_ref_node->payload;
    char** var_ref_arr;
    utils_split_str(var_ref, &var_ref_arr);
    if (strcmp(var_ref_arr[0], func_src_file) == 0) {
      list_append(src_file_refs, var_ref);
      
      if (strcmp(var_ref_arr[1], func_name) == 0) {
        is_local_var = get_local_ref(var_name, var_ref, (const char**) var_ref_arr,
                                     func_name, is_local_var, local_var_refs,
                                     &num_invalid_refs);
        num_local_refs++;
      } else {
        list_append(non_local_refs, var_ref);
      }
    } else {
      list_append(non_src_refs, var_ref);
    }

    /* if (strcmp(var_ref_arr[0], func_src_file) == 0) { */
    /*   list_append(src_file_refs, var_ref); */
    /* } else { */
    /*   list_append(non_src_refs, var_ref); */
    /* } */
    utils_free_str_arr(var_ref_arr);
  }
  //list_free_nodes(var_refs);
  if (num_invalid_refs > 0) {
    struct list* actual_local_refs = list_create();
    for (struct list_node* local_ref_node = local_var_refs->head;
         local_ref_node != NULL; local_ref_node = local_ref_node->next) {
      char* local_ref = (char*) local_ref_node->payload;
      if (strlen(local_ref) > 0) {
        char** local_ref_arr;
        utils_split_str(local_ref, &local_ref_arr);
        const char* full_local_ref =
          file_get_multiline_expr(local_ref, (const char**) local_ref_arr, true);
        if (strlen(full_local_ref) == 0) {
          fprintf(stderr, "Found invalid code: %s\n", local_ref);
          list_append(actual_local_refs, full_local_ref);
          free(local_ref);
          num_invalid_refs++;
        } else {
          list_append(actual_local_refs, local_ref);
        }
        
        utils_free_str_arr(local_ref_arr);
      } else {
        list_append(actual_local_refs, local_ref);
      }
    }
    list_free_nodes(local_var_refs);
    local_var_refs = actual_local_refs;
  }

  if (is_local_var /*|| (is_define && local_var_refs->len > 0)*/) {
    list_free(non_local_refs);
    list_free_nodes(src_file_refs);
    list_free_nodes(non_src_refs);
    list_free_nodes(var_refs);
    utils_free_if_different((char*) var_name, original_var_name);
    return local_var_refs;
  } else if (local_var_refs->len > 0 && num_invalid_refs == num_local_refs) {
    fprintf(stderr, "Function has no valid code: %s\n", func_name);
    list_free(local_var_refs);
    list_free(non_local_refs);
    list_free_nodes(src_file_refs);
    list_free_nodes(non_src_refs);
    list_free_nodes(var_refs);
    return list_create();
  } else if (local_var_refs->len == 0) {
    list_free_nodes(local_var_refs);
    list_free_nodes(non_local_refs);
    //list_free(non_src_refs);

    //ssize_t func_start_line;
    //ssize_t func_end_line = 0;
    //if (is_func_declaration) {
    //  func_start_line = atoi(statement_arr[2]);
    if (func_start_line < 0) {
      func_start_line = func_get_func_start_line(func_name, func_src_file);
      assert(func_start_line >= 0 &&
             "Failed to get function start line: func declaration not found");
    }
    ssize_t func_end_line = file_get_func_end_line(func_src_file, func_start_line);
    //} else {
    //  func_end_line = file_get_func_from_src(func_src_file, func_name, &func_start_line);
    //}

    if (func_end_line < 0) {
      list_free_nodes(src_file_refs);
      list_free_nodes(non_src_refs);
      utils_free_if_different((char*) var_name, original_var_name);
      *global_var_refs = var_refs;
      return NULL;
    } else {
      local_var_refs = get_local_var_refs_from_src(src_file_refs, var_name, func_name,
                                                   func_src_file, func_start_line,
                                                   func_end_line);
      list_free_nodes(src_file_refs);
      utils_free_if_different((char*) var_name, original_var_name);
      if (local_var_refs == NULL) {
        list_free_nodes(non_src_refs);
        *global_var_refs = var_refs;
      } else {
        list_free(non_src_refs);
        list_free_nodes(var_refs);
      }
      return local_var_refs;
    }
  } else {
    list_free_nodes(local_var_refs);
    list_free_nodes(non_local_refs);
    list_free_nodes(src_file_refs);
    list_free_nodes(non_src_refs);
    utils_free_if_different((char*) var_name, original_var_name);
    *global_var_refs = var_refs;
    return NULL;
  }
}

static struct list* get_local_var_refs_from_src(struct list* var_refs, const char* var_name,
                                                const char* func_name, const char* src_file,
                                                size_t func_start_line, size_t func_end_line) {
  struct list* local_var_refs = list_create();
  struct list* non_local_refs = list_create();
  size_t num_invalid_refs = 0;
  size_t num_local_refs = 0;
  bool is_local_var = false;
  for (struct list_node* var_ref_node = var_refs->head; var_ref_node != NULL;
       var_ref_node = var_ref_node->next) {
    const char* var_ref = (const char*) var_ref_node->payload;
    char** var_ref_arr;
    utils_split_str(var_ref, (char***) &var_ref_arr);
    size_t ref_line = atoi(var_ref_arr[2]);
    if (ref_line == 8916) {
      int test = 1;
    }
    if (strcmp(var_ref_arr[0], src_file) == 0 && func_start_line <= ref_line &&
        func_end_line >= ref_line) {
      is_local_var = get_local_ref(var_name, var_ref, (const char**) var_ref_arr,
                                   func_name, is_local_var, local_var_refs,
                                   &num_invalid_refs);
      num_local_refs++;
    } else {
      list_append(non_local_refs, var_ref);
    }
    utils_free_str_arr(var_ref_arr);
  }

  if (is_local_var) {
    list_free(non_local_refs);
    return local_var_refs;
  } else if (num_local_refs == num_invalid_refs) {
    fprintf(stderr, "Function has no valid code: %s\n", func_name);
    list_free(local_var_refs);
    return list_create();
  } else {
    list_free_nodes(local_var_refs);
    return NULL;
  }
}

static bool get_local_ref(const char* var_name, const char* var_ref, const char** var_ref_arr,
                          const char* func_name, bool is_local_var,
                          struct list* local_var_refs, size_t* num_invalid_refs) {
  const char* full_var_ref = file_get_multiline_expr(var_ref, var_ref_arr,
                                                     *num_invalid_refs > 0);
  if (strlen(full_var_ref) == 0) {
    fprintf(stderr, "Found invalid code: %s\n", var_ref);
    (*num_invalid_refs)++;
    free((char*) var_ref);
    list_append(local_var_refs, full_var_ref);
    return is_local_var;
  }
  if (!is_local_var) {
    is_local_var = check_is_var_declaration(var_name, full_var_ref);
    //if (is_local_var) {
    //  list_append(non_local_refs, var_ref);
    //  return true;
    //}
  }

  if (check_is_ref(full_var_ref, var_name, func_name, false)) {
    list_append(local_var_refs, var_ref);
  }

  utils_free_if_different((char*) full_var_ref, var_ref);
  return is_local_var;
}

static void handle_entry_point_return(hash_map func_ret_map, bool record_match) {
  hash_map next_ret_map = map_create();
  struct list* func_key_list = map_get_key_list(func_ret_map);
  if (func_key_list->len == 0) {
    return;
  }
  for (struct list_node* curr_func = func_key_list->head; curr_func != NULL;
       curr_func = curr_func->next) {
    char* func_key = (char*) curr_func->payload;
    if (strcmp(func_key,"ax25_dev_device_down net/ax25/ax25_dev.c") == 0) {
      int test = 1;
    }
    char** func_key_arr;
    utils_split_str(func_key, &func_key_arr);
    const char* ret_func = func_key_arr[0];
    const char* func_src = func_key_arr[1];
    if (strcmp(ret_func, "write_threads") == 0) {
      int test = 1;
    }

    const char* ret_func_decl;
    const char* func_src_tmp;
    size_t func_start_line_tmp;
    enum FuncDeclStatus status = func_get_func_decl(ret_func, func_src, &ret_func_decl, &func_src_tmp,
                       &func_start_line_tmp);
    if (status == FUNC_DECL_NOT_EXISTS) {
      fprintf(stderr, "Entrypoint function has invalid declaration: %s\n", ret_func);
      continue;
    }
    if (status == FUNC_DECL_NOT_FOUND) {
      func_get_curr_func_arg_names(ret_func, func_src);
      status = func_get_func_decl(ret_func, func_src, &ret_func_decl, &func_src_tmp,
                                  &func_start_line_tmp);
      assert(status == FUNC_DECL_FOUND &&
             "handle_entry_point_return: function declaration must be loaded");
    }
    
    //printf("Function return: %s\n", ret_func);
    struct func_ret_entry* entry =
      (struct func_ret_entry*) map_get(func_ret_map, func_key);

    struct func_var_entry* func_var_entry = var_get_func_var_entry(ret_func, "<func>");
    struct list* func_refs;
    if (func_var_entry == NULL) {
      char cmd[256];
      sprintf(cmd, "cscope -d -L0 %s", ret_func);
      func_refs = utils_get_cscope_output(cmd);
      func_var_entry = var_create_func_var_entry(ret_func, "<func>");
      func_var_entry->var_refs = func_refs;
    } else {
      func_refs = func_var_entry->var_refs;
    }

    struct list* full_func_refs = func_var_entry->full_var_refs;
    
    struct list* new_full_func_refs;
    struct list_node* curr_full_func_ref;
    if (full_func_refs == NULL) {
      new_full_func_refs = list_create();
    } else {
      curr_full_func_ref = full_func_refs->head;
    }

    for (struct list_node* curr_ref = func_refs->head; curr_ref != NULL;
         curr_ref = curr_ref->next) {
      char* func_ref = (char*) curr_ref->payload;
      //printf("%s\n", func_ref);
      const char** func_ref_arr;
      size_t func_ref_arr_len = utils_split_str(func_ref, (char***) &func_ref_arr);
      const char* caller_func = func_ref_arr[1];

      if (full_func_refs == NULL) {
        //char* san_func_ref = sanitize_remove_casts(func_ref);
        char* full_func_ref = file_get_multiline_expr(func_ref, func_ref_arr, false);
        //utils_free_if_both_different(san_func_ref, full_func_ref, func_ref);
        list_append(new_full_func_refs, full_func_ref);
        func_ref = full_func_ref;
      } else {
        func_ref = (char*) curr_full_func_ref->payload;
        curr_full_func_ref = curr_full_func_ref->next;
      }

      if (check_is_func_ptr(func_ref)) {
        int test = 1;
      }
      
      struct list* return_hierarchy;
      struct list* output_args;
      if (strcmp(caller_func, "<global>") != 0 &&
          check_has_func_call(func_ref, ret_func) && !check_is_var_declaration(ret_func, func_ref) &&
          check_is_func_decl_in_scope(ret_func_decl, func_src, func_ref_arr[0]) &&
          !check_is_func_ptr(func_ref)) {
        if (strcmp(func_ref,"kernel/bpf/syscall.c link_create 4250 prog = bpf_prog_get(attr->link_create.prog_fd);") == 0) {
          int test = 1;
        }
        bool match_found = false;
        if (entry->return_hierarchy != NULL) {
          if (strcmp(caller_func, "cifs_mount") == 0) {
            int test = 1;
          }
          match_found |= assignment_handle_var_assignment(caller_func, func_ref,
                                                          func_ref_arr,
                                                          func_ref_arr_len, NULL,
                                                          entry->return_hierarchy,
                                                          true, map_create(),
                                                          record_match,
                                                          &return_hierarchy,
                                                          &output_args);
          if (return_hierarchy != NULL) {
            insert_func_ret_hierarchy(next_ret_map, caller_func, func_ref_arr[0],
                                      return_hierarchy);
          }
          insert_func_ret_output_args(next_ret_map, caller_func, func_ref_arr[0],
                                      output_args);
          list_free_nodes(output_args);
        }

        if (entry->output_args != NULL) {
          if (strcmp(caller_func, "cifs_mount") == 0) {
            int test = 1;
          }
          match_found |= func_handle_entrypoint_out_args(ret_func, caller_func,
                                                         entry->output_args,
                                                         func_ref, func_ref_arr,
                                                         func_ref_arr_len,
                                                         record_match,
                                                         &return_hierarchy,
                                                         &output_args);
          if (return_hierarchy != NULL) {
            insert_func_ret_hierarchy(next_ret_map, caller_func, func_ref_arr[0],
                                      return_hierarchy);
          }
          insert_func_ret_output_args(next_ret_map, caller_func, func_ref_arr[0],
                                      output_args);
          list_free_nodes(output_args);
        }

        if (match_found && !list_contains_str(call_graph->entrypoints, caller_func)) {
          list_append(call_graph->entrypoints, caller_func);
        }
      }

      //utils_free_if_different(full_func_ref, func_ref);
      //free(func_ref);
    }

    if (full_func_refs == NULL) {
      func_var_entry->full_var_refs = new_full_func_refs;
      database_write_func_vars_visited_entry(ret_func, "<func>", func_var_entry);
    }
  }

  handle_entry_point_return(next_ret_map, record_match);
}

void var_out_arg_extend_unique(struct list* out_args, struct list* additional_out_args) {
  for (struct list_node* additional_out_arg = additional_out_args->head;
       additional_out_arg != NULL; additional_out_arg = additional_out_arg->next) {
    struct output_arg* new_out_arg = (struct output_arg*) additional_out_arg->payload;
    struct output_arg* curr_out_arg = func_list_get_output_arg(out_args, new_out_arg->name);
    if (curr_out_arg == NULL) {
      list_append(out_args, new_out_arg);
    } else if (new_out_arg->struct_hierarchy->len < curr_out_arg->struct_hierarchy->len) {
      list_free_nodes(curr_out_arg->struct_hierarchy);
      curr_out_arg->struct_hierarchy = new_out_arg->struct_hierarchy;
      //free(new_out_arg);
    } else {
      //list_free_nodes(new_out_arg->struct_hierarchy);
      //free(new_out_arg);
    }
  }

  //list_free_nodes(additional_out_args);
}


struct func_var_entry* var_get_func_var_entry(const char* func, const char* var) {
  if (!map_contains(func_vars_visited, func)) {
    return NULL;
  }

  hash_map var_map = (hash_map) map_get(func_vars_visited, func);
  if (!map_contains(var_map, var)) {
    return NULL;
  }

  return (struct func_var_entry*) map_get(var_map, var);
}

struct func_var_entry* var_create_func_var_entry(const char* func, const char* var) {
  struct func_var_entry* entry =
    (struct func_var_entry*) malloc(sizeof(struct func_var_entry));
  entry->full_var_refs = NULL;
  entry->locked = false;
  
  hash_map var_map;
  if (map_contains(func_vars_visited, func)) {
    var_map = (hash_map) map_get(func_vars_visited, func);
  } else {
    var_map = map_create();
    char* func_key = (char*) malloc(strlen(func) + 1);
    strncpy(func_key, func, strlen(func) + 1);
    map_insert(func_vars_visited, func_key, var_map);
  }

  char* var_key = (char*) malloc(strlen(var) + 1);
  strncpy(var_key, var, strlen(var) + 1);
  map_insert(var_map, var_key, entry);

  return entry;
}

static void insert_func_ret_hierarchy(hash_map func_ret_map, const char* func_name,
                                      const char* src_file, struct list* return_hierarchy) {
  char* func_entry_key = (char*) malloc(strlen(func_name) + strlen(src_file) + 2);
  sprintf(func_entry_key, "%s %s", func_name, src_file);

  if (func_ret_hierarchy_visited(func_entry_key, return_hierarchy)) {
    free(func_entry_key);
    return;
  }
  
  struct func_ret_entry* entry;
  if (map_contains(func_ret_map, func_entry_key)) {
    entry = (struct func_ret_entry*) map_get(func_ret_map, func_entry_key);
    free(func_entry_key);
  } else {
    entry = (struct func_ret_entry*) malloc(sizeof(struct func_ret_entry));
    entry->output_args = NULL;
    map_insert(func_ret_map, func_entry_key, entry);
  }

  entry->return_hierarchy = return_hierarchy;
}

static void insert_func_ret_output_args(hash_map func_ret_map, const char* func_name,
                                        const char* src_file, struct list* output_args) {
  if (output_args->len == 0) {
    //list_free_nodes(output_args);
    return;
  }

  char* func_entry_key = (char*) malloc(strlen(func_name) + strlen(src_file) + 2);
  sprintf(func_entry_key, "%s %s", func_name, src_file);
  struct func_ret_entry* entry;
  if (map_contains(func_ret_map, func_entry_key)) {
    entry = (struct func_ret_entry*) map_get(func_ret_map, func_entry_key);
    free(func_entry_key);
  } else {
    entry = (struct func_ret_entry*) malloc(sizeof(struct func_ret_entry));
    entry->return_hierarchy = NULL;
    entry->output_args = list_create();
    map_insert(func_ret_map, func_entry_key, entry);
  }

  if (entry->output_args == NULL) {
    entry->output_args = list_create();
  }

  var_out_arg_extend_unique(entry->output_args, output_args);
}

static bool func_ret_hierarchy_visited(const char* func_entry_key,
                                       struct list* return_hierarchy) {
  struct visited_func_ret_entry* visited_entry;
  if (!map_contains(visited_funcs_ret, func_entry_key)) {
    visited_entry =
      (struct visited_func_ret_entry*) malloc(sizeof(struct visited_func_ret_entry));
    visited_entry->return_hierarchies = list_create();
    list_append(visited_entry->return_hierarchies, return_hierarchy);
    visited_entry->output_args = list_create();
    map_insert(visited_funcs_ret, func_entry_key, visited_entry);
    return false;
  }
  visited_entry =
    (struct visited_func_ret_entry*) map_get(visited_funcs_ret, func_entry_key);


  for (struct list_node* curr_hierarchy = visited_entry->return_hierarchies->head;
       curr_hierarchy != NULL; curr_hierarchy = curr_hierarchy->next) {
    struct list* visited_hierarchy = (struct list*) curr_hierarchy->payload;
    if (visited_hierarchy->len != return_hierarchy->len) {
      continue;
    }

    bool hierarchy_equal = true;
    struct list_node* curr_visited_segment = visited_hierarchy->head;
    for (struct list_node* curr = return_hierarchy->head; curr != NULL; curr = curr->next) {
      if (strcmp((char*) curr->payload, (char*) curr_visited_segment->payload) != 0) {
        hierarchy_equal = false;
        break;
      }
      curr_visited_segment = curr_visited_segment->next;
    }
    if (hierarchy_equal) {
      return true;
    }
  }

  list_append(visited_entry->return_hierarchies, return_hierarchy);
  return false;
}
