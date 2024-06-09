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
#include "call_graph.h"
#include "database.h"

static hash_map visited_func_ptr_args = map_create();

static hash_map visited_func_args_decl = map_create();

static hash_map visited_func_decls = map_create();

struct func_decl_entry {
  const char* source_file;
  const char* func_declaration;
  size_t line_number;
};

static void append_arg(struct list* args_list, struct list* args_range,
                       const char* var_ref, size_t arg_start, size_t arg_end);

static struct list* get_func_args_declaration(const char* func_name,
                                              const char* ref_src_file,
                                              struct list* func_args,
                                              char*** func_declaration_arr,
                                              size_t* func_declaration_arr_len);

static struct list* get_func_declarations(const char* func_name,
                                          const char* ref_src_file,
                                          struct list** func_declarations_arr,
                                          struct list** func_declarations_arr_len);

static bool handle_memcpy(const char* var_name, const char** var_ref_arr,
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

static struct list* get_func_args_list(hash_map args_map, const char* func_name,
                                       const char* src_file);

static void insert_func_args_list(hash_map args_map, const char* func_name,
                                  const char* src_file, struct list* args_list);

static bool handle_output_args(const char* func_name,
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

void func_load_visited_func_decls(const char* filename) {
  database_read_visited_func_decls(filename);
  struct list* func_list = map_get_key_list(visited_func_decls);
  for (struct list_node* curr_func = func_list->head; curr_func != NULL;
       curr_func = curr_func->next) {
    char* func_name = (char*) curr_func->payload;
    struct list* func_decls_list = (struct list*) map_get(visited_func_decls, func_name);
    if (func_decls_list != NULL) {
      for (struct list_node* curr_entry = func_decls_list->head; curr_entry != NULL;
           curr_entry = curr_entry->next) {
        struct func_decl_entry* entry = (struct func_decl_entry*) curr_entry->payload;
        const char* func_declaration = entry->func_declaration;
        const char* src_file = entry->source_file;
    
        if (func_declaration != NULL) {
          size_t args_start_index = strchr(func_declaration, '(') - func_declaration;
          struct list* args_range;
          if (strcmp(func_name, "devlink_reload") == 0) {
            int test = 1;
          }
          struct list* args_declaration = func_get_func_args(func_declaration,
                                                             args_start_index, &args_range);
          list_free(args_range);
          
          if (args_declaration->len == 0 ||
              (args_declaration->len == 1 &&
               strcmp((char*) args_declaration->head->payload, "void") == 0)) {
            list_free(args_declaration);
          } else {
            insert_func_args_list(visited_func_args_decl, func_name, src_file,
                                  args_declaration);
            
            struct list* func_ptr_args = list_create();
            for (struct list_node* curr_arg = args_declaration->head; curr_arg != NULL;
                 curr_arg = curr_arg->next) {
              if (check_is_func_ptr((char*) curr_arg->payload)) {
                list_append(func_ptr_args, (void*) curr_arg->index);
              }
            }
            if (func_ptr_args->len == 0) {
              list_free_nodes(func_ptr_args);
            } else {
              insert_func_args_list(visited_func_ptr_args, func_name, src_file,
                                    func_ptr_args);
            }
          }
        }
      }
    }
  }
}

bool func_handle_func_call(const char* var_name,
                           struct list* struct_hierarchy,
                           const char* var_ref, const char** var_ref_arr,
                           size_t var_ref_arr_len, const char* func_name,
                           hash_map func_ptrs,
                           struct list** return_struct_hierarchy,
                           struct list** output_vars) {
  if (strcmp(var_ref, "net/core/neighbour.c ___neigh_create 629 if (atomic_read(&tbl->entries) > (1 << nht->hash_shift))") == 0) {
    int test = 1;
  }
  bool has_match = false;
  *return_struct_hierarchy = NULL;
  *output_vars = list_create();
  struct list* calling_func_args = func_get_curr_func_arg_names(func_name,
                                                                var_ref_arr[0]);

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
    if (strcmp(func_name, "print_diff_canary") == 0) {
      int test = 1;
    }
    if (map_contains(func_ptrs, func_call)) {
      curr_call->payload = map_get(func_ptrs, func_call);
      //free(func_call);
      func_call = (char*) curr_call->payload;
    }

    struct list* args_indices = (struct list*) curr_args_indices->payload;
    struct list* args_struct_matches = (struct list*) curr_struct_matches->payload;
    if (strcmp(func_call, "rose_parse_national") == 0) {
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
        has_match |= handle_memcpy(var_name, var_ref_arr,
                                   var_ref_arr_len, func_name,
                                   (struct list*) curr_call_args->payload,
                                   struct_hierarchy, src_struct_match,
                                   func_ptrs,
                                   &assigned_root_name,
                                   &assigned_hierarchy,
                                   &curr_func_return_hierarchy,
                                   &additional_output_args);
        //if (additional_funcs != NULL) {
        //  var_func_extend_unique(funcs, additional_funcs);
        //}
        if (check_is_arg_assignment(assigned_root_name, calling_func_args)) {
          assignment_append_out_arg(additional_output_args, assigned_root_name, assigned_hierarchy);
        }
        var_out_arg_extend_unique(*output_vars, additional_output_args);
      }
    } else if (strcmp(func_call, "create_object") != 0 && strcmp(func_call, "kfree_skb") != 0 &&
               strcmp(func_call, "__jhash_mix") != 0 && strcmp(func_call,"__jhash_final") != 0 &&
               strcmp(func_call, "__kfree_skb") != 0 && strcmp(func_call, "__cache_free") != 0 &&
               strcmp(func_call,  "__list_add") != 0) {
      struct list* func_arg_names;
      struct list* func_ptr_args;
      const char* func_declaration;
      const char* func_src_file;
      size_t func_start_line;
      char** func_declaration_arr;
      size_t func_declaration_arr_len;
      enum FuncDeclStatus func_decl_status =
        func_get_func_decl(func_call, var_ref_arr[0], &func_declaration, &func_src_file,
                           &func_start_line);
      if (func_decl_status == FUNC_DECL_FOUND) {
        if (strcmp(func_call, "__rdma_create_kernel_id") == 0) {
          int test = 1;
        }
        
        struct list* func_args_decl = get_func_args_list(visited_func_args_decl,
                                                          func_call, func_src_file);
        if (func_args_decl == NULL) {
          curr_call_args = curr_call_args->next;
          curr_func_start = curr_func_start->next;
          curr_args_indices = curr_args_indices->next;
          curr_struct_matches = curr_struct_matches->next;
          curr_args_range = curr_args_range->next;
          list_free_nodes(args_struct_matches);
          list_free_nodes(args_indices);
          continue;
        }
        
        func_declaration_arr_len = utils_split_str(func_declaration, &func_declaration_arr);
        func_arg_names = func_get_func_args_name(func_call, func_args_decl,
                                                 (const char**) func_declaration_arr,
                                                 func_declaration_arr_len);
        func_ptr_args = get_func_args_list(visited_func_ptr_args, func_call,
                                           func_src_file);
        if (func_ptr_args == NULL) {
          func_ptr_args = list_create();
        }
      } else if (func_decl_status == FUNC_DECL_NOT_EXISTS) {
        curr_call_args = curr_call_args->next;
        curr_func_start = curr_func_start->next;
        curr_args_indices = curr_args_indices->next;
        curr_struct_matches = curr_struct_matches->next;
        curr_args_range = curr_args_range->next;
        list_free_nodes(args_struct_matches);
        list_free_nodes(args_indices);
        continue;
      } else {
        func_arg_names = func_extract_func_arg_names(func_call,
                                                     var_ref_arr[0],
                                                     (struct list*) curr_call_args->payload,
                                                     &func_ptr_args,
                                                     &func_declaration_arr,
                                                     &func_declaration_arr_len);
        if (func_declaration_arr != NULL) {
          func_src_file = func_declaration_arr[0];
          func_start_line = atoi(func_declaration_arr[2]);
        }
      }
      
      if (func_arg_names->len == 0) {
        curr_call_args = curr_call_args->next;
        curr_func_start = curr_func_start->next;
        curr_args_indices = curr_args_indices->next;
        curr_struct_matches = curr_struct_matches->next;
        curr_args_range = curr_args_range->next;
        list_free(func_arg_names);
        list_free(func_ptr_args);
        list_free_nodes(args_struct_matches);
        list_free_nodes(args_indices);
        continue;
      }

      // TODO: this could be more memory efficient if we only got them for visited args
      struct list* func_arg_refs = func_get_func_args_refs(func_call, func_arg_names,
                                                           args_indices, func_src_file,
                                                           func_start_line,
                                                           (const char**) func_declaration_arr,
                                                           func_declaration_arr_len);

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
        struct func_var_entry* caller_entry = var_get_func_var_entry(func_name, func_var_code);
        if (caller_entry == NULL) {
          caller_entry = var_create_func_var_entry(func_name, func_var_code);
        } else {
          free(func_var_code);
        }
        
        if (!caller_entry->locked) {
          caller_entry->locked = true;
          //var_insert_func_var_visited(func_name, func_var_code,
          //                           arg_struct_hierarchy, NULL, NULL);
          bool match_found = var_get_func_refs(curr_arg_name,
                                               arg_struct_hierarchy,
                                               curr_arg_refs, func_call,
                                               func_ptrs_passed,
                                               &return_var_hierarchy,
                                               &output_args,
                                               NULL);
          caller_entry->locked = false;
          //var_insert_func_var_visited(func_name, func_var_code,
          //                            arg_struct_hierarchy, return_var_hierarchy,
          //                            output_args);
          if (match_found) {
            char* caller_name = (char*) malloc(strlen(func_name) + 1);
            strncpy(caller_name, func_name, strlen(func_name) + 1);
            call_graph_insert(call_graph, func_call, caller_name);
          }
          has_match |= match_found;
          //var_remove_func_var_visited(func_name, func_var_code);
          //free(func_var_code);
          //var_func_extend_unique(funcs, additional_funcs);
          list_free_nodes(arg_struct_hierarchy);
          //list_free_nodes(curr_arg_refs);

          has_match |= handle_output_args(func_name,
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
          var_out_arg_extend_unique(*output_vars, additional_output_args);

          if (return_var_hierarchy != NULL) {
            //struct list* additional_output_args;
            has_match |= assignment_handle_var_assignment(func_name,
                                                          var_ref,
                                                          var_ref_arr,
                                                          var_ref_arr_len,
                                                          var_name,
                                                          return_var_hierarchy,
                                                          true, func_ptrs,
                                                          &curr_func_return_hierarchy,
                                                          &additional_output_args);
            //var_func_extend_unique(funcs, additional_funcs);
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
        }
        
        //if (output_args == NULL) {
        //  output_args = list_create();
        //}
        
        //map_free(func_ptrs_passed); // TODO: maybe only free the payload?
        //list_custom_free(output_args, &func_free_out_arg);
        //var_func_extend_unique(funcs, additional_funcs);
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

  return has_match;
}

enum FuncDeclStatus func_get_func_decl(const char* func_name,
                                       const char* ref_src_file,
                                       const char** func_decl,
                                       const char** func_src_file,
                                       size_t* func_start_line) {
  if (!map_contains(visited_func_decls, func_name)) {
    return FUNC_DECL_NOT_FOUND;
  }

  struct list* entry_list = (struct list*) map_get(visited_func_decls, func_name);
  if (entry_list == NULL) {
    return FUNC_DECL_NOT_EXISTS;
  }

  for (struct list_node* curr = entry_list->head; curr != NULL; curr = curr->next) {
    struct func_decl_entry* entry = (struct func_decl_entry*) curr->payload;
    if (strcmp(entry->source_file, ref_src_file) == 0 &&
        entry->func_declaration == NULL) {
      return FUNC_DECL_NOT_EXISTS;
    }
    if (entry->func_declaration != NULL &&
        check_is_func_decl_in_scope(entry->func_declaration, entry->source_file,
                                    ref_src_file)) {
      *func_decl = entry->func_declaration;
      *func_src_file = entry->source_file;
      *func_start_line = entry->line_number;
      return FUNC_DECL_FOUND;
    }
  }
  
  return FUNC_DECL_NOT_FOUND;
}

static struct list* get_func_args_list(hash_map args_map, const char* func_name,
                                const char* src_file) {
  if (!map_contains(args_map, func_name)) {
    return NULL;
  }

  hash_map src_file_map = map_get(args_map, func_name);
  if (!map_contains(src_file_map, src_file)) {
    return NULL;
  }

  return (struct list*) map_get(src_file_map, src_file);
}

static void insert_func_args_list(hash_map args_map, const char* func_name,
                                  const char* src_file, struct list* args_list) {
  if (strcmp(func_name, "devlink_reload") == 0) {
    int test = 1;
  }
  hash_map src_file_map;
  if (map_contains(args_map, func_name)) {
    src_file_map = (hash_map) map_get(args_map, func_name);
  } else {
    src_file_map = map_create();
    map_insert(args_map, func_name, src_file_map);
  }

  map_insert(src_file_map, src_file, args_list);
}

struct list* func_get_curr_func_arg_names(const char* func_name, const char* ref_src_file) {
  const char* func_declaration;
  const char* func_src_file;
  size_t func_start_line;
  char** func_declaration_arr;
  size_t func_declaration_arr_len;
  enum FuncDeclStatus func_decl_status =
    func_get_func_decl(func_name, ref_src_file, &func_declaration, &func_src_file,
                       &func_start_line);
  if (func_decl_status == FUNC_DECL_FOUND) {
    struct list* args_declaration = get_func_args_list(visited_func_args_decl,
                                                       func_name, func_src_file);
    if (args_declaration == NULL) {
      return list_create();
    }
    func_declaration_arr_len = utils_split_str(func_declaration, &func_declaration_arr);
    return func_get_func_args_name(func_name, args_declaration,
                                   (const char**) func_declaration_arr,
                                   func_declaration_arr_len);
  } else {
    struct list* func_ptr_args;
    return func_extract_func_arg_names(func_name, ref_src_file, NULL, &func_ptr_args,
                                       &func_declaration_arr,
                                       &func_declaration_arr_len);
  }
}

ssize_t func_get_func_start_line(const char* func_name, const char* ref_src_file) {
  const char* func_declaration;
  const char* func_src_file;
  size_t func_start_line;
  enum FuncDeclStatus func_decl_status =
    func_get_func_decl(func_name, ref_src_file, &func_declaration, &func_src_file,
                       &func_start_line);
  if (func_decl_status == FUNC_DECL_FOUND) {
    return func_start_line;
  } else {
    struct list* func_ptr_args;
    char** func_declaration_arr;
    size_t func_declaration_arr_len;
    func_extract_func_arg_names(func_name, ref_src_file, NULL, &func_ptr_args,
                                &func_declaration_arr,
                                &func_declaration_arr_len);
    if (func_declaration_arr == NULL) {
      return -1;
    } else {
      return atoi(func_declaration_arr[2]);
    }
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
    if (strcmp(func_name, "d_inode") == 0) {
      int test = 1;
    }

    struct list* func_args_range;
    struct list* args_list = func_get_func_args(var_ref, args_start_indices[i],
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

struct list* func_get_func_args(const char* var_ref,
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
                                         const char* ref_src_file,
                                         struct list* func_args,
                                         struct list** func_ptr_args,
                                         char*** func_declaration_arr,
                                         size_t* func_declaration_arr_len) {
  struct list* args_declaration = get_func_args_declaration(func_name, ref_src_file,
                                                            func_args,
                                                            func_declaration_arr,
                                                            func_declaration_arr_len);
  if (args_declaration == NULL || func_declaration_arr == NULL) {
    *func_ptr_args = list_create();
    return list_create();
  }

  if (strcmp(func_name, "ic_open_devs") == 0) {
    int test = 1;
  }
  if (strcmp(func_name, "pr_err") == 0) {
    int test = 1;
  }
  insert_func_args_list(visited_func_args_decl, func_name, (*func_declaration_arr)[0],
                        args_declaration);
  

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
    insert_func_args_list(visited_func_ptr_args, func_name,
                          (*func_declaration_arr)[0], *func_ptr_args);
  }
  return func_arg_names;
}


static struct list* get_func_args_declaration(const char* func_name,
                                              const char* ref_src_file,
                                              struct list* func_args,
                                              char*** func_declaration_arr,
                                              size_t* func_declaration_arr_len) {
  if (strcmp(func_name, ">") == 0) {
    int test = 1;
  }
  struct list* func_declarations_arr;
  struct list* func_declarations_arr_len;
  struct list* func_declarations = get_func_declarations(func_name,
                                                         ref_src_file,
                                                         &func_declarations_arr,
                                                         &func_declarations_arr_len);
  if (func_declarations->len == 0) {
    printf("Function declaration not found: %s\n", func_name);
    func_insert_func_decl_entry(func_name, NULL, NULL, 0);
    database_write_visited_func_decls_entry(func_name, NULL, NULL, 0);
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
  struct list_node* curr_decl_arr_node = func_declarations_arr->head;
  struct list_node* curr_decl_arr_len_node = func_declarations_arr_len->head;
  for (curr_declaration = func_declarations->head; curr_declaration != NULL;
       curr_declaration = curr_declaration->next) {
    char* func_declaration = (char*) curr_declaration->payload;
    char** curr_declaration_arr = (char**) curr_decl_arr_node->payload;
    
    size_t args_start_index = strchr(func_declaration, '(') - func_declaration;
    struct list* args_range;
    args_declaration = func_get_func_args(func_declaration, args_start_index, &args_range);
    list_free(args_range);

    size_t num_declaration_args;
    if (args_declaration->len == 1 &&
        strcmp((char*) args_declaration->head->payload, "void") == 0) {
      num_declaration_args = 0;
      list_free(args_declaration);
      args_declaration = list_create();
    } else {
      num_declaration_args = args_declaration->len;
    }

    if ((func_args == NULL || num_declaration_args == func_args->len) &&
        (strstr(func_declaration, "#define") != NULL ||
         check_has_arg_names(args_declaration))) {
      size_t line_number = atoi(curr_declaration_arr[2]);
        func_insert_func_decl_entry(func_name, func_declaration,
                                    curr_declaration_arr[0], line_number);
      database_write_visited_func_decls_entry(func_name, func_declaration,
                                              curr_declaration_arr[0], line_number);
      if (num_declaration_args == 0) {
        list_free(args_declaration);
        args_declaration = NULL;
        //utils_free_str_arr(curr_declaration_arr);
      } else {
        *func_declaration_arr = curr_declaration_arr;
        *func_declaration_arr_len = (size_t) curr_decl_arr_len_node->payload;
      }
      break;
    } else {
      list_free(args_declaration);
      args_declaration = NULL;
      free(func_declaration);
      utils_free_str_arr(curr_declaration_arr);
    }
    curr_decl_arr_node = curr_decl_arr_node->next;
    curr_decl_arr_len_node = curr_decl_arr_len_node->next;
  }

  if (curr_declaration == NULL) {
    printf("No valid function declaration found: %s\n", func_name);
    func_insert_func_decl_entry(func_name, NULL, ref_src_file, 0);
    database_write_visited_func_decls_entry(func_name, NULL, ref_src_file, 0);
  } else {
    curr_decl_arr_node = curr_decl_arr_node->next;
    for (curr_declaration = curr_declaration->next; curr_declaration != NULL;
         curr_declaration = curr_declaration->next) {
      free(curr_declaration->payload);
      utils_free_str_arr((char**) curr_decl_arr_node->payload);
      curr_decl_arr_node = curr_decl_arr_node->next;
    }
  }
  list_free_nodes(func_declarations);
  list_free_nodes(func_declarations_arr);
  list_free_nodes(func_declarations_arr_len);
  
  return args_declaration;
}

void func_insert_func_decl_entry(const char* func_name,
                                 const char* func_declaration,
                                 const char* source_file,
                                 size_t line_number) {
  if (func_declaration == NULL && source_file == NULL) {
    map_insert(visited_func_decls, func_name, NULL);
    return;
  }
  
  struct list* func_decls_list;
  if (map_contains(visited_func_decls, func_name)) {
    func_decls_list = (struct list*) map_get(visited_func_decls, func_name);
  } else {
    func_decls_list = list_create();
    map_insert(visited_func_decls, func_name, func_decls_list);
  }

  struct func_decl_entry* entry =
    (struct func_decl_entry*) malloc(sizeof(struct func_decl_entry));
  entry->source_file = source_file;
  entry->func_declaration = func_declaration;
  entry->line_number = line_number;
  list_append(func_decls_list, entry);
}

static struct list* get_func_declarations(const char* func_name,
                                          const char* ref_src_file,
                                          struct list** func_declarations_arr,
                                          struct list** func_declarations_arr_len) {
  char cmd[256];
  sprintf(cmd, "cscope -d -L0 %s", func_name);
  struct list* func_refs = utils_get_cscope_output(cmd);

  if (strcmp(func_name, "net_eq_idr") == 0) {
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
    if (strstr(func_ref,"struct cpuidle_monitor* (*do_register) (void);") != NULL) {
      int test = 1;
    }
    size_t func_ref_arr_len = utils_split_str(func_ref, &func_ref_arr);
    char* full_func_ref = file_get_multiline_expr(func_ref,
                                                  (const char**) func_ref_arr);
    utils_free_if_different(func_ref, full_func_ref);
    func_ref = full_func_ref;

    if (strcmp(func_ref, "struct timespec64 ts = { sec, min_t(u32, nsec, NSEC_PER_SEC - 1) };") == 0) {
      int test = 1;
    }

    char* declaration_name = token_find_func_name(func_ref);
    if (declaration_name != NULL && strcmp(declaration_name, func_name) == 0 &&
        check_is_var_declaration(func_name, func_ref) &&
        check_is_func_decl_in_scope(func_ref, func_ref_arr[0], ref_src_file)) {
      free(declaration_name);
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
      free(declaration_name);
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
        if (strcmp(func_name, "fib_nl2rule") == 0) {
          int test = 1;
        }
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
                                     const char* func_src_file,
                                     ssize_t func_start_line,
                                     const char** statement_arr,
                                     size_t statement_arr_len) {
  struct list* func_arg_refs = list_create();
  for (struct list_node* curr = var_args_indices->head; curr != NULL; curr = curr->next) {
    size_t curr_arg_index = (size_t) curr->payload;
    char* arg_name = (char*) list_get(func_arg_names, curr_arg_index);

    struct func_var_entry* arg_entry = var_get_func_var_entry(func_name, arg_name);
    struct list* arg_refs;
    if (arg_entry == NULL) {
      arg_entry = var_create_func_var_entry(func_name, arg_name);
      struct list* global_var_refs;
      arg_refs = var_get_local_var_refs(arg_name, func_name, func_src_file,
                                        func_start_line, statement_arr,
                                        statement_arr_len, &global_var_refs);
      if (arg_refs == NULL) {
        printf("Argument not found: Function: %s, Argument: %s\n", func_name,
               arg_name);
        list_append(func_arg_refs, list_create());
      }
      arg_entry->var_refs = arg_refs;
      arg_entry->locked = false;
    } else {
      arg_refs = arg_entry->var_refs;
    }
    
    if (arg_refs == NULL) {
      arg_refs = list_create();
    }
    list_append(func_arg_refs, arg_refs);
  }

  return func_arg_refs;
}

static bool handle_memcpy(const char* var_name, const char** var_ref_arr,
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
    //if (!var_contains_func_var_visited(func_name, *assigned_root_name,
    //                                   *assigned_hierarchy, return_hierarchy,
    //                                   output_args)) {
    //  var_insert_func_var_visited(func_name, *assigned_root_name,
    //                              *assigned_hierarchy, NULL, NULL);
      bool has_match = assignment_get_assigned_var_funcs(func_name,
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
      //var_remove_func_var_visited(func_name, *assigned_root_name);
      return has_match;
      //} else {
      //return false;
      //}
  } else {
    *return_hierarchy = NULL;
    *output_args = list_create();
    return false;
  }
}

static char* get_ptr_from_func_return(const char* func_call, const char** var_ref_arr,
                                      size_t var_ref_arr_len, hash_map func_ptrs,
                                      struct list** return_hierarchy) {
  char* out_func_name = token_find_func_name(func_call);
  size_t args_start_index = strchr(func_call, '(') - func_call;
  struct list* args_range;
  struct list* arg_args = func_get_func_args(func_call, args_start_index, &args_range);
  list_free(args_range);

  for (struct list_node* curr = arg_args->head; curr != NULL; curr = curr->next) {
    char* arg_arg = (char*) curr->payload;
    struct func_var_entry* entry = var_get_func_var_entry(out_func_name, arg_arg);
    struct list* arg_refs;
    if (entry == NULL) {
      struct list* global_var_refs;
      arg_refs = var_get_local_var_refs(arg_arg, out_func_name, var_ref_arr[0],
                                        -1, var_ref_arr, var_ref_arr_len,
                                        &global_var_refs);
      list_free_nodes(global_var_refs);
      entry = var_create_func_var_entry(out_func_name, arg_arg);
      entry->var_refs = arg_refs;
    } else {
      arg_refs = entry->var_refs;
    }
    
    //struct list* arg_refs = var_get_local_var_refs(arg_arg, out_func_name,
    //                                               var_ref_arr, var_ref_arr_len,
    //                                              false, NULL);
    struct list* arg_return_hierarchy;
    struct list* output_args;
    var_get_func_refs(arg_arg, list_create(), arg_refs,
                      out_func_name, func_ptrs,
                      &arg_return_hierarchy, &output_args,
                      NULL);
    //list_free(output_args);
    //list_free(arg_refs);
    if (return_hierarchy != NULL) {
      //free(out_func_name);
      //for (struct list_node* n = curr->next; n != NULL; n = n->next) {
      //  free(n->payload);
      //}
      list_free_nodes(arg_args);
        
      char* root_name;
      struct list* assigned_hierarchy = struct_get_struct_hierarchy(arg_arg, &root_name);
      utils_free_if_different(root_name, arg_arg);
      *return_hierarchy = list_combine(assigned_hierarchy, arg_return_hierarchy);
      list_free_nodes(arg_return_hierarchy);
      list_free_nodes(assigned_hierarchy);
      return arg_arg;
    } else {
      //free(arg_arg);
    }
  }

  //free(out_func_name);
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

static bool handle_output_args(const char* func_name,
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
  bool has_match = false;
  *additional_output_args = list_create();
  *return_hierarchy = NULL;
  //struct list* funcs = list_create();
  
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
    //if (!var_contains_func_var_visited(func_name, call_arg_root, struct_hierarchy,
    //                                   &return_var_hierarchy, &new_output_args)) {
    //  var_insert_func_var_visited(func_name, call_arg_root, struct_hierarchy,
    //                              NULL, NULL);
      has_match |= assignment_get_assigned_var_funcs(func_name, call_arg_root,
                                                     struct_hierarchy, var_ref_arr,
                                                     var_ref_arr_len, func_ptrs,
                                                     &return_var_hierarchy,
                                                     &new_output_args);
      //var_func_extend_unique(funcs, additional_funcs);
      //var_insert_func_var_visited(func_name, call_arg_root, struct_hierarchy,
      //                            return_var_hierarchy, new_output_args);
      //var_remove_func_var_visited(func_name, call_arg_root);
      //}
    if (return_var_hierarchy != NULL) {
      *return_hierarchy = return_var_hierarchy;
    }
    if (new_output_args != NULL) {
      var_out_arg_extend_unique(*additional_output_args, new_output_args);
    }
  }

  return has_match;
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

void func_handle_entrypoint_out_args(const char* entry_func, const char* caller_func,
                                     struct list* output_args, const char* func_ref,
                                     const char** func_ref_arr, size_t func_ref_arr_len,
                                     struct list** return_hierarchy,
                                     struct list** caller_out_args) {
  if (strcmp(func_ref,"fs/nfs/nfs42xdr.c decode_copy 974 status = decode_write_response(xdr, &res->write_res);") == 0) {
    int test = 1;
  }
  struct list* entry_arg_names =
    func_get_curr_func_arg_names(entry_func, func_ref_arr[0]);
  struct list* caller_arg_names =
    func_get_curr_func_arg_names(caller_func, func_ref_arr[0]);
  

  *return_hierarchy = NULL;
  *caller_out_args = list_create();
  size_t* args_start_indices;
  size_t num_start_indices = utils_get_char_occurences(func_ref, '(',
                                                       &args_start_indices);
  for (size_t i = 0; i < num_start_indices; i++) {
    char* func_name = token_get_func_name(func_ref, args_start_indices[i]);
    if (func_name == NULL || strcmp(func_name, entry_func) != 0) {
      free(func_name);
      continue;
    }
    free(func_name);

    struct list* func_args_range;
    struct list* call_args = func_get_func_args(func_ref, args_start_indices[i],
                                                &func_args_range);
    list_free(func_args_range);

    struct list* additional_output_args;
    struct list* return_var_hierarchy;
    hash_map func_ptrs = map_create();
    handle_output_args(caller_func, caller_arg_names, entry_func, call_args,
                       entry_arg_names, output_args, func_ref_arr,
                       func_ref_arr_len, func_ptrs, &additional_output_args,
                       &return_var_hierarchy);
    if (return_var_hierarchy != NULL) {
      *return_hierarchy = return_var_hierarchy;
    }
    var_out_arg_extend_unique(*caller_out_args, additional_output_args);
  }
}
