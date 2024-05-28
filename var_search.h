#ifndef VAR_SEARCH_H
#define VAR_SEARCH_H

#include "list.h"
#include "hash_map.h"
#include "call_graph.h"

struct struct_match_node {
  char* segment_name;
  struct list* funcs;
  hash_map next_segments;
};

char* var_find_knob_var(const char* knob, struct list** struct_hierarchy);

struct list* var_find_func_refs(const char* var_name, struct list* struct_hierarchy,
                                struct list** return_struct_hierarchy,
                                struct list** output_vars);

struct list* var_get_func_refs(const char* var_name, struct list* struct_hierarchy,
                               struct list* var_refs, bool is_global,
                               const char* func_name, hash_map func_ptrs,
                               struct list** return_struct_hierarchy,
                               struct list** output_vars);

struct list* var_get_local_var_refs(const char* var_name, const char* func_name,
                                    const char** statement_arr, int statement_arr_len,
                                    bool is_func_declaration);

void var_func_extend_unique(struct list *funcs, struct list* additional_funcs);

void var_out_arg_extend_unique(struct list* out_args, struct list* additional_out_args);

void var_insert_func_var_visited(const char* func, const char* var,
                                 struct list* struct_hierarchy,
                                 struct list* return_hierarchy,
                                 struct list* output_args);

bool var_contains_func_var_visited(const char* func, const char* var,
                                   struct list* struct_hierarchy,
                                   struct list** return_hierarchy,
                                   struct list** output_args);

void var_remove_func_var_visited(const char* func, const char* var);

#endif /* VAR_SEARCH_H */
