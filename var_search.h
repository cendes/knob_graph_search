#ifndef VAR_SEARCH_H
#define VAR_SEARCH_H

#include "list.h"
#include "hash_map.h"
#include "call_graph.h"

struct func_var_entry {
  struct list* var_refs;
  struct list* full_var_refs;
  bool locked;
};

extern struct call_graph* call_graph;

char* var_find_knob_var(const char* knob, struct list** struct_hierarchy);

void var_get_global_var_refs(const char* var_name, struct list* struct_hierarchy,
                             struct list* var_refs, bool record_match);

bool var_get_func_refs(const char* var_name, struct list* struct_hierarchy,
                       struct list* var_refs, const char* func_name,
                       hash_map func_ptrs, bool record_match,
                       struct list** return_struct_hierarchy,
                       struct list** output_vars, hash_map* func_ret_map);

struct list* var_get_local_var_refs(const char* var_name, const char* func_name,
                                    const char* func_src_file,
                                    ssize_t func_start_line,
                                    bool is_define,
                                    struct list** global_var_refs);

//void var_func_extend_unique(struct list *funcs, struct list* additional_funcs);

void var_out_arg_extend_unique(struct list* out_args, struct list* additional_out_args);

/* void var_insert_func_var_visited(const char* func, const char* var, */
/*                                  struct list* struct_hierarchy, */
/*                                  struct list* return_hierarchy, */
/*                                  struct list* output_args); */

/* bool var_contains_func_var_visited(const char* func, const char* var, */
/*                                    struct list* struct_hierarchy, */
/*                                    struct list** return_hierarchy, */
/*                                    struct list** output_args); */

/* void var_remove_func_var_visited(const char* func, const char* var); */

struct func_var_entry* var_get_func_var_entry(const char* func, const char* var);

struct func_var_entry* var_create_func_var_entry(const char* func, const char* var);



#endif /* VAR_SEARCH_H */
