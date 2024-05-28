#ifndef STRUCT_PARSE_H
#define STRUCT_PARSE_H

#include "list.h"

char* struct_get_root_name(const char* var_name);

struct list* struct_get_struct_hierarchy(const char* var_name, char** root_name);

struct list* struct_get_struct_matches(const char* var_ref, const char* root_name,
                                struct list* field_hierarchy);

bool struct_has_full_match(struct list* struct_matches, bool is_normal_var);

struct list_node* struct_get_highest_match(struct list* hierarchy_matches);

#endif /* STRUCT_PARSE_H */
