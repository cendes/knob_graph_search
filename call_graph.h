#ifndef CALL_GRAPH_H
#define CALL_GRAPH_H

#include "list.h"

struct call_graph {
  size_t num_root_nodes;
  struct list* func_names;
  struct list* entrypoints;
  hash_map nodes;
};

struct graph_node {
  const char* func_name;
  hash_map callers;
};

struct call_graph* call_graph_create();

void call_graph_add_root(struct call_graph* graph, const char* root);

void call_graph_insert(struct call_graph* graph, const char* callee, const char* caller);

void call_graph_dump(struct call_graph* graph, const char* file_name);

struct call_graph* call_graph_load(const char* file_name);;

void call_graph_dump_dot(struct call_graph* graph, const char* file_name);

bool call_graph_contains_call(struct call_graph* graph, const char* callee, const char* caller);

#endif /* CALL_GRAPH_H */
