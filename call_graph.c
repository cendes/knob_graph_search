#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_map.h"
#include "list.h"
#include "call_graph.h"

static struct graph_node* create_node(const char* func_name);

struct call_graph* call_graph_create() {
  struct call_graph* graph = (struct call_graph*) malloc(sizeof(struct call_graph));
  graph->num_root_nodes = 0;
  graph->func_names = list_create();
  graph->nodes = map_create();
  return graph;
}

void call_graph_add_root(struct call_graph* graph, const char* func_name) {
  if (!map_contains(graph->nodes, func_name)) {
    struct graph_node* root_node = create_node(func_name);
    map_insert(graph->nodes, func_name, root_node);
    list_append(graph->func_names, func_name);
    graph->num_root_nodes++;
  }
}

static struct graph_node* create_node(const char* func_name) {
  struct graph_node* node = (struct graph_node*) malloc(sizeof(struct graph_node));
  node->func_name = func_name;
  node->callers = map_create();
  return node;
}

void call_graph_insert(struct call_graph* graph, const char* callee, const char* caller) {
  struct graph_node* caller_node;
  if (map_contains(graph->nodes, caller)) {
    caller_node = (struct graph_node*) map_get(graph->nodes, caller);
  } else {
    caller_node = create_node(caller);
    map_insert(graph->nodes, caller, caller_node);
    list_append(graph->func_names, caller);
  }

  struct graph_node* callee_node = (struct graph_node*) map_get(graph->nodes, callee);
  if (!map_contains(callee_node->callers, caller)) {
    map_insert(callee_node->callers, caller, caller_node);
  }
}

bool call_graph_contains_call(struct call_graph* graph, const char* callee, const char* caller) {
  if (!map_contains(graph->nodes, callee)) {
    return false;
  }
  struct graph_node* callee_node = (struct graph_node*) map_get(graph->nodes, callee);
  return map_contains(callee_node->callers, caller);
}

void call_graph_dump(struct call_graph* graph, const char* file_name) {
  struct list* funcs = graph->func_names;
  FILE* f = fopen(file_name, "w");
  fwrite(&funcs->len, sizeof(size_t), 1, f);
  for (struct list_node* curr = funcs->head; curr != NULL; curr = curr->next) {
    char* func_name = (char*) curr->payload;
    fwrite(func_name, 1, strlen(func_name) + 1, f);
  }
  fwrite(&graph->num_root_nodes, sizeof(size_t), 1, f);

  for (struct list_node* curr_callee = funcs->head; curr_callee != NULL;
       curr_callee = curr_callee->next) {
    char* callee = (char*) curr_callee->payload;
    struct graph_node* callee_node = (struct graph_node*) map_get(graph->nodes, callee);
    struct list* callers = map_get_key_list(callee_node->callers);
    fwrite(&callers->len, sizeof(size_t), 1, f);
    for (struct list_node* curr_caller = callers->head; curr_caller != NULL;
         curr_caller = curr_caller->next) {
      char* caller = (char*) curr_caller->payload;
      size_t caller_index = list_find_str(funcs, caller);
      fwrite(&caller_index, sizeof(size_t), 1, f);
    }
  }

  fclose(f);
}

void call_graph_dump_dot(struct call_graph* graph, const char* file_name) {
  FILE* f = fopen(file_name, "w");
  fprintf(f, "digraph \"%s\" {\n", file_name);
  struct list* func = graph->func_names;
  for (struct list_node* curr_callee = func->head; curr_callee != NULL; curr_callee = curr_callee->next) {
    char* callee = (char*) curr_callee->payload;
    struct graph_node* callee_node = (struct graph_node*) map_get(graph->nodes, callee);
    struct list* callers = map_get_key_list(callee_node->callers);
    for (struct list_node* curr_caller = callers->head; curr_caller != NULL; curr_caller = curr_caller->next) {
      char* caller = (char*) curr_caller->payload;
      fprintf(f, "\t %s -> %s\n", caller, callee);
    }
  }
  fprintf(f, "}\n");
  fclose(f);
}
