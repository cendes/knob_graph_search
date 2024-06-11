#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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
  if (map_contains(graph->nodes, func_name)) {
    size_t node_idx = list_find_str(graph->func_names, func_name);
    assert(node_idx >= 0 &&
           "call_graph_add_root: node is in function list but not in node map");
    if (node_idx >= graph->num_root_nodes) {
      list_remove(graph->func_names, node_idx);
      list_insert(graph->func_names, func_name);
      graph->num_root_nodes++;
    }
  } else {
    struct graph_node* root_node = create_node(func_name);
    map_insert(graph->nodes, func_name, root_node);
    list_insert(graph->func_names, func_name);
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
  if (f == NULL) {
    perror("Could not create file: ");
    return;
  }
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
  if(f == NULL) {
    perror("Could not create file: ");
    return;
  }

  size_t curr_func_index = 0;
  struct list* func = graph->func_names;
  for (struct list_node* curr_callee = func->head; curr_callee != NULL; curr_callee = curr_callee->next) {
    char* callee = (char*) curr_callee->payload;
    if (curr_func_index < graph->num_root_nodes) {
      fprintf(f, "\t %s -> _ROOT_\n", callee);
    }
    struct graph_node* callee_node = (struct graph_node*) map_get(graph->nodes, callee);
    struct list* callers = map_get_key_list(callee_node->callers);
    for (struct list_node* curr_caller = callers->head; curr_caller != NULL; curr_caller = curr_caller->next) {
      char* caller = (char*) curr_caller->payload;
      fprintf(f, "\t %s -> %s\n", caller, callee);
    }
    curr_func_index++;
  }
  fprintf(f, "}\n");
  fclose(f);
}

struct call_graph* call_graph_load(const char* file_name) {
  FILE* f = fopen(file_name, "r");
  if (f == NULL) {
    return NULL;
  }

  struct call_graph* graph = call_graph_create();
  size_t num_nodes;
  fread(&num_nodes, sizeof(size_t), 1, f);
  for (size_t i = 0; i < num_nodes; i++) {
    char* func_name = (char*) malloc(256);
    char* curr_char = func_name;
    char* last_char;
    do {
      last_char = curr_char;
      fread(curr_char, 1, 1, f);
      if (*curr_char != '\0') {
        curr_char++;
      }
    } while(*last_char != '\0');
    list_append(graph->func_names, func_name);
    struct graph_node* func_node = create_node(func_name);
    map_insert(graph->nodes, func_name, func_node);
  }

  fread(&graph->num_root_nodes, sizeof(size_t), 1, f);
  for (struct list_node* curr = graph->func_names->head; curr != NULL; curr = curr->next) {
    char* curr_callee = (char*) curr->payload;
    size_t num_callers;
    fread(&num_callers, sizeof(size_t), 1, f);
    for (size_t i = 0; i < num_callers; i++) {
      size_t caller_index;
      fread(&caller_index, sizeof(size_t), 1, f);
      char* curr_caller = (char*) list_get(graph->func_names, caller_index);
      call_graph_insert(graph, curr_callee, curr_caller);
    }
  }

  fclose(f);
  return graph;
}
