#include "hash_map.h"
#include "list.h"

struct resolved_call_graph {
  size_t num_root_nodes;
  struct list* func_addrs;
  hash_map nodes;
};

struct resolved_graph_node {
  size_t func_addr;
  size_t next_addr;
  hash_map callers;
};

struct resolved_call_graph* resolved_call_graph_create() {
  struct resolved_call_graph* graph =
    (struct resolved_call_graph*) malloc(sizeof(struct resolved_call_graph));
  graph->num_root_nodes = 0;
  graph->func_addrs = list_create();
  graph->nodes = map_create();
}

void resolved_call_graph_add_root(struct resolved_call_graph* graph, size_t func_addr, size_t next_addr) {
  struct resolved_graph_node* root = create_node(func_addr, next_addr);
  map_insert(graph->nodes, func_addr, root);
  list_insert(graph->func_addrs, func_addr);
  graph->num_root_nodes++;
}

static struct resolved_graph_node* create_node(size_t func_addr, size_t next_addr) {
  struct resolved_graph_node* node =
    (struct resolved_graph_node*) malloc(sizeof(struct resolved_graph_node));
  node->func_addr = func_addr;
  node->next_addr = next_addr;
  node->callers = map_create();
}
