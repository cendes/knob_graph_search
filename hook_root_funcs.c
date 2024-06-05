#include <stdio.h>
#include "hash_map.h"
#include "list.h"
#include "call_graph.h"

static struct list* get_kallsyms_roots(struct call_graph* graph, const char* root);

static bool is_in_kallsyms(const char* func_name);

static void append_unique(struct list* this_list, struct list* other_list);

int main(int argc, char* argv[]) {
  char* knob_name = argv[1];

  struct call_graph* graph = call_graph_load(knob_name);
  struct list* actual_root_funcs = list_create();

  struct list_node* curr_root = graph->func_names->head;
  for (size_t i = 0; i < graph->num_root_nodes; i++) {
    char* root_func = (char*) curr_root->payload;
    if (is_in_kallsyms(root_func)) {
      list_append(actual_root_funcs, root_func);
    } else {
      struct list* kallsyms_callers = get_kallsyms_roots(graph, root_func);
      append_unique(actual_root_funcs, kallsyms_callers);
    }
    curr_root = curr_root->next;
  }

  for (struct list_node* curr = actual_root_funcs->head; curr != NULL; curr = curr->next) {
    printf("SEC(\"kprobe/%s\")\n", (char*) curr->payload);
    printf("int BPF_KPROBE(%s, void* args) {\n", (char*) curr->payload);
    printf("  bpf_printk(\"KPROBE_HIT: %s %s\");\n", knob_name, (char*) curr->payload);
    printf("  return 0;\n");
    printf("}\n");
    printf("\n");
  }
}

static struct list* get_kallsyms_roots(struct call_graph* graph, const char* root) {
  struct graph_node* root_node = (struct graph_node*) map_get(graph->nodes, root);
  struct list* root_callers = map_get_key_list(root_node->callers);
  struct list* kallsyms_roots = list_create();
  for (struct list_node* curr = root_callers->head; curr != NULL; curr = curr->next) {
    char* curr_caller = (char*) curr->payload;
    if (is_in_kallsyms(curr_caller)) {
      list_append(kallsyms_roots, curr_caller);
    } else {
      struct list* kallsyms_caller_callers = get_kallsyms_roots(graph, curr_caller);
      append_unique(kallsyms_roots, kallsyms_caller_callers);
    }
  }

  return kallsyms_roots;
}

static bool is_in_kallsyms(const char* func_name) {
  char command[256];
  sprintf(command, "grep \"\\<%s\\>\" /proc/kallsyms > /dev/null", func_name);
  int ret = system(command);
  if (ret == 0) {
    return true;
  } else {
    return false;
  }
}

static void append_unique(struct list* this_list, struct list* other_list) {
  for (struct list_node* curr = other_list->head; curr != NULL; curr = curr->next) {
    if (!list_contains_str(this_list, (char*) curr->payload)) {
      list_append(this_list, curr->payload);
    }
  }

  list_free_nodes(other_list);
}
