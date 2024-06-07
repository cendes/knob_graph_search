#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include "hash_map.h"
#include "list.h"
#include "call_graph.h"

static void handle_knob(const char* graphs_directory, const char* knob_name);

static void get_kallsyms_roots(struct call_graph* graph, const char* root,
			       const char* knob_name);

static bool is_in_kallsyms(const char* func_name);

static void append_knob_to_root(const char* root_func, const char* knob_name);

static bool contains_knob_func_visited(const char* knob_name, const char* func_name);

static void append_knob_func_visited(const char* knob_name, const char* func_name);

static void write_bpf_program();

hash_map root_knob_map = map_create();

hash_map knob_funcs_visited = map_create();

int main(int argc, char* argv[]) {
  char* graphs_directory = argv[1];
  DIR* d = opendir(graphs_directory);
  if (d == NULL) {
    perror("Could not open directory: ");
    return EXIT_FAILURE;
  }

  struct dirent* dir_entry = readdir(d);
  while (dir_entry != NULL) {
    char* filename = dir_entry->d_name;
    if (strcmp(filename, ".") != 0 && strcmp(filename, "..") != 0) {
      printf("Reading knob %s\n", filename);
      handle_knob(graphs_directory, filename);
    }
    dir_entry = readdir(d);
  }

  write_bpf_program();
  return EXIT_SUCCESS;

  /* for (struct list_node* curr = actual_root_funcs->head; curr != NULL; curr = curr->next) { */
  /*   printf("SEC(\"kprobe/%s\")\n", (char*) curr->payload); */
  /*   printf("int BPF_KPROBE(%s, void* args) {\n", (char*) curr->payload); */
  /*   printf("  bpf_printk(\"KPROBE_HIT: %s %s\");\n", knob_name, (char*) curr->payload); */
  /*   printf("  return 0;\n"); */
  /*   printf("}\n"); */
  /*   printf("\n"); */
  /* } */
}

static void handle_knob(const char* graphs_directory, const char* knob_name) {
  char file_path[256];
  sprintf(file_path, "%s/%s", graphs_directory, knob_name);
  struct call_graph* graph = call_graph_load(file_path);
  
  struct list_node* curr_root = graph->func_names->head;
  for (size_t i = 0; i < graph->num_root_nodes; i++) {
    char* root_func = (char*) curr_root->payload;
    append_knob_func_visited(knob_name, root_func);
    if (is_in_kallsyms(root_func)) {
      append_knob_to_root(root_func, knob_name);
    } else {
      get_kallsyms_roots(graph, root_func, knob_name);
    }
    curr_root = curr_root->next;
  }
}

static void get_kallsyms_roots(struct call_graph* graph, const char* root,
				       const char* knob_name) {
  struct graph_node* root_node = (struct graph_node*) map_get(graph->nodes, root);
  struct list* root_callers = map_get_key_list(root_node->callers);
  for (struct list_node* curr = root_callers->head; curr != NULL; curr = curr->next) {
    char* curr_caller = (char*) curr->payload;
    if (!contains_knob_func_visited(knob_name, curr_caller)) {
      append_knob_func_visited(knob_name, curr_caller);
      if (is_in_kallsyms(curr_caller)) {
	append_knob_to_root(curr_caller, knob_name);
      } else {
	get_kallsyms_roots(graph, curr_caller, knob_name);
      }
    }
  }
}

static bool is_in_kallsyms(const char* func_name) {
  char command[256];
  sprintf(command, "grep \"^%s$\" init_funcs", func_name);
  int ret = system(command);
  if (ret == 0) {
    return false;
  }
  
  sprintf(command, "grep \"\\s%s$\" /proc/kallsyms", func_name);
  ret = system(command);
  if (ret == 0) {
    return true;
  } else {
    return false;
  }
}

static void append_knob_to_root(const char* root_func, const char* knob_name) {
  struct list* knob_list;
  if (map_contains(root_knob_map, root_func)) {
    knob_list = (struct list*) map_get(root_knob_map, root_func);
  } else {
    knob_list = list_create();
    map_insert(root_knob_map, root_func, knob_list);
  }

  if (!list_contains_str(knob_list, knob_name)) {
    list_append(knob_list, knob_name);
  }
}

static bool contains_knob_func_visited(const char* knob_name, const char* func_name) {
  if (!map_contains(knob_funcs_visited, knob_name)) {
    return false;
  }

  struct list* funcs_visited = (struct list*) map_get(knob_funcs_visited, knob_name);
  return list_contains_str(funcs_visited, func_name);
}

static void append_knob_func_visited(const char* knob_name, const char* func_name) {
  struct list* funcs_visited_list;
  if (map_contains(knob_funcs_visited, knob_name)) {
    funcs_visited_list = (struct list*) map_get(knob_funcs_visited, knob_name);
  } else {
    funcs_visited_list = list_create();
    map_insert(knob_funcs_visited, knob_name, funcs_visited_list);
  }

  list_append(funcs_visited_list, func_name);
}

static void write_bpf_program() {
  FILE* f = fopen("bpf_hook_funcs.c", "w");
  if (f == NULL) {
    perror("Failed to create BPF program: ");
    return;
  }
  
  struct list* root_funcs = map_get_key_list(root_knob_map);
  for (struct list_node* curr_func = root_funcs->head; curr_func != NULL;
       curr_func = curr_func->next) {
    char* func_name = (char*) curr_func->payload;
    fprintf(f, "SEC(\"kprobe/%s\")\n", func_name);
    fprintf(f, "int kprobe__%s(struct pt_regs* ctx) {\n", func_name);
    struct list* knob_list = (struct list*) map_get(root_knob_map, func_name);
    for (struct list_node* curr_knob = knob_list->head; curr_knob != NULL;
	 curr_knob = curr_knob->next) {
      char* knob_name = (char*) curr_knob->payload;
      fprintf(f, "  bpf_printk(\"KPROBE_HIT: %s %s\");\n", knob_name, func_name);
    }
    fprintf(f, "  return 0;\n");
    fprintf(f, "}\n");
    fprintf(f, "\n");
  }
}
