#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include "hash_map.h"
#include "list.h"
#include "call_graph.h"

static void handle_knob(const char* graphs_directory, const char* knob_name);

static void get_kallsyms_callers(struct call_graph* graph, const char* root,
				 const char* knob_name, bool is_root,
				 hash_map funcs_visited);

static bool is_in_kallsyms(const char* func_name);

static void append_knob_to_root(const char* root_func, const char* knob_name);

static void append_entrypoint_to_knob(const char* knob_name, const char* entrypoint);

static void get_root_entrypoints(struct call_graph* graph, const char* root_func,
				 const char* knob_name);

static void get_entrypoint_callers(struct call_graph* graph,
				   struct list* knob_entrypoints,
				   struct list* root_entrypoints,
				   struct list* funcs_visited,
				   const char* func);

static bool contains_knob_func_visited(const char* knob_name, const char* func_name,
				       hash_map funcs_visited);

static void append_knob_func_visited(const char* knob_name, const char* func_name,
				      hash_map funcs_visited);

static void write_bpf_program();


hash_map root_map = map_create();

hash_map knob_entrypoint_map = map_create();

struct list* entrypoint_list = list_create();

hash_map root_funcs_visited = map_create();

hash_map entrypoint_funcs_visited = map_create();

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
}

static void handle_knob(const char* graphs_directory, const char* knob_name) {
  char file_path[256];
  sprintf(file_path, "%s/%s", graphs_directory, knob_name);
  struct call_graph* graph = call_graph_load(file_path);

  map_insert(knob_entrypoint_map, knob_name, list_create());
  for (struct list_node* curr_entry = graph->entrypoints->head; curr_entry != NULL;
       curr_entry = curr_entry->next) {
    char* entrypoint = (char*) curr_entry->payload;
    append_knob_func_visited(knob_name, entrypoint, entrypoint_funcs_visited);
    if (is_in_kallsyms(entrypoint)) {
      if (!list_contains_str(entrypoint_list, entrypoint)) {
	list_append(entrypoint_list, entrypoint);
      }
      append_entrypoint_to_knob(knob_name, entrypoint);
    } else {
      get_kallsyms_callers(graph, entrypoint, knob_name, false, entrypoint_funcs_visited);
    }
  }
  
  struct list_node* curr_root = graph->func_names->head;
  for (size_t i = 0; i < graph->num_root_nodes; i++) {
    char* root_func = (char*) curr_root->payload;
    append_knob_func_visited(knob_name, root_func, root_funcs_visited);
    if (is_in_kallsyms(root_func)) {
      append_knob_to_root(root_func, knob_name);
      get_root_entrypoints(graph, root_func, knob_name);
    } else {
      get_kallsyms_callers(graph, root_func, knob_name, true, root_funcs_visited);
    }
    curr_root = curr_root->next;
  }
}

static void get_kallsyms_callers(struct call_graph* graph, const char* root,
				 const char* knob_name, bool is_root,
				 hash_map funcs_visited) {
  struct graph_node* node = (struct graph_node*) map_get(graph->nodes, root);
  struct list* callers = map_get_key_list(node->callers);
  for (struct list_node* curr = callers->head; curr != NULL; curr = curr->next) {
    char* curr_caller = (char*) curr->payload;
    if (!contains_knob_func_visited(knob_name, curr_caller, funcs_visited)) {
      append_knob_func_visited(knob_name, curr_caller, funcs_visited);
      if (is_in_kallsyms(curr_caller)) {
	if (is_root) {
	  append_knob_to_root(curr_caller, knob_name);
	  get_root_entrypoints(graph, curr_caller, knob_name);
	} else {
	  if (!list_contains_str(entrypoint_list, curr_caller)) {
	    list_append(entrypoint_list, curr_caller);
	  }
	  append_entrypoint_to_knob(knob_name, curr_caller);
	}
      } else {
	get_kallsyms_callers(graph, curr_caller, knob_name, is_root, funcs_visited);
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
  hash_map knob_map;
  if (map_contains(root_map, root_func)) {
    knob_map = (hash_map) map_get(root_map, root_func);
  } else {
    knob_map = map_create();
    map_insert(root_map, root_func, knob_map);
  }

  if (!map_contains(knob_map, knob_name)) {
    map_insert(knob_map, knob_name, list_create());
  }
}

static void append_entrypoint_to_knob(const char* knob_name, const char* entrypoint) {
  struct list* knob_entrypoint_list = (struct list*) map_get(knob_entrypoint_map, knob_name);
  if (!list_contains_str(knob_entrypoint_list, entrypoint)) {
    list_append(knob_entrypoint_list, entrypoint);
  }
}

static void get_root_entrypoints(struct call_graph* graph, const char* root_func,
				 const char* knob_name) {
  struct list* knob_entrypoints = (struct list*) map_get(knob_entrypoint_map, knob_name);

  hash_map root_knob_map = (hash_map) map_get(root_map, root_func);
  struct list* root_entrypoints = (struct list*) map_get(root_knob_map, knob_name);
  struct list* funcs_visited = list_create();

  get_entrypoint_callers(graph, knob_entrypoints, root_entrypoints,
			 funcs_visited, root_func);

  list_free_nodes(funcs_visited);
}

static void get_entrypoint_callers(struct call_graph* graph,
				   struct list* knob_entrypoints,
				   struct list* root_entrypoints,
				   struct list* funcs_visited,
				   const char* func) {
  if (list_contains_str(knob_entrypoints, func)) {
    list_append(root_entrypoints, func);
    return;
  }
  list_append(funcs_visited, func);

  struct graph_node* node = (struct graph_node*) map_get(graph->nodes, func);
  struct list* callers = map_get_key_list(node->callers);
  for (struct list_node* curr = callers->head; curr != NULL; curr = curr->next) {
    char* caller = (char*) curr->payload;
    if (!list_contains_str(funcs_visited, caller)) {
      get_entrypoint_callers(graph, knob_entrypoints, root_entrypoints, funcs_visited, caller);
    }
  }
}
 
static bool contains_knob_func_visited(const char* knob_name, const char* func_name,
					hash_map funcs_visited) {
  if (!map_contains(funcs_visited, knob_name)) {
    return false;
  }

  struct list* visited_list = (struct list*) map_get(funcs_visited, knob_name);
  return list_contains_str(visited_list, func_name);
}

 static void append_knob_func_visited(const char* knob_name, const char* func_name,
				      hash_map funcs_visited) {
  struct list* funcs_visited_list;
  if (map_contains(funcs_visited, knob_name)) {
    funcs_visited_list = (struct list*) map_get(funcs_visited, knob_name);
  } else {
    funcs_visited_list = list_create();
    map_insert(funcs_visited, knob_name, funcs_visited_list);
  }

  list_append(funcs_visited_list, func_name);
}

static void write_bpf_program() {
  FILE* f = fopen("bpf_hook_funcs.c", "w");
  if (f == NULL) {
    perror("Failed to create BPF program: ");
    return;
  }
  fprintf(f, "#include \"vmlinux.h\"\n");
  fprintf(f, "#include <bpf/bpf_helpers.h>\n");
  fprintf(f, "#include <bpf/bpf_tracing.h>\n");
  fprintf(f, "#include <bpf/bpf_core_read.h>\n");
  fprintf(f, "\n");

  fprintf(f, "char LICENSE[] SEC(\"license\") = \"Dual BSD/GPL\";\n");
  fprintf(f, "\n");

  fprintf(f, "struct {\n");
  fprintf(f, "  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);\n");
  fprintf(f, "  __type(key, uint32_t);\n");
  fprintf(f, "  __type(value, bool);\n");
  fprintf(f, "  __uint(max_entries, %ld);\n", entrypoint_list->len);
  fprintf(f, "} flag_map SEC(\".maps\");\n");
  fprintf(f, "\n");

  for (struct list_node* curr_entry = entrypoint_list->head; curr_entry != NULL;
       curr_entry = curr_entry->next) {
    char* entrypoint = (char*) curr_entry->payload;
    if (!map_contains(root_map, entrypoint)) {
      fprintf(f, "SEC(\"kprobe/%s\")\n", entrypoint);
      fprintf(f, "int kprobe__%s(struct pt_regs* ctx) {\n", entrypoint);
      fprintf(f, "  uint32_t index = %ld;\n", curr_entry->index);
      fprintf(f, "  bool flag = true;\n");
      fprintf(f, "  bpf_map_update_elem(&flag_map, &index, &flag, BPF_ANY);\n");
      fprintf(f, "  return 0;\n");
      fprintf(f, "}\n");
      fprintf(f, "\n");
    }
    fprintf(f, "SEC(\"kretprobe/%s\")\n", entrypoint);
    fprintf(f, "int kretprobe__%s(struct pt_regs* ctx) {\n", entrypoint);
    fprintf(f, "  uint32_t index = %ld;\n", curr_entry->index);
    fprintf(f, "  bool flag = false;\n");
    fprintf(f, "  bpf_map_update_elem(&flag_map, &index, &flag, BPF_ANY);\n");
    fprintf(f, "  return 0;\n");
    fprintf(f, "}\n");
    fprintf(f, "\n");
  }

  

  struct list* overall_entrypoints_visited = list_create();
  struct list* root_funcs = map_get_key_list(root_map);
  for (struct list_node* curr_root = root_funcs->head; curr_root != NULL;
       curr_root = curr_root->next) {
    char* root_func = (char*) curr_root->payload;
    if (strcmp(root_func, "x86_perf_rdpmc_index") == 0) {
      int test = 1;
    }
    fprintf(f, "SEC(\"kprobe/%s\")\n", root_func);
    fprintf(f, "int kprobe__%s(struct pt_regs* ctx) {\n", root_func);
    struct list* knob_entrypoints_visited = list_create();
    hash_map root_knob_map = (hash_map) map_get(root_map, root_func);
    struct list* knob_list = map_get_key_list(root_knob_map);
    for (struct list_node* curr_knob = knob_list->head; curr_knob != NULL;
	 curr_knob = curr_knob->next) {
      char* knob = (char*) curr_knob->payload;
      struct list* knob_entrypoint_list = (struct list*) map_get(root_knob_map, knob);

      if (list_contains_str(entrypoint_list, root_func) && !
	  list_contains_str(overall_entrypoints_visited, root_func)) {
	size_t root_entry_idx = list_find_str(entrypoint_list, root_func);
	fprintf(f, "  uint32_t index = %ld;\n", root_entry_idx);
	fprintf(f, "  bool flag = true;\n");
	fprintf(f, "  bpf_map_update_elem(&flag_map, &index, &flag, BPF_ANY);\n");
	list_append(overall_entrypoints_visited, root_func);
      }
      if (list_contains_str(knob_entrypoint_list, root_func) || knob_entrypoint_list->len == 0) {
	fprintf(f, "  bpf_printk(\"KPROBE_HIT %s %s %s\");\n", knob, root_func, root_func);
      } else {
	for (struct list_node* curr_entry = knob_entrypoint_list->head; curr_entry != NULL;
	     curr_entry = curr_entry->next) {
	  char* entrypoint = (char*) curr_entry->payload;
	  size_t entrypoint_idx = list_find_str(entrypoint_list, entrypoint);
	  if (!list_contains_str(knob_entrypoints_visited, entrypoint)) {
	    fprintf(f, "  uint32_t %s_index = %ld;\n", entrypoint, entrypoint_idx);
	    fprintf(f, "  bool* %s_flag = bpf_map_lookup_elem(&flag_map, &%s_index);\n", entrypoint, entrypoint);
	    fprintf(f, "  if (%s_flag == NULL) {\n", entrypoint);
	    fprintf(f, "    bpf_printk(\"KPROBE_ERROR: %s_flag not found\");\n", entrypoint);
	    fprintf(f, "    return 1;\n");
	    fprintf(f, "  }\n");
	  }
	  fprintf(f, "  if (*%s_flag) {\n", entrypoint);
	  fprintf(f, "    bpf_printk(\"KPROBE_HIT %s %s %s\");\n", knob, entrypoint, root_func);
	  fprintf(f, "  }\n");
	  fprintf(f, "\n");
	  
	  list_append(knob_entrypoints_visited, entrypoint);
	}
      }
    }
    fprintf(f, "}\n");
    fprintf(f, "\n");
    list_free_nodes(knob_entrypoints_visited);
  }

  fclose(f);
}
