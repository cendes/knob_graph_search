#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "hash_map.h"
#include "utils.h"
#include "call_graph.h"

static const char* FUNCS_TO_IGNORE[] = {"main", "test", "init"};

static void search_call_graph(struct call_graph* graph, const char* curr_func,
                              const char* perf_file, struct list* matches);

static void write_matches(struct list* matches, const char* filename);

static struct list* funcs_visited = list_create();

int main(int argc, char* argv[]) {
  if (argc < 4) {
    printf("Usage: ./search_call_graph KNOB_NAME GRAPH_DATABASE PERF_CALL_GRAPH [OUTPUT_DIR]\n");
    return EXIT_FAILURE;
  }
  char* knob_name = argv[1];
  char* database_file = argv[2];
  char* perf_call_graph = argv[3];
  const char* output_dir;
  if (argc >= 5) {
    output_dir = argv[4];
  } else {
    output_dir = ".";
  }

  struct call_graph* graph = call_graph_load(database_file);
  if (graph == NULL) {
    perror("Could not load call graph: ");
    return EXIT_FAILURE;
  }

  struct list* matches = list_create();
  struct list_node* curr_root = graph->func_names->head;
  for (size_t i = 0; i < graph->num_root_nodes; i++) {
    char* root_func = (char*) curr_root->payload;
    search_call_graph(graph, root_func, perf_call_graph, matches);
    curr_root = curr_root->next;
  }

  if (matches->len > 0) {
    char matches_filename[4096];
    sprintf(matches_filename, "%s/%s_matches.txt", output_dir, knob_name);
    write_matches(matches, matches_filename);
  }
}

static void search_call_graph(struct call_graph* graph, const char* curr_func,
                              const char* perf_file, struct list* matches) {
  if (utils_str_in_array(FUNCS_TO_IGNORE, curr_func, UTILS_SIZEOF_ARR(FUNCS_TO_IGNORE))) {
    return;
  }
  char command[256];
  sprintf(command, "grep \"\\<%s\\>\" %s", curr_func, perf_file);
  int ret = system(command);
  list_append(funcs_visited, curr_func);
  if (ret == 0) {
    list_append(matches, curr_func);
  } else {
    struct graph_node* func_node = (struct graph_node*) map_get(graph->nodes, curr_func);
    struct list* caller_list = map_get_key_list(func_node->callers);
    for (struct list_node* curr = caller_list->head; curr != NULL; curr = curr->next) {
      char* caller = (char*) curr->payload;
      if (!list_contains_str(funcs_visited, caller)) {
        search_call_graph(graph, caller, perf_file, matches);
      }
    }
  }
}

static void write_matches(struct list* matches, const char* filename) {
  FILE* f = fopen(filename, "w");
  if (f == NULL) {
    perror("Could not write matches: ");
    return;
  }

  for (struct list_node* curr = matches->head; curr != NULL; curr = curr->next) {
    fprintf(f, "%s\n", (char*) curr->payload);
  }
  
  fclose(f);
}
