#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "hash_map.h"
#include "token_get.h"
#include "var_search.h"
#include "func_call_parse.h"
#include "database.h"

static FILE* func_vars_visited_file;

static FILE* visited_func_decls_file;

static FILE* macros_return_range_file;

static char* read_database_string(FILE* file);

static struct list* read_string_list(FILE* file);

static void write_database_string(const char* string, FILE* file);

static void write_string_list(struct list* string_list, FILE* file);

hash_map database_read_func_vars_visited(const char* filename) {
  func_vars_visited_file = fopen(filename, "a+");
  if (func_vars_visited_file == NULL) {
    perror("Could not open database: ");
    return NULL;
  }

  hash_map func_var_database = map_create();
  char* func;
  do {
    func = read_database_string(func_vars_visited_file);
    if (func != NULL) {
      if (strcmp(func, "EMIT") == 0) {
        int test = 1;
      }
      char* var = read_database_string(func_vars_visited_file);
      struct list* var_refs = read_string_list(func_vars_visited_file);
      struct list* full_var_refs = read_string_list(func_vars_visited_file);

      struct func_var_entry* entry =
        (struct func_var_entry*) malloc(sizeof(struct func_var_entry));
      entry->var_refs = var_refs;
      entry->full_var_refs = full_var_refs;
      entry->locked = false;
      
      hash_map var_map;
      if (map_contains(func_var_database, func)) {
        var_map = (hash_map) map_get(func_var_database, func);
      } else {
        var_map = map_create();
        map_insert(func_var_database, func, var_map);
      }
      map_insert(var_map, var, entry);
    }
  } while (func != NULL);

  return func_var_database;
}

void database_read_visited_func_decls(const char* filename) {
  visited_func_decls_file = fopen(filename, "a+");
  if (visited_func_decls_file == NULL) {
    perror("Could not open database: ");
    return;
  }

  hash_map visited_funcs_decl_database = map_create();
  char* func;
  do {
    func = read_database_string(visited_func_decls_file);
    if (func != NULL) {
      char* func_declaration = read_database_string(visited_func_decls_file);
      char* source_file = read_database_string(visited_func_decls_file);
      size_t line_number;
      fread(&line_number, sizeof(size_t), 1, visited_func_decls_file);
      func_insert_func_decl_entry(func, func_declaration, source_file, line_number);
      free(source_file);
    }
  } while(func != NULL);
}

void database_read_macros_return_range(const char* filename) {
  macros_return_range_file = fopen(filename, "a+");
  if (visited_func_decls_file == NULL) {
    perror("Could not open database: ");
    return;
  }

  char* macro;
  do {
    macro = read_database_string(macros_return_range_file);
    if (macro != NULL) {
      char* source_file = read_database_string(macros_return_range_file);
      size_t return_start;
      fread(&return_start, sizeof(size_t), 1, macros_return_range_file);
      size_t return_end;
      fread(&return_end, sizeof(size_t), 1, macros_return_range_file);
      token_insert_macro_return_entry(macro, source_file, return_start, return_end);
    }
  } while (macro != NULL);
}

static char* read_database_string(FILE* file) {
  size_t string_len;
  size_t bytes_read = fread(&string_len, sizeof(size_t), 1, file);
  if (bytes_read == 0 || string_len == 0) {
    return NULL;
  }
  
  char* string = (char*) malloc(string_len + 1);
  fread(string, 1, string_len, file);
  string[string_len] = '\0';
  
  return string;
}

static struct list* read_string_list(FILE* file) {
  size_t num_strings;
  fread(&num_strings, sizeof(size_t), 1, file);
  struct list* string_list = list_create();
  for (size_t i = 0; i < num_strings; i++) {
    char* string = read_database_string(file);
    if (string == NULL) {
      string = "";
    }
    list_append(string_list, string);
  }

  return string_list;
}

void database_write_func_vars_visited_entry(const char* func, const char* var,
                                            struct func_var_entry* entry) {
  write_database_string(func, func_vars_visited_file);
  write_database_string(var, func_vars_visited_file);
  write_string_list(entry->var_refs, func_vars_visited_file);
  write_string_list(entry->full_var_refs, func_vars_visited_file);
  
  int ret = fflush(func_vars_visited_file);
  if (ret != 0) {
    perror("Database write failed: ");
  }
}

void database_write_visited_func_decls_entry(const char* func,
                                             const char* func_declaration,
                                             const char* source_file,
                                             size_t line_number) {
  write_database_string(func, visited_func_decls_file);
  write_database_string(func_declaration, visited_func_decls_file);
  write_database_string(source_file, visited_func_decls_file);
  fwrite(&line_number, sizeof(size_t), 1, visited_func_decls_file);

  int ret = fflush(visited_func_decls_file);
  if (ret != 0) {
    perror("Database write failed: ");
  }
}

void database_write_macros_return_range(const char* macro, const char* source_file,
                                         size_t return_start, size_t return_end) {
  write_database_string(macro, macros_return_range_file);
  write_database_string(source_file, macros_return_range_file);
  fwrite(&return_start, sizeof(size_t), 1, macros_return_range_file);
  fwrite(&return_end, sizeof(size_t), 1, macros_return_range_file);

  int ret = fflush(macros_return_range_file);
  if (ret != 0) {
    perror("Database write failed: ");
  }
}

static void write_database_string(const char* string, FILE* file) {
  if (string == NULL) {
    size_t zero = 0;
    fwrite(&zero, sizeof(size_t), 1, file);
    return;
  }
  
  size_t string_len = strlen(string);
  fwrite(&string_len, sizeof(size_t), 1, file);
  fwrite(string, 1, string_len, file);
}

static void write_string_list(struct list* string_list, FILE* file) {
  if (string_list == NULL) {
    size_t zero = 0;
    fwrite(&zero, sizeof(size_t), 1, file);
    return;
  }
  
  fwrite(&string_list->len, sizeof(size_t), 1, file);
  for (struct list_node* curr = string_list->head; curr != NULL; curr = curr->next) {
    size_t string_len = strlen((char*) curr->payload);
    fwrite(&string_len, sizeof(size_t), 1, file);
    fwrite(curr->payload, 1, string_len, file);
  }
}
