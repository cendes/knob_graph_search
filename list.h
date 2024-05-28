#ifndef LIST_H
#define LIST_H

#include <stdbool.h>
#include <stdlib.h>

struct list_node {
  void* payload;
  size_t index;
  struct list_node* next;
};

struct list {
  struct list_node* head;
  struct list_node* tail;
  size_t len;
};

struct list* list_create();

int list_insert(struct list* list, const void* payload);

int list_append(struct list* list, const void* payload);

bool list_contains_val(struct list* list, size_t payload);

bool list_contains_str(struct list* list, const char* payload);

ssize_t list_find_str(struct list* list, const char* str);

void* list_get(struct list* list, size_t index);

void list_remove(struct list* list, ssize_t index);

struct list* list_copy(struct list* list, struct list_node* start_node);

struct list* list_combine(struct list* this_list, struct list* other_list);

void list_extend(struct list* this_list, struct list* other_list);

void list_free(struct list* list);

void list_free_nodes(struct list* list);

void list_custom_free(struct list* list, void (*free_func)(void*));

#endif /* LIST_H */
