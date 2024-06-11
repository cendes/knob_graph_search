#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "list.h"

struct list* list_create() {
  struct list* list = (struct list*) malloc(sizeof(struct list));
  if (list == NULL) {
    return NULL;
  }
  
  list->head = NULL;
  list->tail = NULL;
  list->len = 0;
  return list;
}

int list_insert(struct list* list, const void* payload) {
  struct list_node* new_node = (struct list_node*) malloc(sizeof(struct list_node));
  if (new_node == NULL) {
    return -1;
  }
  
  new_node->payload = (void*) payload;
  new_node->index = 0;
  new_node->next = list->head;
  list->head = new_node;
  if (list->tail == NULL) {
    list->tail = new_node;
  }
  list->len++;

  for (struct list_node* curr = new_node->next; curr != NULL; curr = curr->next) {
    curr->index++;
  }
  
  return 0;
}

int list_append(struct list* list, const void* payload) {
  if (list->head == NULL) {
    return list_insert(list, payload);
  } else {
    struct list_node* new_node = (struct list_node*) malloc(sizeof(struct list_node));
    if (new_node == NULL) {
      return -1;
    }
    
    new_node->payload = (void*) payload;
    new_node->index = list->len;
    new_node->next = NULL;
    list->tail->next = new_node;
    list->tail = new_node;
    list->len++;

    return 0;
  }
}

bool list_contains_val(struct list* list, size_t payload) {
  for (struct list_node* curr = list->head; curr != NULL; curr = curr->next) {
    if ((size_t) curr->payload == payload) {
      return true;
    }
  }

  return false;
}

bool list_contains_str(struct list* list, const char* payload) {
  for (struct list_node* curr = list->head; curr != NULL; curr = curr->next) {
    if (strcmp((char*) curr->payload, payload) == 0) {
      return true;
    }
  }

  return false;
}

void* list_get(struct list* list, size_t index) {
  for (struct list_node* curr = list->head; curr != NULL; curr = curr->next) {
    if (curr->index == index) {
      return curr->payload;
    }
  }
  
  return NULL;
}

struct list_node* list_get_node(struct list* list, size_t index) {
  for (struct list_node* curr = list->head; curr != NULL; curr = curr->next) {
    if (curr->index == index) {
      return curr;
    }
  }
  
  return NULL;
}

ssize_t list_find_str(struct list* list, const char* str) {
  for (struct list_node* curr = list->head; curr != NULL; curr = curr->next) {
    if (strcmp((char*) curr->payload, str) == 0) {
      return curr->index;
    }
  }

  return -1;
}

void list_remove(struct list* list, ssize_t index) {
  size_t real_index = index < 0 ? list->len + index : index;
  struct list_node* node_after;
  if (real_index >= list->len) {
    return;
  } else if (real_index == 0) {
    list->head = list->head->next;
    if (list->head == NULL) {
      list->tail = NULL;
      node_after = NULL;
    } else {
      node_after = list->head->next;
    }
  } else {
    size_t curr_index = 0;
    struct list_node* curr = list->head;
    while (curr_index < real_index - 1) {
      curr_index++;
      curr = curr->next;
    }
    if (curr->next == list->tail) {
      list->tail = curr;
    }
    curr->next = curr->next->next;
    node_after = curr->next;
  }

  list->len--;
  for (struct list_node* curr = node_after; curr != NULL; curr = curr->next) {
    curr->index--;
  }
}

struct list* list_copy(struct list* list, struct list_node* start_node) {
  struct list* new_list = list_create();
  if (start_node == NULL) {
    //return new_list;
    start_node = list->head;
  } else {
    start_node = start_node->next;
  }

  for (struct list_node* curr = start_node; curr != NULL; curr = curr->next) {
    list_append(new_list, curr->payload);
  }

  return new_list;
}

struct list* list_combine(struct list* this_list, struct list* other_list) {
  if (this_list->len == 0) {
    return list_copy(other_list, NULL);
  }
  
  struct list* this_list_cpy = list_copy(this_list, NULL);
  if (other_list->len == 0) {
    return this_list_cpy;
  }
  
  struct list* other_list_cpy = list_copy(other_list, NULL);
  
  if (this_list_cpy->tail == NULL) {
    this_list_cpy->head = other_list_cpy->head;
    this_list_cpy->tail = other_list_cpy->tail;
  } else {
    this_list_cpy->tail->next = other_list_cpy->head;
    this_list_cpy->tail = other_list_cpy->tail;
  }

  size_t curr_index = this_list_cpy->len;
  for (struct list_node* curr = other_list_cpy->head; curr != NULL; curr = curr->next) {
    curr->index = curr_index;
    curr_index++;
  }
  this_list_cpy->len = curr_index;
  free(other_list_cpy);
  return this_list_cpy;
}

void list_free(struct list* list) {
  if (list != NULL) {
    struct list_node* curr = list->head;
    while (curr != NULL) {
      struct list_node* next = curr->next;
      free(curr->payload);
      free(curr);
      curr = next;
    }
    free(list);
  }
}

void list_free_nodes(struct list* list) {
  if (list != NULL) {
    struct list_node* curr = list->head;
    while (curr != NULL) {
      struct list_node* next = curr->next;
      free(curr);
      curr = next;
    }
    free(list);
  }
}

void list_custom_free(struct list* list, void (*free_func)(void*)) {
  if (list != NULL) {
    struct list_node* curr = list->head;
    while (curr != NULL) {
      struct list_node* next = curr->next;
      (*free_func)(curr->payload);
      free(curr);
      curr = next;
    }
    free(list);
  }
}
