#ifndef HASH_MAP_H
#define HASH_MAP_H

#ifdef __cplusplus
#define EXTERNC extern "C"
#else
#define EXTERNC
#endif

#include <stdbool.h>

typedef void* hash_map;

EXTERNC hash_map map_create();

EXTERNC void map_insert(hash_map map, const char* key, const void* value);

EXTERNC bool map_contains(hash_map map, const char* key);

EXTERNC void* map_get(hash_map map, const char* key);

EXTERNC void map_free(hash_map map);

EXTERNC void map_update(hash_map this_map, hash_map other_map);

EXTERNC struct list* map_get_key_list(hash_map map);

EXTERNC void map_remove(hash_map map, const char* key);

#undef EXTERNC

#endif /* HASH_MAP_H */
