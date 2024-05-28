#include <unordered_map>
#include <string>
#include <cstdlib>
#include "hash_map.h"
#include "list.h"

using namespace std;

hash_map map_create() {
  return new unordered_map<string, void*>();
}

void map_insert(hash_map map, const char* key, const void* value) {
  unordered_map<string, void*>* cpp_map = static_cast<unordered_map<string, void*>*>(map);
  string cpp_key(key);
  (*cpp_map)[cpp_key] = const_cast<void*>(value);
}

bool map_contains(hash_map map, const char* key) {
  unordered_map<string, void*>* cpp_map = static_cast<unordered_map<string, void*>*>(map);
  string cpp_key(key);
  return (*cpp_map).find(cpp_key) != (*cpp_map).end();
}

void* map_get(hash_map map, const char* key) {
  unordered_map<string, void*>* cpp_map = reinterpret_cast<unordered_map<string, void*>*>(map);
  string cpp_key(key);
  return (*cpp_map)[cpp_key];
}

void map_free(hash_map map) {
  unordered_map<string, void*>* cpp_map = static_cast<unordered_map<string, void*>*>(map);
  unordered_map<string, void*>:: iterator it;
  for (it = (*cpp_map).begin(); it != (*cpp_map).end(); it++) {
    //free(const_cast<char*>(it->first));
    free(it->second);
  }
  delete cpp_map;
}

void map_update(hash_map this_map, hash_map other_map) {
  unordered_map<string, void*>* cpp_this_map = static_cast<unordered_map<string, void*>*>(this_map);
  unordered_map<string, void*>* cpp_other_map = static_cast<unordered_map<string, void*>*>(other_map);
  unordered_map<string, void*>:: iterator it;
  for (it = (*cpp_other_map).begin(); it != (*cpp_other_map).end(); it++) {
    (*cpp_this_map)[it->first] = it->second;
  }
}

struct list* map_get_key_list(hash_map map) {
  unordered_map<string, void*>* cpp_map = reinterpret_cast<unordered_map<string, void*>*>(map);
  struct list* list = list_create();
  unordered_map<string, void*>:: iterator it;
  for (it = (*cpp_map).begin(); it != (*cpp_map).end(); it++) {
    const char* key = (it->first).c_str();
    list_append(list, key);
  }

  return list;
}

void map_remove(hash_map map, const char* key) {
  unordered_map<string, void*>* cpp_map = reinterpret_cast<unordered_map<string, void*>*>(map);
  string cpp_key(key);
  (*cpp_map).erase(cpp_key);
}
