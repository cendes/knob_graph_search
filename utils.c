#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"
#include "list.h"

size_t utils_split_str(const char* str, char*** str_arr) {
  char* str_tmp = (char*) malloc(strlen(str) + 1);
  strncpy(str_tmp, str, strlen(str) + 1);

  char** arr = (char**) malloc(sizeof(char*) * 256);
  arr[0] = str_tmp;
  char* token = strtok(str_tmp, " ");
  int arr_size = 1;
  while (token != NULL) {
    if (strlen(token) == 0) {
      int test = 1;
    }
    arr[arr_size] = token;
    token = strtok(NULL, " ");
    arr_size++;
  }

  *str_arr = (arr + 1);
  return arr_size - 1;
}

size_t utils_split_on_delim(const char* str, const char* delim, char*** str_arr) {
  char* str_tmp = (char*) malloc(strlen(str) + 1);
  strncpy(str_tmp, str, strlen(str) + 1);

  char** arr = (char**) malloc(sizeof(char*) * 256);
  arr[0] = str_tmp;
  char* token = strtok(str_tmp, delim);
  int arr_size = 1;
  while (token != NULL) {
    if (strlen(token) == 0) {
      int test = 1;
    }
    arr[arr_size] = token;
    token = strtok(NULL, delim);
    arr_size++;
  }

  *str_arr = (arr + 1);
  return arr_size - 1;
}

char* utils_read_file_line(const char* file_path, int line_num) {
  FILE* f = fopen(file_path, "r");
  if (f == NULL) {
    perror("Failed to open source file: ");
    return NULL;
  }
  
  char* line = NULL;
  size_t line_len = 0;
  for (int i = 0; i < line_num; i++) {
    int ret = getline(&line, &line_len, f);
    if (ret < 0) {
      fclose(f);
      perror("Failed to read line in file: ");
      return NULL;
    }
  }
  int ret = getline(&line, &line_len, f);
  if (ret < 0) {
    fclose(f);
    perror("Failed to read line in file: ");
    return NULL;
  }

  fclose(f);
  return line;
}

char* utils_trim_str(char* str) {
  char* original_str = str;
  for (char* s = str; *s != '\0' && isspace(*s); s++) {
    str++;
  }
  if (str != original_str) {
    char* new_str = (char*) malloc(strlen(str) + 1);
    strncpy(new_str, str, strlen(str) + 1);
    str = new_str;
  }
  if (strlen(str) == 0) {
    return str;
  }

  for (char* s = str + strlen(str) - 1; s != str && isspace(*s); s--) {
    *s = '\0';
  }

  return str;
}

void utils_truncate_str(char* str, int index) {
  int truncate_index;
  if (index < 0) {
    truncate_index = strlen(str) + index;
  } else {
    truncate_index = index;
  }
  str[truncate_index] = '\0';
}

void utils_free_str_arr(char** str_arr) {
  free(str_arr[-1]);
  free(str_arr - 1);
}

char** utils_get_sub_array(const char** array, int index) {
  char** sub_array = (char**) array;
  for (int i = 0; i < index; i++) {
    sub_array++;
  }
  return sub_array;
}

struct list* utils_get_cscope_output(const char* cmd) {
  FILE* f = popen(cmd, "r");
  if (f == NULL) {
    perror("Failed to run cscope query: ");
    return NULL;
  }

  struct list* var_refs = list_create();
  if (var_refs == NULL) {
    perror("Could not create var references list: ");
    return NULL;
  }

  char* line_buf = NULL;
  size_t len = 0;
  int bytes_read = 0;
  do {
    bytes_read = getline(&line_buf, &len, f);
    if (bytes_read > 0) {
      char* ref = (char*) malloc(bytes_read + 1);
      strncpy(ref, line_buf, bytes_read + 1);
      list_append(var_refs, ref);
    } else if (bytes_read == -1 && !feof(f)) {
      perror("Failed to read cscope output: ");
      return NULL;
    }
  } while (bytes_read >= 0);
  free(line_buf);
  if (var_refs->len == 0) {
    int test = 1;
  }

  pclose(f);
  return var_refs;
}

bool utils_char_in_array(const char* array, char chr, size_t array_len) {
  for (size_t i = 0; i < array_len; i++) {
    if (array[i] == chr) {
      return true;
    }
  }

  return false;
}

bool utils_val_in_array(const size_t* array, size_t val, size_t array_len) {
  for (size_t i = 0; i < array_len; i++) {
    if (array[i] == val) {
      return true;
    }
  }

  return false;
}

bool utils_str_in_array(const char** array, const char* str, size_t array_len) {
  for (size_t i = 0; i < array_len; i++) {
    if (strcmp(array[i], str) == 0) {
      return true;
    }
  }

  return false;
}

bool utils_substr_in_array(const char** array, const char* str, size_t array_len,
                           size_t substr_end) {
  for (size_t i = 0; i < array_len; i++) {
    if (strncmp(array[i], str, substr_end - 1) == 0) {
      return true;
    }
  }

  return false;
}

size_t utils_get_char_occurences(const char* str, char chr, size_t** indices) {
  if (indices != NULL) {
    *indices = (size_t*) malloc(strlen(str) * sizeof(size_t));
  }
  size_t num_occurences = 0;
  for (size_t i = 0; i < strlen(str); i++) {
    if (str[i] == chr) {
      if (indices != NULL) {
        (*indices)[num_occurences] = i;
      }
      num_occurences++;
    }
  }

  return num_occurences;
}

size_t utils_get_str_occurences(const char* str, const char* token, size_t** indices) {
  if (indices != NULL) {
    *indices = (size_t*) malloc(strlen(str) * sizeof(size_t));
  }
  size_t token_len = strlen(token);
  size_t num_occurences = 0;
  char* str_tmp = (char*) str;
  const char* curr_occurence;
  while ((curr_occurence = strstr(str_tmp, token)) != NULL) {
    if (indices != NULL) {
      (*indices)[num_occurences] = curr_occurence - str;
    }
    num_occurences++;
    str_tmp = (char*) (curr_occurence + token_len);
  }

  return num_occurences;
}

bool utils_isnumeric(const char* str) {
  if (strlen(str) == 0) {
    return false;
  }
  char* end_ptr;
  strtol(str, &end_ptr, 0);
  if (end_ptr < str + strlen(str)) {
    strtod(str, &end_ptr);
    return end_ptr == str + strlen(str);
  } else {
    return true;
  }
}

void utils_free_if_different(void* ptr_to_free, const void* ptr_to_cmp) {
  if (ptr_to_free != ptr_to_cmp) {
    free(ptr_to_free);
  }
}

void utils_free_if_both_different(void* ptr_to_free, const void* ptr_to_cmp1,
                                  const void* ptr_to_cmp2) {
  if (ptr_to_free != ptr_to_cmp1 && ptr_to_free != ptr_to_cmp2) {
    free(ptr_to_free);
  }
}
