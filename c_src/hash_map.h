/**
 * @file hash_map.h
 * @brief 简单的字符串哈希映射（用于IP到ID的映射）
 * 
 * 提供字符串键到整数ID的哈希表功能
 */

#ifndef HASH_MAP_H
#define HASH_MAP_H

#include "common.h"

typedef struct {
    char key[MAX_IP_LEN];
    int value;
    bool occupied;
} HashEntry;

typedef struct {
    HashEntry* entries;
    int capacity;
    int size;
} HashMap;

HashMap* hash_map_create(int initial_capacity);
int hash_map_put(HashMap* map, const char* key, int value);
int hash_map_get(HashMap* map, const char* key, int* out_value);
void hash_map_destroy(HashMap* map);
int hash_map_size(HashMap* map);
char* hash_map_get_key_by_index(HashMap* map, int index);

#endif
