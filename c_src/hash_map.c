/**
 * @file hash_map.c
 * @brief 哈希映射实现
 * 
 * 使用线性探测解决冲突的哈希表，用于存储字符串键到整数值的映射
 */

#include "hash_map.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * @brief 计算字符串的哈希值
 * 
 * @param key 字符串键
 * @param capacity 哈希表容量
 * @return 哈希值
 */
static unsigned int hash(const char* key, int capacity) {
    unsigned int h = 0;
    // 使用DJB2哈希算法
    while (*key) {
        h = (h << 5) + h + *key++;
    }
    return h % capacity;
}

/**
 * @brief 创建哈希映射
 * 
 * @param initial_capacity 初始容量
 * @return 哈希映射指针，失败返回NULL
 */
HashMap* hash_map_create(int initial_capacity) {
    // 分配哈希表结构体
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    if (!map) return NULL;
    
    // 初始化哈希表参数
    map->capacity = initial_capacity > 0 ? initial_capacity : INITIAL_CAPACITY;
    map->size = 0;
    
    // 分配并初始化条目数组
    map->entries = (HashEntry*)calloc(map->capacity, sizeof(HashEntry));
    if (!map->entries) {
        free(map);
        return NULL;
    }
    
    return map;
}

/**
 * @brief 扩容哈希映射
 * 
 * @param map 哈希映射指针
 */
static void hash_map_resize(HashMap* map) {
    // 计算新容量
    int new_capacity = map->capacity * GROWTH_FACTOR;
    
    // 分配新的条目数组
    HashEntry* new_entries = (HashEntry*)calloc(new_capacity, sizeof(HashEntry));
    if (!new_entries) return;
    
    // 重新哈希所有现有条目
    for (int i = 0; i < map->capacity; i++) {
        if (map->entries[i].occupied) {
            unsigned int h = hash(map->entries[i].key, new_capacity);
            // 线性探测找到空位置
            while (new_entries[h].occupied) {
                h = (h + 1) % new_capacity;
            }
            new_entries[h] = map->entries[i];
        }
    }
    
    // 释放旧数组并更新哈希表参数
    free(map->entries);
    map->entries = new_entries;
    map->capacity = new_capacity;
}

/**
 * @brief 向哈希映射中插入或更新键值对
 * 
 * @param map 哈希映射指针
 * @param key 字符串键
 * @param value 整数值
 * @return 成功返回SUCCESS，失败返回错误码
 */
int hash_map_put(HashMap* map, const char* key, int value) {
    if (!map || !key) return ERR_INVALID_INPUT;
    
    // 如果负载因子超过0.7，先扩容
    if (map->size >= map->capacity * 0.7) {
        hash_map_resize(map);
    }
    
    // 计算哈希值
    unsigned int h = hash(key, map->capacity);
    
    // 线性探测查找或插入
    while (map->entries[h].occupied) {
        // 如果键已存在，更新值
        if (strcmp(map->entries[h].key, key) == 0) {
            map->entries[h].value = value;
            return SUCCESS;
        }
        h = (h + 1) % map->capacity;
    }
    
    // 插入新键值对
    strncpy(map->entries[h].key, key, MAX_IP_LEN - 1);
    map->entries[h].key[MAX_IP_LEN - 1] = '\0';
    map->entries[h].value = value;
    map->entries[h].occupied = true;
    map->size++;
    
    return SUCCESS;
}

/**
 * @brief 从哈希映射中获取键对应的值
 * 
 * @param map 哈希映射指针
 * @param key 字符串键
 * @param out_value 输出值指针
 * @return 成功返回SUCCESS，未找到返回ERR_NOT_FOUND，失败返回错误码
 */
int hash_map_get(HashMap* map, const char* key, int* out_value) {
    if (!map || !key || !out_value) return ERR_INVALID_INPUT;
    
    // 计算哈希值
    unsigned int h = hash(key, map->capacity);
    int start_h = h;
    
    // 线性探测查找键
    while (map->entries[h].occupied) {
        if (strcmp(map->entries[h].key, key) == 0) {
            *out_value = map->entries[h].value;
            return SUCCESS;
        }
        h = (h + 1) % map->capacity;
        // 避免无限循环
        if (h == start_h) break;
    }
    
    return ERR_NOT_FOUND;
}

/**
 * @brief 销毁哈希映射，释放所有内存
 * 
 * @param map 哈希映射指针
 */
void hash_map_destroy(HashMap* map) {
    if (map) {
        if (map->entries) free(map->entries);
        free(map);
    }
}

/**
 * @brief 获取哈希映射当前键值对个数
 * 
 * @param map 哈希映射指针
 * @return 键值对个数，映射无效返回0
 */
int hash_map_size(HashMap* map) {
    return map ? map->size : 0;
}

/**
 * @brief 根据索引获取哈希映射中的键
 * 
 * @param map 哈希映射指针
 * @param index 索引
 * @return 键字符串，索引无效返回NULL
 */
char* hash_map_get_key_by_index(HashMap* map, int index) {
    if (!map || index < 0) return NULL;
    
    int count = 0;
    // 遍历查找第index个被占用的条目
    for (int i = 0; i < map->capacity; i++) {
        if (map->entries[i].occupied) {
            if (count == index) {
                return map->entries[i].key;
            }
            count++;
        }
    }
    return NULL;
}
