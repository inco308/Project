/**
 * @file dynamic_array.c
 * @brief 动态数组实现
 * 
 * 提供可自动扩容的动态数组数据结构
 */

#include "dynamic_array.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief 创建动态数组
 * 
 * @param element_size 每个元素的大小（字节数）
 * @param initial_capacity 初始容量
 * @return 动态数组指针，失败返回NULL
 */
DynamicArray* dynamic_array_create(size_t element_size, int initial_capacity) {
    // 分配数组结构体
    DynamicArray* arr = (DynamicArray*)malloc(sizeof(DynamicArray));
    if (!arr) return NULL;
    
    // 初始化数组参数
    arr->element_size = element_size;
    arr->size = 0;
    arr->capacity = initial_capacity > 0 ? initial_capacity : INITIAL_CAPACITY;
    
    // 分配数据指针数组
    arr->data = (void**)malloc(arr->capacity * sizeof(void*));
    if (!arr->data) {
        free(arr);
        return NULL;
    }
    
    return arr;
}

/**
 * @brief 扩容动态数组
 * 
 * @param arr 动态数组指针
 * @return 成功返回SUCCESS，失败返回错误码
 */
static int dynamic_array_resize(DynamicArray* arr) {
    // 按增长因子计算新容量
    int new_capacity = arr->capacity * GROWTH_FACTOR;
    
    // 重新分配数据数组
    void** new_data = (void**)realloc(arr->data, new_capacity * sizeof(void*));
    if (!new_data) return ERR_MEMORY;
    
    // 更新数组参数
    arr->data = new_data;
    arr->capacity = new_capacity;
    return SUCCESS;
}

/**
 * @brief 向动态数组末尾添加元素
 * 
 * @param arr 动态数组指针
 * @param element 待添加的元素指针
 * @return 成功返回SUCCESS，失败返回错误码
 */
int dynamic_array_append(DynamicArray* arr, void* element) {
    if (!arr || !element) return ERR_INVALID_INPUT;
    
    // 如果容量不足，先扩容
    if (arr->size >= arr->capacity) {
        int ret = dynamic_array_resize(arr);
        if (ret != SUCCESS) return ret;
    }
    
    // 分配新元素内存并复制数据
    void* new_element = malloc(arr->element_size);
    if (!new_element) return ERR_MEMORY;
    memcpy(new_element, element, arr->element_size);
    
    // 添加到数组末尾
    arr->data[arr->size] = new_element;
    arr->size++;
    return SUCCESS;
}

/**
 * @brief 获取动态数组指定索引的元素
 * 
 * @param arr 动态数组指针
 * @param index 元素索引
 * @return 元素指针，索引无效返回NULL
 */
void* dynamic_array_get(DynamicArray* arr, int index) {
    if (!arr || index < 0 || index >= arr->size) return NULL;
    return arr->data[index];
}

/**
 * @brief 销毁动态数组，释放所有内存
 * 
 * @param arr 动态数组指针
 */
void dynamic_array_destroy(DynamicArray* arr) {
    if (arr) {
        if (arr->data) {
            // 释放每个元素的内存
            for (int i = 0; i < arr->size; i++) {
                if (arr->data[i]) free(arr->data[i]);
            }
            // 释放数据指针数组
            free(arr->data);
        }
        // 释放数组结构体
        free(arr);
    }
}

/**
 * @brief 获取动态数组当前元素个数
 * 
 * @param arr 动态数组指针
 * @return 元素个数，数组无效返回0
 */
int dynamic_array_size(DynamicArray* arr) {
    return arr ? arr->size : 0;
}
