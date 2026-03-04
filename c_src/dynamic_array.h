/**
 * @file dynamic_array.h
 * @brief 动态数组实现
 * 
 * 提供可动态扩容的数组功能
 */

#ifndef DYNAMIC_ARRAY_H
#define DYNAMIC_ARRAY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    void** data;
    int size;
    int capacity;
    size_t element_size;
} DynamicArray;

DynamicArray* dynamic_array_create(size_t element_size, int initial_capacity);
int dynamic_array_append(DynamicArray* arr, void* element);
void* dynamic_array_get(DynamicArray* arr, int index);
void dynamic_array_destroy(DynamicArray* arr);
int dynamic_array_size(DynamicArray* arr);

#endif
