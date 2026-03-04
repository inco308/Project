/**
 * @file common.h
 * @brief 通用定义与类型声明
 * 
 * 本文件包含项目通用的宏定义、类型声明和错误代码
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MAX_IP_LEN 64
#define MAX_LINE_LEN 2048
#define INITIAL_CAPACITY 128
#define GROWTH_FACTOR 2

#define SUCCESS 0
#define ERR_FILE_OPEN -1
#define ERR_MEMORY -2
#define ERR_INVALID_INPUT -3
#define ERR_NOT_FOUND -4

typedef struct {
    char source_ip[MAX_IP_LEN];
    char dest_ip[MAX_IP_LEN];
    int protocol;
    int src_port;
    int dst_port;
    int64_t data_size;
    double duration;
} Session;

typedef struct {
    int protocol;
    int64_t total_data_size;
    double total_duration;
} ProtocolTraffic;

typedef struct {
    char ip[MAX_IP_LEN];
    int64_t total_traffic;
    int64_t outgoing_traffic;
    int64_t incoming_traffic;
} NodeTraffic;

typedef struct {
    char ip[MAX_IP_LEN];
    int64_t total_traffic;
    double outgoing_ratio;
} SuspiciousNode;

int ip_to_uint32(const char* ip_str, uint32_t* out_ip);
int ip_in_range(const char* ip_str, const char* start_str, const char* end_str);

#endif
