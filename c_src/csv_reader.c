/**
 * @file csv_reader.c
 * @brief CSV文件读取实现
 * 
 * 提供从CSV文件读取会话数据的功能
 */

#include "csv_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief 去除字符串首尾的空白字符
 * 
 * @param str 待处理的字符串
 * @return 处理后的字符串指针
 */
static char* trim(char* str) {
    // 跳过开头的空白字符
    while (*str == ' ' || *str == '\t') str++;
    if (*str == '\0') return str;
    
    // 从末尾开始去除空白字符
    char* end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) {
        *end = '\0';
        end--;
    }
    return str;
}

/**
 * @brief 解析一行CSV数据为会话结构体
 * 
 * @param line CSV行数据
 * @param session 输出的会话结构体指针
 * @return 成功返回SUCCESS，失败返回错误码
 */
static int parse_session(char* line, Session* session) {
    char* token;
    char* saveptr;
    int field_idx = 0;
    
    // 使用逗号分隔符解析CSV行
    token = strtok_s(line, ",", &saveptr);
    while (token != NULL) {
        char* trimmed = trim(token);
        // 根据字段索引解析不同的数据
        switch (field_idx) {
            case 0:
                // 源IP地址
                strncpy(session->source_ip, trimmed, MAX_IP_LEN - 1);
                session->source_ip[MAX_IP_LEN - 1] = '\0';
                break;
            case 1:
                // 目标IP地址
                strncpy(session->dest_ip, trimmed, MAX_IP_LEN - 1);
                session->dest_ip[MAX_IP_LEN - 1] = '\0';
                break;
            case 2:
                // 协议号
                session->protocol = atoi(trimmed);
                break;
            case 3:
                // 源端口
                session->src_port = atoi(trimmed);
                break;
            case 4:
                // 目标端口
                session->dst_port = atoi(trimmed);
                break;
            case 5:
                // 数据大小
                session->data_size = atoll(trimmed);
                break;
            case 6:
                // 持续时间
                session->duration = atof(trimmed);
                break;
        }
        field_idx++;
        token = strtok_s(NULL, ",", &saveptr);
    }
    
    // 确保至少解析了7个字段
    return field_idx >= 7 ? SUCCESS : ERR_INVALID_INPUT;
}

/**
 * @brief 从CSV文件读取数据并构建CSR图
 * 
 * @param file_path CSV文件路径
 * @return CSR图指针，失败返回NULL
 */
CSRGraph* read_csv_to_graph(const char* file_path) {
    // 打开CSV文件
    FILE* fp = fopen(file_path, "r");
    if (!fp) return NULL;
    
    // 创建空的CSR图
    CSRGraph* graph = csr_graph_create();
    if (!graph) {
        fclose(fp);
        return NULL;
    }
    
    char line[MAX_LINE_LEN];
    int line_num = 0;
    
    // 跳过表头行
    if (fgets(line, sizeof(line), fp)) {
        line_num++;
    }
    
    // 逐行读取并解析数据
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        Session session;
        memset(&session, 0, sizeof(Session));
        
        // 解析会话数据并添加到图中
        if (parse_session(line, &session) == SUCCESS) {
            csr_graph_add_session(graph, &session);
        }
    }
    
    fclose(fp);
    return graph;
}

/**
 * @brief 从CSV文件读取所有会话数据到动态数组
 * 
 * @param file_path CSV文件路径
 * @return 动态数组指针，包含所有会话数据，失败返回NULL
 */
DynamicArray* read_all_sessions(const char* file_path) {
    // 打开CSV文件
    FILE* fp = fopen(file_path, "r");
    if (!fp) return NULL;
    
    // 创建动态数组存储会话数据
    DynamicArray* sessions = dynamic_array_create(sizeof(Session), INITIAL_CAPACITY);
    if (!sessions) {
        fclose(fp);
        return NULL;
    }
    
    char line[MAX_LINE_LEN];
    int line_num = 0;
    
    // 跳过表头行
    if (fgets(line, sizeof(line), fp)) {
        line_num++;
    }
    
    // 逐行读取并解析数据
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        Session session;
        memset(&session, 0, sizeof(Session));
        
        // 解析会话数据并添加到数组中
        if (parse_session(line, &session) == SUCCESS) {
            dynamic_array_append(sessions, &session);
        }
    }
    
    fclose(fp);
    return sessions;
}
