/**
 * @file csr_graph.c
 * @brief CSR图结构实现
 * 
 * 使用CSR（Compressed Sparse Row）格式高效存储稀疏图
 */

#include "csr_graph.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * @brief 创建CSR图
 * 
 * @return CSR图指针，失败返回NULL
 */
CSRGraph* csr_graph_create(void) {
    CSRGraph* graph = (CSRGraph*)malloc(sizeof(CSRGraph));
    if (!graph) return NULL;
    
    // 初始化基本计数
    graph->node_count = 0;
    graph->edge_count = 0;
    graph->session_count = 0;
    
    // 创建IP到ID的哈希表，用于快速查找
    graph->ip_to_id = hash_map_create(INITIAL_CAPACITY);
    if (!graph->ip_to_id) {
        free(graph);
        return NULL;
    }
    
    // 初始化其他指针为NULL
    graph->id_to_ip = NULL;
    graph->node_total_traffic = NULL;
    graph->node_outgoing_traffic = NULL;
    graph->node_incoming_traffic = NULL;
    
    // 初始化row_ptr数组，CSR格式的行指针
    graph->row_ptr = (int*)malloc(sizeof(int));
    if (!graph->row_ptr) {
        hash_map_destroy(graph->ip_to_id);
        free(graph);
        return NULL;
    }
    graph->row_ptr[0] = 0;
    
    graph->edges = NULL;
    
    return graph;
}

/**
 * @brief 确保节点存在，不存在则创建
 * 
 * @param graph CSR图指针
 * @param ip IP地址字符串
 * @return 节点ID，失败返回-1
 */
static int csr_graph_ensure_node(CSRGraph* graph, const char* ip) {
    int node_id;
    // 检查节点是否已存在
    if (hash_map_get(graph->ip_to_id, ip, &node_id) == SUCCESS) {
        return node_id;
    }
    
    // 分配新节点ID
    node_id = graph->node_count;
    hash_map_put(graph->ip_to_id, ip, node_id);
    
    // 扩展id_to_ip数组
    char** new_id_to_ip = (char**)realloc(graph->id_to_ip, (node_id + 1) * sizeof(char*));
    if (!new_id_to_ip) return -1;
    graph->id_to_ip = new_id_to_ip;
    graph->id_to_ip[node_id] = (char*)malloc(MAX_IP_LEN);
    strncpy(graph->id_to_ip[node_id], ip, MAX_IP_LEN - 1);
    graph->id_to_ip[node_id][MAX_IP_LEN - 1] = '\0';
    
    // 扩展总流量数组
    int64_t* new_traffic = (int64_t*)realloc(graph->node_total_traffic, (node_id + 1) * sizeof(int64_t));
    if (!new_traffic) return -1;
    graph->node_total_traffic = new_traffic;
    graph->node_total_traffic[node_id] = 0;
    
    // 扩展出流量数组
    int64_t* new_outgoing = (int64_t*)realloc(graph->node_outgoing_traffic, (node_id + 1) * sizeof(int64_t));
    if (!new_outgoing) return -1;
    graph->node_outgoing_traffic = new_outgoing;
    graph->node_outgoing_traffic[node_id] = 0;
    
    // 扩展入流量数组
    int64_t* new_incoming = (int64_t*)realloc(graph->node_incoming_traffic, (node_id + 1) * sizeof(int64_t));
    if (!new_incoming) return -1;
    graph->node_incoming_traffic = new_incoming;
    graph->node_incoming_traffic[node_id] = 0;
    
    // 扩展row_ptr数组
    int* new_row_ptr = (int*)realloc(graph->row_ptr, (node_id + 2) * sizeof(int));
    if (!new_row_ptr) return -1;
    graph->row_ptr = new_row_ptr;
    graph->row_ptr[node_id + 1] = graph->row_ptr[node_id];
    
    graph->node_count++;
    return node_id;
}

/**
 * @brief 查找指定源节点和目标节点的边
 * 
 * @param graph CSR图指针
 * @param source 源节点ID
 * @param target 目标节点ID
 * @return 边的索引，未找到返回-1
 */
static int find_edge(CSRGraph* graph, int source, int target) {
    if (!graph || source < 0 || source >= graph->node_count) return -1;
    if (!graph->row_ptr || !graph->edges) return -1;
    
    int start = graph->row_ptr[source];
    int end = graph->row_ptr[source + 1];
    
    // 在源节点的出边中查找
    for (int i = start; i < end; i++) {
        if (graph->edges[i].target_node == target) {
            return i;
        }
    }
    return -1;
}

/**
 * @brief 添加一条边到CSR图
 * 
 * 将新边插入到正确位置以保持CSR格式
 * 
 * @param graph CSR图指针
 * @param source 源节点ID
 * @param target 目标节点ID
 */
static void csr_graph_add_edge(CSRGraph* graph, int source, int target) {
    int i;
    int insert_pos;
    EdgeData* new_edges;
    EdgeData* edge;
    
    if (!graph || source < 0 || source >= graph->node_count) return;
    
    // 扩展edges数组
    new_edges = (EdgeData*)realloc(graph->edges, (graph->edge_count + 1) * sizeof(EdgeData));
    if (!new_edges) return;
    graph->edges = new_edges;
    
    // 计算插入位置
    insert_pos = graph->row_ptr[source];
    
    // 将插入位置后的元素后移
    for (i = graph->edge_count; i > insert_pos; i--) {
        graph->edges[i] = graph->edges[i - 1];
    }
    
    // 初始化新边
    edge = &graph->edges[insert_pos];
    edge->target_node = target;
    edge->total_data_size = 0;
    edge->total_duration = 0.0;
    edge->protocol = 0;
    edge->src_port = 0;
    edge->dst_port = 0;
    memset(edge->protocol_traffic, 0, sizeof(edge->protocol_traffic));
    
    // 更新row_ptr数组（source之后的所有节点）
    for (i = source + 1; i <= graph->node_count; i++) {
        graph->row_ptr[i]++;
    }
    
    graph->edge_count++;
}

/**
 * @brief 添加一个会话到CSR图
 * 
 * @param graph CSR图指针
 * @param session 会话数据指针
 * @return 成功返回SUCCESS，失败返回错误码
 */
int csr_graph_add_session(CSRGraph* graph, Session* session) {
    if (!graph || !session) return ERR_INVALID_INPUT;
    
    // 确保源节点和目标节点存在
    int source_id = csr_graph_ensure_node(graph, session->source_ip);
    int dest_id = csr_graph_ensure_node(graph, session->dest_ip);
    
    if (source_id < 0 || dest_id < 0) return ERR_MEMORY;
    
    // 查找边是否已存在
    int edge_idx = find_edge(graph, source_id, dest_id);
    if (edge_idx < 0) {
        csr_graph_add_edge(graph, source_id, dest_id);
        edge_idx = find_edge(graph, source_id, dest_id);
    }
    
    // 更新边的数据
    if (edge_idx >= 0 && graph->edges) {
        EdgeData* edge = &graph->edges[edge_idx];
        edge->total_data_size += session->data_size;
        edge->total_duration += session->duration;
        edge->protocol = session->protocol;
        edge->src_port = session->src_port;
        edge->dst_port = session->dst_port;
        
        // 更新协议流量统计
        int proto = session->protocol;
        if (proto >= 0 && proto < MAX_PROTOCOLS) {
            edge->protocol_traffic[proto].protocol = proto;
            edge->protocol_traffic[proto].total_data_size += session->data_size;
            edge->protocol_traffic[proto].total_duration += session->duration;
        }
    }
    
    // 更新节点流量统计
    graph->node_total_traffic[source_id] += session->data_size;
    graph->node_total_traffic[dest_id] += session->data_size;
    graph->node_outgoing_traffic[source_id] += session->data_size;
    graph->node_incoming_traffic[dest_id] += session->data_size;
    
    graph->session_count++;
    
    return SUCCESS;
}

/**
 * @brief 获取会话总数
 * 
 * @param graph CSR图指针
 * @return 会话总数
 */
int csr_graph_get_session_count(CSRGraph* graph) {
    return graph ? graph->session_count : 0;
}

/**
 * @brief 根据IP获取节点ID
 * 
 * @param graph CSR图指针
 * @param ip IP地址字符串
 * @return 节点ID，未找到返回-1
 */
int csr_graph_get_node_id(CSRGraph* graph, const char* ip) {
    if (!graph || !ip) return -1;
    int id;
    if (hash_map_get(graph->ip_to_id, ip, &id) == SUCCESS) {
        return id;
    }
    return -1;
}

/**
 * @brief 根据节点ID获取IP
 * 
 * @param graph CSR图指针
 * @param node_id 节点ID
 * @return IP地址字符串，失败返回NULL
 */
const char* csr_graph_get_ip(CSRGraph* graph, int node_id) {
    if (!graph || node_id < 0 || node_id >= graph->node_count) return NULL;
    if (!graph->id_to_ip) return NULL;
    return graph->id_to_ip[node_id];
}

/**
 * @brief 获取节点总流量
 * 
 * @param graph CSR图指针
 * @param node_id 节点ID
 * @return 节点总流量
 */
int64_t csr_graph_get_node_traffic(CSRGraph* graph, int node_id) {
    if (!graph || node_id < 0 || node_id >= graph->node_count) return 0;
    if (!graph->node_total_traffic) return 0;
    return graph->node_total_traffic[node_id];
}

/**
 * @brief 获取节点出流量
 * 
 * @param graph CSR图指针
 * @param node_id 节点ID
 * @return 节点出流量
 */
int64_t csr_graph_get_node_outgoing_traffic(CSRGraph* graph, int node_id) {
    if (!graph || node_id < 0 || node_id >= graph->node_count) return 0;
    if (!graph->node_outgoing_traffic) return 0;
    return graph->node_outgoing_traffic[node_id];
}

/**
 * @brief 获取节点入流量
 * 
 * @param graph CSR图指针
 * @param node_id 节点ID
 * @return 节点入流量
 */
int64_t csr_graph_get_node_incoming_traffic(CSRGraph* graph, int node_id) {
    if (!graph || node_id < 0 || node_id >= graph->node_count) return 0;
    if (!graph->node_incoming_traffic) return 0;
    return graph->node_incoming_traffic[node_id];
}

/**
 * @brief 销毁CSR图
 * 
 * @param graph CSR图指针
 */
void csr_graph_destroy(CSRGraph* graph) {
    if (graph) {
        hash_map_destroy(graph->ip_to_id);
        if (graph->id_to_ip) {
            for (int i = 0; i < graph->node_count; i++) {
                free(graph->id_to_ip[i]);
            }
            free(graph->id_to_ip);
        }
        free(graph->row_ptr);
        free(graph->edges);
        free(graph->node_total_traffic);
        free(graph->node_outgoing_traffic);
        free(graph->node_incoming_traffic);
        free(graph);
    }
}

/**
 * @brief 获取节点总数
 * 
 * @param graph CSR图指针
 * @return 节点总数
 */
int csr_graph_get_node_count(CSRGraph* graph) {
    return graph ? graph->node_count : 0;
}

/**
 * @brief 获取边总数
 * 
 * @param graph CSR图指针
 * @return 边总数
 */
int csr_graph_get_edge_count(CSRGraph* graph) {
    return graph ? graph->edge_count : 0;
}
