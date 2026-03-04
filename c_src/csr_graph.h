/**
 * @file csr_graph.h
 * @brief CSR格式的图数据结构
 * 
 * 使用CSR（Compressed Sparse Row）格式高效存储稀疏图
 * 同时包含按协议统计的流量信息
 */

#ifndef CSR_GRAPH_H
#define CSR_GRAPH_H

#include "common.h"
#include "hash_map.h"

#define MAX_PROTOCOLS 256

typedef struct {
    int target_node;
    int64_t total_data_size;
    double total_duration;
    int protocol;
    int src_port;
    int dst_port;
    ProtocolTraffic protocol_traffic[MAX_PROTOCOLS];
} EdgeData;

typedef struct {
    int* row_ptr;
    EdgeData* edges;
    int node_count;
    int edge_count;
    int session_count;
    HashMap* ip_to_id;
    char** id_to_ip;
    int64_t* node_total_traffic;
    int64_t* node_outgoing_traffic;
    int64_t* node_incoming_traffic;
} CSRGraph;

CSRGraph* csr_graph_create(void);
int csr_graph_add_session(CSRGraph* graph, Session* session);
int csr_graph_get_node_id(CSRGraph* graph, const char* ip);
const char* csr_graph_get_ip(CSRGraph* graph, int node_id);
int64_t csr_graph_get_node_traffic(CSRGraph* graph, int node_id);
int64_t csr_graph_get_node_outgoing_traffic(CSRGraph* graph, int node_id);
int64_t csr_graph_get_node_incoming_traffic(CSRGraph* graph, int node_id);
void csr_graph_destroy(CSRGraph* graph);
int csr_graph_get_node_count(CSRGraph* graph);
int csr_graph_get_edge_count(CSRGraph* graph);
int csr_graph_get_session_count(CSRGraph* graph);

#endif
