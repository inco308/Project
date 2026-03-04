/**
 * @file analysis.h
 * @brief 网络流量分析算法模块
 * 
 * 提供流量排序、星型结构查找、子图查找等功能
 */

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "dynamic_array.h"
#include "common.h"
#include "csr_graph.h"

typedef struct {
    DynamicArray* path_nodes;
    double total_congestion;
    int hop_count;
} PathResult;

int compare_node_traffic(const void* a, const void* b);
DynamicArray* sort_nodes_by_traffic(CSRGraph* graph);

int compare_suspicious_node(const void* a, const void* b);
DynamicArray* filter_https_nodes(CSRGraph* graph, const char* csv_file);
DynamicArray* find_suspicious_nodes(CSRGraph* graph, double min_ratio);

typedef struct {
    char center_ip[MAX_IP_LEN];
    DynamicArray* leaf_ips;
} StarStructure;

DynamicArray* find_star_structures(CSRGraph* graph, int min_edges);
void star_structure_destroy(StarStructure* star);

typedef struct {
    int source_node;
    int target_node;
    int64_t total_data_size;
} SubgraphEdge;

typedef struct {
    DynamicArray* nodes;
    DynamicArray* edges;
} Subgraph;

typedef struct {
    int root_node_id;
    DynamicArray* nodes;
} SubgraphInfo;

Subgraph* get_subgraph_by_ip(CSRGraph* graph, const char* target_ip);
Subgraph* get_subgraph_by_root(CSRGraph* graph, int root_id);
DynamicArray* get_all_subgraphs(CSRGraph* graph);
void subgraph_destroy(Subgraph* subgraph);
void subgraph_info_destroy(SubgraphInfo* info);

PathResult* find_min_congestion_path(CSRGraph* graph, const char* source_ip, const char* dest_ip);
PathResult* find_min_hop_path(CSRGraph* graph, const char* source_ip, const char* dest_ip);
void path_result_destroy(PathResult* result);

DynamicArray* check_security_rules(DynamicArray* sessions, const char* addr1, const char* addr2, const char* addr3, int is_allowed);

#endif
