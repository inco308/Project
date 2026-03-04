/**
 * @file analysis.c
 * @brief 网络流量分析算法实现
 * 
 * 包含流量排序、HTTPS筛选、可疑节点检测、
 * 星型结构查找、子图分析、路径查找等功能
 */

#include "analysis.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * @brief 并查集结构，用于子图划分
 */
typedef struct {
    int parent;
    int rank;
} UnionFind;

/**
 * @brief 创建并查集
 * 
 * @param size 集合大小（节点数）
 * @return 并查集指针，失败返回NULL
 */
static UnionFind* uf_create(int size) {
    if (size <= 0) return NULL;
    UnionFind* uf = (UnionFind*)malloc(size * sizeof(UnionFind));
    if (!uf) return NULL;
    // 初始化每个节点的父节点为自己
    for (int i = 0; i < size; i++) {
        uf[i].parent = i;
        uf[i].rank = 0;
    }
    return uf;
}

/**
 * @brief 查找节点的根
 * 
 * @param uf 并查集指针
 * @param x 节点编号
 * @return 根节点编号，失败返回-1
 */
static int uf_find(UnionFind* uf, int x) {
    if (!uf || x < 0) return -1;
    if (uf[x].parent != x) {
        uf[x].parent = uf_find(uf, uf[x].parent);
    }
    return uf[x].parent;
}

/**
 * @brief 合并两个集合（按秩合并）
 * 
 * @param uf 并查集指针
 * @param x 第一个节点
 * @param y 第二个节点
 */
static void uf_union(UnionFind* uf, int x, int y) {
    if (!uf || x < 0 || y < 0) return;
    int x_root = uf_find(uf, x);
    int y_root = uf_find(uf, y);
    if (x_root < 0 || y_root < 0 || x_root == y_root) return;
    
    // 按秩合并：小秩树合并到大秩树下
    if (uf[x_root].rank < uf[y_root].rank) {
        uf[x_root].parent = y_root;
    } else {
        uf[y_root].parent = x_root;
        if (uf[x_root].rank == uf[y_root].rank) {
            uf[x_root].rank++;
        }
    }
}

/**
 * @brief 销毁并查集
 * 
 * @param uf 并查集指针
 */
static void uf_destroy(UnionFind* uf) {
    free(uf);
}

/**
 * @brief 比较节点流量（用于qsort排序）
 * 
 * 按总流量从大到小排序，流量相同时按IP字典序排序
 * 
 * @param a 第一个节点
 * @param b 第二个节点
 * @return 比较结果：负数表示a应在b前，正数表示a应在b后
 */
int compare_node_traffic(const void* a, const void* b) {
    if (!a || !b) return 0;
    NodeTraffic* na = (NodeTraffic*)a;
    NodeTraffic* nb = (NodeTraffic*)b;
    if (na->total_traffic > nb->total_traffic) return -1;
    if (na->total_traffic < nb->total_traffic) return 1;
    return strcmp(na->ip, nb->ip);
}

/**
 * @brief 按流量排序节点
 * 
 * @param graph CSR图指针
 * @return 排序后的节点数组，失败返回NULL
 */
DynamicArray* sort_nodes_by_traffic(CSRGraph* graph) {
    if (!graph || graph->node_count == 0) return NULL;
    
    // 创建临时数组存储节点数据
    NodeTraffic* temp_array = (NodeTraffic*)malloc(graph->node_count * sizeof(NodeTraffic));
    if (!temp_array) return NULL;
    
    // 收集节点流量数据
    for (int i = 0; i < graph->node_count; i++) {
        if (graph->id_to_ip && graph->id_to_ip[i]) {
            strncpy(temp_array[i].ip, graph->id_to_ip[i], MAX_IP_LEN - 1);
            temp_array[i].ip[MAX_IP_LEN - 1] = '\0';
        } else {
            temp_array[i].ip[0] = '\0';
        }
        temp_array[i].total_traffic = graph->node_total_traffic ? graph->node_total_traffic[i] : 0;
    }
    
    // 使用qsort排序
    qsort(temp_array, graph->node_count, sizeof(NodeTraffic), compare_node_traffic);
    
    // 创建结果数组
    DynamicArray* result = dynamic_array_create(sizeof(NodeTraffic), graph->node_count);
    if (!result) {
        free(temp_array);
        return NULL;
    }
    
    // 将排序后的数据复制到结果数组
    for (int i = 0; i < graph->node_count; i++) {
        dynamic_array_append(result, &temp_array[i]);
    }
    
    free(temp_array);
    return result;
}

/**
 * @brief 查找星型结构
 * 
 * 星型结构定义：中心节点与多个叶子节点相连，
 * 且叶子节点只与中心节点相连
 * 
 * @param graph CSR图指针
 * @param min_edges 星型结构的最小边数
 * @return 星型结构数组，失败返回NULL
 */
DynamicArray* find_star_structures(CSRGraph* graph, int min_edges) {
    if (!graph || graph->node_count == 0 || !graph->row_ptr || !graph->edges) {
        return NULL;
    }
    
    DynamicArray* stars = dynamic_array_create(sizeof(StarStructure), 8);
    if (!stars) return NULL;
    
    // 遍历每个节点作为潜在的中心节点
    for (int center_id = 0; center_id < graph->node_count; center_id++) {
        DynamicArray* neighbors = dynamic_array_create(sizeof(int), 32);
        if (!neighbors) continue;
        
        // 收集所有直接邻居（出边和入边）
        int start = graph->row_ptr[center_id];
        int end = graph->row_ptr[center_id + 1];
        for (int i = start; i < end; i++) {
            int neighbor = graph->edges[i].target_node;
            int found = 0;
            for (int j = 0; j < neighbors->size; j++) {
                int* n = (int*)dynamic_array_get(neighbors, j);
                if (n && *n == neighbor) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                dynamic_array_append(neighbors, &neighbor);
            }
        }
        
        // 收集入边的邻居
        for (int u = 0; u < graph->node_count; u++) {
            if (u == center_id) continue;
            int u_start = graph->row_ptr[u];
            int u_end = graph->row_ptr[u + 1];
            for (int i = u_start; i < u_end; i++) {
                if (graph->edges[i].target_node == center_id) {
                    int found = 0;
                    for (int j = 0; j < neighbors->size; j++) {
                        int* n = (int*)dynamic_array_get(neighbors, j);
                        if (n && *n == u) {
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        dynamic_array_append(neighbors, &u);
                    }
                    break;
                }
            }
        }
        
        // 验证邻居是否只与中心节点相连
        DynamicArray* valid_leaves = dynamic_array_create(sizeof(int), 32);
        if (!valid_leaves) {
            dynamic_array_destroy(neighbors);
            continue;
        }
        
        for (int i = 0; i < neighbors->size; i++) {
            int* leaf_id_ptr = (int*)dynamic_array_get(neighbors, i);
            if (!leaf_id_ptr) continue;
            int leaf_id = *leaf_id_ptr;
            int only_center = 1;
            
            // 检查叶子节点的出边
            int leaf_start = graph->row_ptr[leaf_id];
            int leaf_end = graph->row_ptr[leaf_id + 1];
            for (int j = leaf_start; j < leaf_end; j++) {
                if (graph->edges[j].target_node != center_id) {
                    only_center = 0;
                    break;
                }
            }
            
            // 检查叶子节点的入边
            if (only_center) {
                for (int u = 0; u < graph->node_count; u++) {
                    if (u == leaf_id) continue;
                    int u_start = graph->row_ptr[u];
                    int u_end = graph->row_ptr[u + 1];
                    for (int j = u_start; j < u_end; j++) {
                        if (graph->edges[j].target_node == leaf_id && u != center_id) {
                            only_center = 0;
                            break;
                        }
                    }
                    if (!only_center) break;
                }
            }
            
            if (only_center) {
                dynamic_array_append(valid_leaves, &leaf_id);
            }
        }
        
        dynamic_array_destroy(neighbors);
        
        // 如果有效叶子数满足要求，添加到结果
        if (valid_leaves->size >= min_edges) {
            StarStructure star;
            if (graph->id_to_ip && graph->id_to_ip[center_id]) {
                strncpy(star.center_ip, graph->id_to_ip[center_id], MAX_IP_LEN - 1);
                star.center_ip[MAX_IP_LEN - 1] = '\0';
            } else {
                star.center_ip[0] = '\0';
            }
            star.leaf_ips = dynamic_array_create(MAX_IP_LEN, valid_leaves->size);
            if (star.leaf_ips) {
                for (int i = 0; i < valid_leaves->size; i++) {
                    int* leaf_id_ptr = (int*)dynamic_array_get(valid_leaves, i);
                    if (leaf_id_ptr) {
                        int leaf_id = *leaf_id_ptr;
                        if (graph->id_to_ip && graph->id_to_ip[leaf_id]) {
                            dynamic_array_append(star.leaf_ips, graph->id_to_ip[leaf_id]);
                        }
                    }
                }
                dynamic_array_append(stars, &star);
            }
        }
        
        dynamic_array_destroy(valid_leaves);
    }
    
    return stars;
}

/**
 * @brief 销毁星型结构
 * 
 * @param star 星型结构指针
 */
void star_structure_destroy(StarStructure* star) {
    if (star) {
        if (star->leaf_ips) {
            dynamic_array_destroy(star->leaf_ips);
        }
    }
}

/**
 * @brief 根据IP获取子图
 * 
 * @param graph CSR图指针
 * @param target_ip 目标IP地址
 * @return 子图指针，失败返回NULL
 */
Subgraph* get_subgraph_by_ip(CSRGraph* graph, const char* target_ip) {
    if (!graph || !target_ip) return NULL;
    
    // 查找目标IP对应的节点ID
    int target_id = csr_graph_get_node_id(graph, target_ip);
    if (target_id < 0) return NULL;
    
    return get_subgraph_by_root(graph, target_id);
}

/**
 * @brief 根据根节点ID获取子图
 * 
 * 使用并查集确定连通分量
 * 
 * @param graph CSR图指针
 * @param root_id 根节点ID
 * @return 子图指针，失败返回NULL
 */
Subgraph* get_subgraph_by_root(CSRGraph* graph, int root_id) {
    if (!graph || root_id < 0 || root_id >= graph->node_count) return NULL;
    if (!graph->row_ptr || !graph->edges) return NULL;
    
    // 创建并查集
    UnionFind* uf = uf_create(graph->node_count);
    if (!uf) return NULL;
    
    // 合并所有相连的节点
    for (int u = 0; u < graph->node_count; u++) {
        int start = graph->row_ptr[u];
        int end = graph->row_ptr[u + 1];
        for (int i = start; i < end; i++) {
            int v = graph->edges[i].target_node;
            uf_union(uf, u, v);
        }
    }
    
    // 找到目标节点的根
    int target_root = uf_find(uf, root_id);
    if (target_root < 0) {
        uf_destroy(uf);
        return NULL;
    }
    
    // 创建子图结构
    Subgraph* subgraph = (Subgraph*)malloc(sizeof(Subgraph));
    if (!subgraph) {
        uf_destroy(uf);
        return NULL;
    }
    
    subgraph->nodes = dynamic_array_create(sizeof(NodeTraffic), graph->node_count);
    subgraph->edges = dynamic_array_create(sizeof(SubgraphEdge), graph->edge_count);
    if (!subgraph->nodes || !subgraph->edges) {
        subgraph_destroy(subgraph);
        uf_destroy(uf);
        return NULL;
    }
    
    // 收集子图中的所有节点
    for (int i = 0; i < graph->node_count; i++) {
        if (uf_find(uf, i) == target_root) {
            NodeTraffic nt;
            if (graph->id_to_ip && graph->id_to_ip[i]) {
                strncpy(nt.ip, graph->id_to_ip[i], MAX_IP_LEN - 1);
                nt.ip[MAX_IP_LEN - 1] = '\0';
            } else {
                nt.ip[0] = '\0';
            }
            nt.total_traffic = graph->node_total_traffic ? graph->node_total_traffic[i] : 0;
            dynamic_array_append(subgraph->nodes, &nt);
        }
    }
    
    // 收集子图中的所有边
    for (int u = 0; u < graph->node_count; u++) {
        if (uf_find(uf, u) != target_root) continue;
        int start = graph->row_ptr[u];
        int end = graph->row_ptr[u + 1];
        for (int i = start; i < end; i++) {
            int v = graph->edges[i].target_node;
            if (uf_find(uf, v) == target_root) {
                SubgraphEdge se;
                se.source_node = u;
                se.target_node = v;
                se.total_data_size = graph->edges[i].total_data_size;
                dynamic_array_append(subgraph->edges, &se);
            }
        }
    }
    
    uf_destroy(uf);
    return subgraph;
}

/**
 * @brief 获取所有子图
 * 
 * @param graph CSR图指针
 * @return 子图信息数组，失败返回NULL
 */
DynamicArray* get_all_subgraphs(CSRGraph* graph) {
    if (!graph || graph->node_count == 0 || !graph->row_ptr || !graph->edges) {
        return NULL;
    }
    
    // 创建并查集
    UnionFind* uf = uf_create(graph->node_count);
    if (!uf) return NULL;
    
    // 合并所有相连的节点
    for (int u = 0; u < graph->node_count; u++) {
        int start = graph->row_ptr[u];
        int end = graph->row_ptr[u + 1];
        for (int i = start; i < end; i++) {
            int v = graph->edges[i].target_node;
            uf_union(uf, u, v);
        }
    }
    
    // 使用哈希表记录每个连通分量
    HashMap* root_map = hash_map_create(INITIAL_CAPACITY);
    DynamicArray* subgraphs = dynamic_array_create(sizeof(SubgraphInfo), 8);
    if (!root_map || !subgraphs) {
        hash_map_destroy(root_map);
        uf_destroy(uf);
        dynamic_array_destroy(subgraphs);
        return NULL;
    }
    
    // 划分连通分量
    for (int i = 0; i < graph->node_count; i++) {
        int root = uf_find(uf, i);
        char root_key[32];
        sprintf(root_key, "%d", root);
        
        int idx;
        if (hash_map_get(root_map, root_key, &idx) != SUCCESS) {
            // 新的连通分量
            idx = subgraphs->size;
            hash_map_put(root_map, root_key, idx);
            SubgraphInfo info;
            info.root_node_id = root;
            info.nodes = dynamic_array_create(sizeof(int), 16);
            if (info.nodes) {
                dynamic_array_append(subgraphs, &info);
            }
        }
        
        // 将当前节点添加到对应的连通分量
        if (idx < subgraphs->size) {
            SubgraphInfo* info = (SubgraphInfo*)dynamic_array_get(subgraphs, idx);
            if (info && info->nodes) {
                dynamic_array_append(info->nodes, &i);
            }
        }
    }
    
    hash_map_destroy(root_map);
    uf_destroy(uf);
    return subgraphs;
}

/**
 * @brief 销毁子图信息
 * 
 * @param info 子图信息指针
 */
void subgraph_info_destroy(SubgraphInfo* info) {
    if (info) {
        if (info->nodes) {
            dynamic_array_destroy(info->nodes);
        }
    }
}

/**
 * @brief 销毁子图
 * 
 * @param subgraph 子图指针
 */
void subgraph_destroy(Subgraph* subgraph) {
    if (subgraph) {
        if (subgraph->nodes) {
            dynamic_array_destroy(subgraph->nodes);
        }
        if (subgraph->edges) {
            dynamic_array_destroy(subgraph->edges);
        }
        free(subgraph);
    }
}

/**
 * @brief 比较可疑节点（用于qsort排序）
 * 
 * 按总流量从大到小排序
 * 
 * @param a 第一个可疑节点
 * @param b 第二个可疑节点
 * @return 比较结果
 */
int compare_suspicious_node(const void* a, const void* b) {
    if (!a || !b) return 0;
    SuspiciousNode* sa = (SuspiciousNode*)a;
    SuspiciousNode* sb = (SuspiciousNode*)b;
    if (sa->total_traffic > sb->total_traffic) return -1;
    if (sa->total_traffic < sb->total_traffic) return 1;
    return 0;
}

/**
 * @brief 筛选HTTPS节点
 * 
 * HTTPS节点定义为：参与protocol=6且dst_port=443会话的节点
 * 
 * @param graph CSR图指针
 * @param csv_file CSV文件路径（用于读取原始会话数据）
 * @return HTTPS节点数组，失败返回NULL
 */
DynamicArray* filter_https_nodes(CSRGraph* graph, const char* csv_file) {
    if (!graph || graph->node_count == 0 || !csv_file) return NULL;
    
    // 读取所有会话数据
    DynamicArray* sessions = read_all_sessions(csv_file);
    if (!sessions) return NULL;
    
    // 使用哈希表记录HTTPS节点
    HashMap* https_node_map = hash_map_create(INITIAL_CAPACITY);
    if (!https_node_map) {
        dynamic_array_destroy(sessions);
        return NULL;
    }
    
    // 遍历会话，筛选HTTPS会话
    for (int i = 0; i < sessions->size; i++) {
        Session* session = (Session*)dynamic_array_get(sessions, i);
        if (session && session->protocol == 6 && session->dst_port == 443) {
            // 添加源IP
            if (session->source_ip[0] != '\0') {
                int dummy;
                if (hash_map_get(https_node_map, session->source_ip, &dummy) != SUCCESS) {
                    hash_map_put(https_node_map, session->source_ip, 1);
                }
            }
            
            // 添加目标IP
            if (session->dest_ip[0] != '\0') {
                int dummy;
                if (hash_map_get(https_node_map, session->dest_ip, &dummy) != SUCCESS) {
                    hash_map_put(https_node_map, session->dest_ip, 1);
                }
            }
        }
    }
    
    dynamic_array_destroy(sessions);
    
    // 创建结果数组
    DynamicArray* result = dynamic_array_create(sizeof(NodeTraffic), 32);
    if (!result) {
        hash_map_destroy(https_node_map);
        return NULL;
    }
    
    // 收集HTTPS节点的流量信息
    for (int i = 0; i < graph->node_count; i++) {
        const char* ip = csr_graph_get_ip(graph, i);
        if (ip) {
            int dummy;
            if (hash_map_get(https_node_map, ip, &dummy) == SUCCESS) {
                NodeTraffic nt;
                strncpy(nt.ip, ip, MAX_IP_LEN - 1);
                nt.ip[MAX_IP_LEN - 1] = '\0';
                nt.total_traffic = graph->node_total_traffic ? graph->node_total_traffic[i] : 0;
                nt.outgoing_traffic = graph->node_outgoing_traffic ? graph->node_outgoing_traffic[i] : 0;
                nt.incoming_traffic = graph->node_incoming_traffic ? graph->node_incoming_traffic[i] : 0;
                dynamic_array_append(result, &nt);
            }
        }
    }
    
    hash_map_destroy(https_node_map);
    
    // 按流量排序
    int temp_size = result->size;
    if (temp_size > 0) {
        NodeTraffic* temp = (NodeTraffic*)malloc(temp_size * sizeof(NodeTraffic));
        if (temp) {
            for (int i = 0; i < temp_size; i++) {
                NodeTraffic* nt = (NodeTraffic*)dynamic_array_get(result, i);
                if (nt) temp[i] = *nt;
            }
            qsort(temp, temp_size, sizeof(NodeTraffic), compare_node_traffic);
            dynamic_array_destroy(result);
            result = dynamic_array_create(sizeof(NodeTraffic), temp_size);
            if (result) {
                for (int i = 0; i < temp_size; i++) {
                    dynamic_array_append(result, &temp[i]);
                }
            }
            free(temp);
        }
    }
    
    return result;
}

/**
 * @brief 查找可疑节点
 * 
 * 可疑节点定义为：出流量占总流量的比例超过指定阈值的节点
 * 
 * @param graph CSR图指针
 * @param min_ratio 最小出流量比例阈值
 * @return 可疑节点数组，失败返回NULL
 */
DynamicArray* find_suspicious_nodes(CSRGraph* graph, double min_ratio) {
    if (!graph || graph->node_count == 0) return NULL;
    
    DynamicArray* result = dynamic_array_create(sizeof(SuspiciousNode), 32);
    if (!result) return NULL;
    
    // 遍历所有节点，检查出流量比例
    for (int i = 0; i < graph->node_count; i++) {
        int64_t total = graph->node_total_traffic ? graph->node_total_traffic[i] : 0;
        int64_t outgoing = graph->node_outgoing_traffic ? graph->node_outgoing_traffic[i] : 0;
        
        if (total > 0) {
            double ratio = (double)outgoing / (double)total;
            if (ratio >= min_ratio) {
                SuspiciousNode sn;
                const char* ip = csr_graph_get_ip(graph, i);
                if (ip) {
                    strncpy(sn.ip, ip, MAX_IP_LEN - 1);
                    sn.ip[MAX_IP_LEN - 1] = '\0';
                    sn.total_traffic = total;
                    sn.outgoing_ratio = ratio;
                    dynamic_array_append(result, &sn);
                }
            }
        }
    }
    
    // 按流量排序
    int temp_size = result->size;
    if (temp_size > 0) {
        SuspiciousNode* temp = (SuspiciousNode*)malloc(temp_size * sizeof(SuspiciousNode));
        if (temp) {
            for (int i = 0; i < temp_size; i++) {
                SuspiciousNode* sn = (SuspiciousNode*)dynamic_array_get(result, i);
                if (sn) temp[i] = *sn;
            }
            qsort(temp, temp_size, sizeof(SuspiciousNode), compare_suspicious_node);
            dynamic_array_destroy(result);
            result = dynamic_array_create(sizeof(SuspiciousNode), temp_size);
            if (result) {
                for (int i = 0; i < temp_size; i++) {
                    dynamic_array_append(result, &temp[i]);
                }
            }
            free(temp);
        }
    }
    
    return result;
}

/**
 * @brief 查找最小拥塞路径（Dijkstra算法）
 * 
 * 拥塞定义为：数据大小 / 持续时间
 * 
 * @param graph CSR图指针
 * @param source_ip 源IP地址
 * @param dest_ip 目标IP地址
 * @return 路径结果，失败返回NULL
 */
PathResult* find_min_congestion_path(CSRGraph* graph, const char* source_ip, const char* dest_ip) {
    if (!graph || !source_ip || !dest_ip) return NULL;
    
    // 查找源节点和目标节点ID
    int source_id = csr_graph_get_node_id(graph, source_ip);
    int dest_id = csr_graph_get_node_id(graph, dest_ip);
    if (source_id < 0 || dest_id < 0) return NULL;
    
    // 如果源节点等于目标节点
    if (source_id == dest_id) {
        PathResult* result = (PathResult*)malloc(sizeof(PathResult));
        if (!result) return NULL;
        result->path_nodes = dynamic_array_create(MAX_IP_LEN, 16);
        if (result->path_nodes) {
            dynamic_array_append(result->path_nodes, (void*)source_ip);
        }
        result->total_congestion = 0;
        result->hop_count = 0;
        return result;
    }
    
    // 初始化Dijkstra算法所需数组
    double* distance = (double*)malloc(graph->node_count * sizeof(double));
    int* predecessor = (int*)malloc(graph->node_count * sizeof(int));
    bool* visited = (bool*)malloc(graph->node_count * sizeof(bool));
    
    if (!distance || !predecessor || !visited) {
        free(distance);
        free(predecessor);
        free(visited);
        return NULL;
    }
    
    // 初始化距离、前驱和访问状态
    for (int i = 0; i < graph->node_count; i++) {
        distance[i] = 1e18;
        predecessor[i] = -1;
        visited[i] = false;
    }
    
    distance[source_id] = 0;
    
    // Dijkstra主循环
    for (int count = 0; count < graph->node_count; count++) {
        // 找到未访问的最小距离节点
        int u = -1;
        double min_dist = 1e18;
        for (int i = 0; i < graph->node_count; i++) {
            if (!visited[i] && distance[i] < min_dist) {
                min_dist = distance[i];
                u = i;
            }
        }
        
        if (u < 0 || u == dest_id) break;
        visited[u] = true;
        
        // 松弛邻居节点
        int start = graph->row_ptr[u];
        int end = graph->row_ptr[u + 1];
        for (int i = start; i < end; i++) {
            int v = graph->edges[i].target_node;
            double congestion = graph->edges[i].total_duration > 0 
                ? (double)graph->edges[i].total_data_size / graph->edges[i].total_duration 
                : 1e10;
            
            if (!visited[v] && distance[u] + congestion < distance[v]) {
                distance[v] = distance[u] + congestion;
                predecessor[v] = u;
            }
        }
    }
    
    // 检查是否找到路径
    if (distance[dest_id] == 1e18) {
        free(distance);
        free(predecessor);
        free(visited);
        return NULL;
    }
    
    // 构建路径结果
    PathResult* result = (PathResult*)malloc(sizeof(PathResult));
    if (!result) {
        free(distance);
        free(predecessor);
        free(visited);
        return NULL;
    }
    
    result->path_nodes = dynamic_array_create(MAX_IP_LEN, 16);
    result->total_congestion = distance[dest_id];
    
    // 从目标节点回溯到源节点
    int current = dest_id;
    DynamicArray* temp_path = dynamic_array_create(sizeof(int), 16);
    
    while (current != -1 && temp_path) {
        dynamic_array_append(temp_path, &current);
        current = predecessor[current];
    }
    
    // 验证路径并反转
    if (temp_path && temp_path->size > 0) {
        int* first_node = (int*)dynamic_array_get(temp_path, temp_path->size - 1);
        if (!first_node || *first_node != source_id) {
            path_result_destroy(result);
            if (temp_path) dynamic_array_destroy(temp_path);
            free(distance);
            free(predecessor);
            free(visited);
            return NULL;
        }
        for (int i = temp_path->size - 1; i >= 0 && result->path_nodes; i--) {
            int* node_id = (int*)dynamic_array_get(temp_path, i);
            if (node_id) {
                const char* ip = csr_graph_get_ip(graph, *node_id);
                if (ip) {
                    dynamic_array_append(result->path_nodes, (void*)ip);
                }
            }
        }
        result->hop_count = temp_path->size - 1;
    } else {
        path_result_destroy(result);
        if (temp_path) dynamic_array_destroy(temp_path);
        free(distance);
        free(predecessor);
        free(visited);
        return NULL;
    }
    
    if (temp_path) dynamic_array_destroy(temp_path);
    free(distance);
    free(predecessor);
    free(visited);
    
    return result;
}

/**
 * @brief 查找最小跳数路径（BFS算法）
 * 
 * @param graph CSR图指针
 * @param source_ip 源IP地址
 * @param dest_ip 目标IP地址
 * @return 路径结果，失败返回NULL
 */
PathResult* find_min_hop_path(CSRGraph* graph, const char* source_ip, const char* dest_ip) {
    if (!graph || !source_ip || !dest_ip) return NULL;
    
    // 查找源节点和目标节点ID
    int source_id = csr_graph_get_node_id(graph, source_ip);
    int dest_id = csr_graph_get_node_id(graph, dest_ip);
    if (source_id < 0 || dest_id < 0) return NULL;
    
    // 如果源节点等于目标节点
    if (source_id == dest_id) {
        PathResult* result = (PathResult*)malloc(sizeof(PathResult));
        if (!result) return NULL;
        result->path_nodes = dynamic_array_create(MAX_IP_LEN, 16);
        if (result->path_nodes) {
            dynamic_array_append(result->path_nodes, (void*)source_ip);
        }
        result->total_congestion = 0;
        result->hop_count = 0;
        return result;
    }
    
    // 初始化BFS所需数组
    int* distance = (int*)malloc(graph->node_count * sizeof(int));
    int* predecessor = (int*)malloc(graph->node_count * sizeof(int));
    bool* visited = (bool*)malloc(graph->node_count * sizeof(bool));
    int* queue = (int*)malloc(graph->node_count * sizeof(int));
    
    if (!distance || !predecessor || !visited || !queue) {
        free(distance);
        free(predecessor);
        free(visited);
        free(queue);
        return NULL;
    }
    
    // 初始化距离、前驱和访问状态
    for (int i = 0; i < graph->node_count; i++) {
        distance[i] = -1;
        predecessor[i] = -1;
        visited[i] = false;
    }
    
    // BFS初始化
    int front = 0, rear = 0;
    queue[rear++] = source_id;
    distance[source_id] = 0;
    visited[source_id] = true;
    
    // BFS主循环
    while (front < rear) {
        int u = queue[front++];
        if (u == dest_id) break;
        
        int start = graph->row_ptr[u];
        int end = graph->row_ptr[u + 1];
        for (int i = start; i < end; i++) {
            int v = graph->edges[i].target_node;
            if (!visited[v]) {
                visited[v] = true;
                distance[v] = distance[u] + 1;
                predecessor[v] = u;
                queue[rear++] = v;
            }
        }
    }
    
    // 检查是否找到路径
    if (distance[dest_id] == -1) {
        free(distance);
        free(predecessor);
        free(visited);
        free(queue);
        return NULL;
    }
    
    // 构建路径结果
    PathResult* result = (PathResult*)malloc(sizeof(PathResult));
    if (!result) {
        free(distance);
        free(predecessor);
        free(visited);
        free(queue);
        return NULL;
    }
    
    result->path_nodes = dynamic_array_create(MAX_IP_LEN, 16);
    result->hop_count = distance[dest_id];
    
    // 计算总拥塞
    double total_congestion = 0;
    int current = dest_id;
    DynamicArray* temp_path = dynamic_array_create(sizeof(int), 16);
    
    while (current != -1 && temp_path) {
        dynamic_array_append(temp_path, &current);
        int prev = predecessor[current];
        if (prev != -1) {
            int start = graph->row_ptr[prev];
            int end = graph->row_ptr[prev + 1];
            for (int i = start; i < end; i++) {
                if (graph->edges[i].target_node == current) {
                    double congestion = graph->edges[i].total_duration > 0 
                        ? (double)graph->edges[i].total_data_size / graph->edges[i].total_duration 
                        : 1e10;
                    total_congestion += congestion;
                    break;
                }
            }
        }
        current = prev;
    }
    
    result->total_congestion = total_congestion;
    
    // 验证路径并反转
    if (temp_path && temp_path->size > 0) {
        int* first_node = (int*)dynamic_array_get(temp_path, temp_path->size - 1);
        if (!first_node || *first_node != source_id) {
            path_result_destroy(result);
            if (temp_path) dynamic_array_destroy(temp_path);
            free(distance);
            free(predecessor);
            free(visited);
            free(queue);
            return NULL;
        }
        for (int i = temp_path->size - 1; i >= 0 && result->path_nodes; i--) {
            int* node_id = (int*)dynamic_array_get(temp_path, i);
            if (node_id) {
                const char* ip = csr_graph_get_ip(graph, *node_id);
                if (ip) {
                    dynamic_array_append(result->path_nodes, (void*)ip);
                }
            }
        }
    } else {
        path_result_destroy(result);
        if (temp_path) dynamic_array_destroy(temp_path);
        free(distance);
        free(predecessor);
        free(visited);
        free(queue);
        return NULL;
    }
    
    if (temp_path) dynamic_array_destroy(temp_path);
    free(distance);
    free(predecessor);
    free(visited);
    free(queue);
    
    return result;
}

/**
 * @brief 销毁路径结果
 * 
 * @param result 路径结果指针
 */
void path_result_destroy(PathResult* result) {
    if (result) {
        if (result->path_nodes) {
            dynamic_array_destroy(result->path_nodes);
        }
        free(result);
    }
}

/**
 * @brief 将IP字符串转换为32位整数
 * 
 * @param ip_str IP字符串
 * @param out_ip 输出32位整数
 * @return 成功返回SUCCESS，失败返回ERR_INVALID_INPUT
 */
int ip_to_uint32(const char* ip_str, uint32_t* out_ip) {
    if (!ip_str || !out_ip) return ERR_INVALID_INPUT;
    
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return ERR_INVALID_INPUT;
    }
    
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return ERR_INVALID_INPUT;
    }
    
    *out_ip = (a << 24) | (b << 16) | (c << 8) | d;
    return SUCCESS;
}

/**
 * @brief 检查IP是否在指定范围内
 * 
 * @param ip_str 待检查的IP字符串
 * @param start_str 范围起始IP
 * @param end_str 范围结束IP
 * @return 1表示在范围内，0表示不在范围内或错误
 */
int ip_in_range(const char* ip_str, const char* start_str, const char* end_str) {
    uint32_t ip, start, end;
    
    if (ip_to_uint32(ip_str, &ip) != SUCCESS) return 0;
    if (ip_to_uint32(start_str, &start) != SUCCESS) return 0;
    if (ip_to_uint32(end_str, &end) != SUCCESS) return 0;
    
    // 确保start <= end
    if (start > end) {
        uint32_t temp = start;
        start = end;
        end = temp;
    }
    
    return (ip >= start && ip <= end) ? 1 : 0;
}

/**
 * @brief 检查安全规则
 * 
 * @param sessions 会话数组
 * @param addr1 关键地址（源或目标）
 * @param addr2 地址范围起始
 * @param addr3 地址范围结束
 * @param is_allowed 1表示允许该范围，0表示禁止该范围
 * @return 违反规则的会话数组，失败返回NULL
 */
DynamicArray* check_security_rules(DynamicArray* sessions, const char* addr1, const char* addr2, const char* addr3, int is_allowed) {
    if (!sessions || !addr1 || !addr2 || !addr3) return NULL;
    
    DynamicArray* violating_sessions = dynamic_array_create(sizeof(Session), INITIAL_CAPACITY);
    if (!violating_sessions) return NULL;
    
    // 遍历所有会话，检查是否违反规则
    for (int i = 0; i < sessions->size; i++) {
        Session* session = (Session*)dynamic_array_get(sessions, i);
        if (!session) continue;
        
        int is_violating = 0;
        
        // 检查源IP是addr1的情况
        if (strcmp(session->source_ip, addr1) == 0) {
            int in_range = ip_in_range(session->dest_ip, addr2, addr3);
            if ((is_allowed && !in_range) || (!is_allowed && in_range)) {
                is_violating = 1;
            }
        } 
        // 检查目标IP是addr1的情况
        else if (strcmp(session->dest_ip, addr1) == 0) {
            int in_range = ip_in_range(session->source_ip, addr2, addr3);
            if ((is_allowed && !in_range) || (!is_allowed && in_range)) {
                is_violating = 1;
            }
        }
        
        if (is_violating) {
            dynamic_array_append(violating_sessions, session);
        }
    }
    
    return violating_sessions;
}
