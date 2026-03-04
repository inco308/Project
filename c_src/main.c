/**
 * @file main.c
 * @brief 主程序，与Python通信的入口
 * 
 * 通过命令行参数和标准输入/输出与Python交互
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "csr_graph.h"
#include "csv_reader.h"
#include "analysis.h"
#include "hash_map.h"
#include "dynamic_array.h"

static CSRGraph* global_graph = NULL;
static char global_csv_file[1024] = "";

/**
 * @brief 执行安全规则检查命令
 * 
 * 从CSV文件读取所有会话，根据指定的安全规则进行检查，
 * 输出违反规则的会话列表。
 * 
 * @param csv_file CSV文件路径
 * @param addr1 关键地址（源或目标）
 * @param addr2 地址范围起始
 * @param addr3 地址范围结束
 * @param is_allowed 1表示允许该范围，0表示禁止该范围
 */
void check_security_rules_cmd(const char* csv_file, const char* addr1, const char* addr2, const char* addr3, int is_allowed) {
    // 读取所有会话数据
    DynamicArray* sessions = read_all_sessions(csv_file);
    if (!sessions) {
        printf("{\"status\":\"error\",\"message\":\"Failed to read sessions\"}\n");
        fflush(stdout);
        return;
    }
    
    // 执行安全规则检查
    DynamicArray* violating_sessions = check_security_rules(sessions, addr1, addr2, addr3, is_allowed);
    if (!violating_sessions) {
        printf("[]\n");
        dynamic_array_destroy(sessions);
        fflush(stdout);
        return;
    }
    
    // 输出违反规则的会话
    printf("[");
    for (int i = 0; i < violating_sessions->size; i++) {
        Session* s = (Session*)dynamic_array_get(violating_sessions, i);
        if (s) {
            if (i > 0) printf(",");
            printf("{\"source\":\"%s\",\"destination\":\"%s\",\"protocol\":%d,\"src_port\":%d,\"dst_port\":%d,\"data_size\":%lld,\"duration\":%.2f}",
                   s->source_ip, s->dest_ip, s->protocol, s->src_port, s->dst_port,
                   (long long)s->data_size, s->duration);
        }
    }
    printf("]\n");
    
    // 清理资源
    dynamic_array_destroy(violating_sessions);
    dynamic_array_destroy(sessions);
    fflush(stdout);
}

/**
 * @brief 打印图的基本信息
 * 
 * 输出节点数、边数和会话数等信息
 */
void print_graph_info(void) {
    if (global_graph) {
        printf("{\"status\":\"ok\",\"node_count\":%d,\"edge_count\":%d,\"session_count\":%d}\n",
               csr_graph_get_node_count(global_graph),
               csr_graph_get_edge_count(global_graph),
               csr_graph_get_session_count(global_graph));
    } else {
        printf("{\"status\":\"error\",\"message\":\"No graph loaded\"}\n");
    }
    fflush(stdout);
}

/**
 * @brief 加载CSV文件并构建图
 * 
 * @param file_path CSV文件路径
 */
void load_csv(const char* file_path) {
    // 如果已有图，先销毁
    if (global_graph) {
        csr_graph_destroy(global_graph);
        global_graph = NULL;
    }
    // 从CSV文件构建新图
    global_graph = read_csv_to_graph(file_path);
    print_graph_info();
}

/**
 * @brief 按流量排序节点并输出
 * 
 * 从高到低排序节点，流量相同时按IP字典序排序
 */
void sort_traffic(void) {
    if (global_graph) {
        DynamicArray* sorted = sort_nodes_by_traffic(global_graph);
        if (sorted) {
            printf("[");
            for (int i = 0; i < sorted->size; i++) {
                NodeTraffic* nt = (NodeTraffic*)dynamic_array_get(sorted, i);
                if (nt) {
                    if (i > 0) printf(",");
                    printf("[\"%s\",%lld]", nt->ip, (long long)nt->total_traffic);
                }
            }
            printf("]\n");
            dynamic_array_destroy(sorted);
        } else {
            printf("[]\n");
        }
    } else {
        printf("[]\n");
    }
    fflush(stdout);
}

/**
 * @brief 查找星型结构并输出
 * 
 * 星型结构定义为：中心节点与多个叶子节点相连，
 * 且叶子节点只与中心节点相连
 * 
 * @param min_edges 星型结构的最小边数
 */
void find_stars(int min_edges) {
    if (global_graph) {
        DynamicArray* stars = find_star_structures(global_graph, min_edges);
        if (stars) {
            printf("[");
            for (int i = 0; i < stars->size; i++) {
                StarStructure* star = (StarStructure*)dynamic_array_get(stars, i);
                if (star) {
                    if (i > 0) printf(",");
                    printf("{\"center\":\"%s\",\"leaves\":[", star->center_ip);
                    if (star->leaf_ips) {
                        for (int j = 0; j < star->leaf_ips->size; j++) {
                            char* leaf = (char*)dynamic_array_get(star->leaf_ips, j);
                            if (leaf) {
                                if (j > 0) printf(",");
                                printf("\"%s\"", leaf);
                            }
                        }
                    }
                    printf("],\"display_text\":\"");
                    printf("%s: ", star->center_ip);
                    if (star->leaf_ips) {
                        for (int j = 0; j < star->leaf_ips->size; j++) {
                            char* leaf = (char*)dynamic_array_get(star->leaf_ips, j);
                            if (leaf) {
                                if (j > 0) printf(", ");
                                printf("%s", leaf);
                            }
                        }
                    }
                    printf("\"}");
                }
            }
            printf("]\n");
            // 清理星型结构资源
            for (int i = 0; i < stars->size; i++) {
                StarStructure* star = (StarStructure*)dynamic_array_get(stars, i);
                star_structure_destroy(star);
            }
            dynamic_array_destroy(stars);
        } else {
            printf("[]\n");
        }
    } else {
        printf("[]\n");
    }
    fflush(stdout);
}

/**
 * @brief 筛选HTTPS节点并输出
 * 
 * HTTPS节点定义为：参与protocol=6且dst_port=443会话的节点
 */
void filter_https(void) {
    if (global_graph && global_csv_file[0] != '\0') {
        DynamicArray* nodes = filter_https_nodes(global_graph, global_csv_file);
        if (nodes) {
            printf("[");
            for (int i = 0; i < nodes->size; i++) {
                NodeTraffic* nt = (NodeTraffic*)dynamic_array_get(nodes, i);
                if (nt) {
                    if (i > 0) printf(",");
                    printf("{\"ip\":\"%s\",\"total_traffic\":%lld,\"outgoing_traffic\":%lld,\"incoming_traffic\":%lld}",
                           nt->ip, (long long)nt->total_traffic,
                           (long long)nt->outgoing_traffic, (long long)nt->incoming_traffic);
                }
            }
            printf("]\n");
            dynamic_array_destroy(nodes);
        } else {
            printf("[]\n");
        }
    } else {
        printf("[]\n");
    }
    fflush(stdout);
}

/**
 * @brief 查找可疑节点并输出
 * 
 * 可疑节点定义为：出流量占总流量的比例超过指定阈值的节点
 * 
 * @param min_ratio 最小出流量比例阈值
 */
void find_suspicious(double min_ratio) {
    if (global_graph) {
        DynamicArray* nodes = find_suspicious_nodes(global_graph, min_ratio);
        if (nodes) {
            printf("[");
            for (int i = 0; i < nodes->size; i++) {
                SuspiciousNode* sn = (SuspiciousNode*)dynamic_array_get(nodes, i);
                if (sn) {
                    if (i > 0) printf(",");
                    printf("{\"ip\":\"%s\",\"total_traffic\":%lld,\"outgoing_ratio\":%.4f}",
                           sn->ip, (long long)sn->total_traffic, sn->outgoing_ratio);
                }
            }
            printf("]\n");
            dynamic_array_destroy(nodes);
        } else {
            printf("[]\n");
        }
    } else {
        printf("[]\n");
    }
    fflush(stdout);
}

/**
 * @brief 打印路径查找结果
 * 
 * @param result 路径查找结果
 */
void print_path_result(PathResult* result) {
    if (!result) {
        printf("{\"path\":[],\"hop_count\":-1,\"total_congestion\":0.00}");
        return;
    }
    printf("{\"path\":[");
    if (result->path_nodes) {
        for (int i = 0; i < result->path_nodes->size; i++) {
            char* ip = (char*)dynamic_array_get(result->path_nodes, i);
            if (ip) {
                if (i > 0) printf(",");
                printf("\"%s\"", ip);
            }
        }
    }
    printf("],\"hop_count\":%d,\"total_congestion\":%.2f}",
           result->hop_count, result->total_congestion);
}

/**
 * @brief 查找从源IP到目标IP的路径
 * 
 * 同时查找最小拥塞路径和最小跳数路径
 * 
 * @param source_ip 源IP地址
 * @param dest_ip 目标IP地址
 */
void find_path(const char* source_ip, const char* dest_ip) {
    if (global_graph && source_ip && dest_ip) {
        // 查找最小拥塞路径
        PathResult* congestion_path = find_min_congestion_path(global_graph, source_ip, dest_ip);
        // 查找最小跳数路径
        PathResult* hop_path = find_min_hop_path(global_graph, source_ip, dest_ip);
        
        printf("{\"min_congestion_path\":");
        print_path_result(congestion_path);
        printf(",\"min_hop_path\":");
        print_path_result(hop_path);
        printf("}\n");
        
        // 清理路径结果资源
        if (congestion_path) path_result_destroy(congestion_path);
        if (hop_path) path_result_destroy(hop_path);
    } else {
        printf("{\"status\":\"error\",\"message\":\"Invalid parameters\"}\n");
    }
    fflush(stdout);
}

/**
 * @brief 获取指定IP所在的子图
 * 
 * 使用并查集确定子图，输出子图的所有节点和边
 * 
 * @param target_ip 目标IP地址
 */
void get_subgraph(const char* target_ip) {
    if (global_graph) {
        Subgraph* subgraph = get_subgraph_by_ip(global_graph, target_ip);
        if (subgraph) {
            // 输出子图节点
            printf("{\"nodes\":[");
            if (subgraph->nodes) {
                for (int i = 0; i < subgraph->nodes->size; i++) {
                    NodeTraffic* nt = (NodeTraffic*)dynamic_array_get(subgraph->nodes, i);
                    if (nt) {
                        if (i > 0) printf(",");
                        printf("{\"ip\":\"%s\",\"total_traffic\":%lld}", nt->ip, (long long)nt->total_traffic);
                    }
                }
            }
            // 输出子图边
            printf("],\"edges\":[");
            if (subgraph->edges) {
                for (int i = 0; i < subgraph->edges->size; i++) {
                    SubgraphEdge* se = (SubgraphEdge*)dynamic_array_get(subgraph->edges, i);
                    if (se) {
                        if (i > 0) printf(",");
                        const char* src_ip = csr_graph_get_ip(global_graph, se->source_node);
                        const char* dst_ip = csr_graph_get_ip(global_graph, se->target_node);
                        printf("{\"source\":\"%s\",\"target\":\"%s\",\"data_size\":%lld}",
                               src_ip ? src_ip : "", dst_ip ? dst_ip : "", (long long)se->total_data_size);
                    }
                }
            }
            printf("],\"target_ip\":\"%s\"}\n", target_ip);
            subgraph_destroy(subgraph);
        } else {
            printf("{\"status\":\"error\",\"message\":\"IP not found\"}\n");
        }
    } else {
        printf("{\"status\":\"error\",\"message\":\"No graph loaded\"}\n");
    }
    fflush(stdout);
}

/**
 * @brief 列出图中的所有子图
 * 
 * 使用并查集将图划分为连通分量，输出每个子图的信息
 */
void list_subgraphs(void) {
    if (global_graph) {
        DynamicArray* subgraphs = get_all_subgraphs(global_graph);
        if (subgraphs) {
            printf("[");
            for (int i = 0; i < subgraphs->size; i++) {
                SubgraphInfo* info = (SubgraphInfo*)dynamic_array_get(subgraphs, i);
                if (info && info->nodes) {
                    if (i > 0) printf(",");
                    const char* root_ip = csr_graph_get_ip(global_graph, info->root_node_id);
                    printf("{\"root\":\"%s\",\"size\":%d,\"nodes\":[", root_ip ? root_ip : "", info->nodes->size);
                    for (int j = 0; j < info->nodes->size; j++) {
                        int* node_id = (int*)dynamic_array_get(info->nodes, j);
                        if (node_id) {
                            if (j > 0) printf(",");
                            const char* ip = csr_graph_get_ip(global_graph, *node_id);
                            printf("\"%s\"", ip ? ip : "");
                        }
                    }
                    printf("]}");
                }
            }
            printf("]\n");
            // 清理子图信息资源
            for (int i = 0; i < subgraphs->size; i++) {
                SubgraphInfo* info = (SubgraphInfo*)dynamic_array_get(subgraphs, i);
                if (info) {
                    subgraph_info_destroy(info);
                }
            }
            dynamic_array_destroy(subgraphs);
        } else {
            printf("[]\n");
        }
    } else {
        printf("[]\n");
    }
    fflush(stdout);
}

/**
 * @brief 主函数
 * 
 * 解析命令行参数，加载CSV文件，执行相应命令
 * 
 * @param argc 参数个数
 * @param argv 参数数组
 * @return 0表示成功，非0表示失败
 */
int main(int argc, char* argv[]) {
    // 检查参数数量
    if (argc < 3) {
        printf("{\"status\":\"error\",\"message\":\"Usage: network_analyzer <csv_file> <command> [args]\\n\"");
        printf("Commands:\\n");
        printf("  info - Print graph info\\n");
        printf("  sort_traffic - Sort nodes by traffic\\n");
        printf("  find_stars <min_edges> - Find star structures\\n");
        printf("  get_subgraph <ip> - Get subgraph by IP\\n");
        printf("  list_subgraphs - List all subgraphs\\n");
        printf("  filter_https - Filter HTTPS nodes (protocol 6, port 443)\\n");
        printf("  find_suspicious <min_ratio> - Find suspicious nodes\\n");
        printf("  find_path <source_ip> <dest_ip> - Find paths\\n");
        printf("  check_security <addr1> <addr2> <addr3> <is_allowed> - Check security rules\\n");
        return 1;
    }
    
    // 解析CSV文件路径和命令
    char* csv_file = argv[1];
    char* command = argv[2];
    
    // 保存全局CSV文件路径
    strncpy(global_csv_file, csv_file, sizeof(global_csv_file) - 1);
    global_csv_file[sizeof(global_csv_file) - 1] = '\0';
    
    // 安全规则检查命令特殊处理（不需要加载图）
    if (strcmp(command, "check_security") == 0 && argc >= 7) {
        check_security_rules_cmd(csv_file, argv[3], argv[4], argv[5], atoi(argv[6]));
        return 0;
    }
    
    // 加载CSV文件构建图
    global_graph = read_csv_to_graph(csv_file);
    if (!global_graph) {
        printf("{\"status\":\"error\",\"message\":\"Failed to load CSV file\"}\n");
        return 1;
    }
    
    // 根据命令执行相应功能
    if (strcmp(command, "info") == 0) {
        print_graph_info();
    } else if (strcmp(command, "sort_traffic") == 0) {
        sort_traffic();
    } else if (strcmp(command, "find_stars") == 0 && argc >= 4) {
        find_stars(atoi(argv[3]));
    } else if (strcmp(command, "get_subgraph") == 0 && argc >= 4) {
        get_subgraph(argv[3]);
    } else if (strcmp(command, "list_subgraphs") == 0) {
        list_subgraphs();
    } else if (strcmp(command, "filter_https") == 0) {
        filter_https();
    } else if (strcmp(command, "find_suspicious") == 0 && argc >= 4) {
        find_suspicious(atof(argv[3]));
    } else if (strcmp(command, "find_path") == 0 && argc >= 5) {
        find_path(argv[3], argv[4]);
    } else {
        printf("{\"status\":\"error\",\"message\":\"Unknown command\\n\"}");
    }
    
    // 清理全局图资源
    if (global_graph) {
        csr_graph_destroy(global_graph);
    }
    
    return 0;
}
