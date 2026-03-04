# Network Analyzer C/C++ Implementation

## 项目结构

```
c_src/
├── common.h          # 通用类型和宏定义
├── hash_map.h/.c     # 字符串哈希表（IP到ID映射）
├── dynamic_array.h/.c # 动态数组实现
├── csr_graph.h/.c    # CSR格式的图数据结构
├── csv_reader.h/.c   # CSV文件读取
├── analysis.h/.c     # 分析算法（流量排序、星型结构、子图）
├── main.c            # 主程序（与Python通信）
├── build.bat         # Windows编译脚本
└── README.md         # 本文档
```

## 核心功能

### 1. CSR图结构 (csr_graph)
- 使用CSR（Compressed Sparse Row）格式高效存储稀疏图
- 支持IP到ID的双向映射
- 合并相同源IP和目的IP的会话
- 按协议统计流量和持续时间

### 2. 会话合并
- 自动合并相同 (源IP, 目的IP) 的会话
- 累加总数据大小和持续时间
- 分别统计不同协议的流量

### 3. 分析算法
- 流量排序：按总流量大小排序节点
- 星型结构查找：找出中心节点与叶节点的星型拓扑
- 子图查找：使用并查集快速确定连通分量

## 编译

### Windows (MinGW/MSVC)
```batch
cd c_src
build.bat
```

### Linux/Mac (GCC)
```bash
cd c_src
gcc -O2 -o ../network_analyzer \
    hash_map.c dynamic_array.c csr_graph.c csv_reader.c analysis.c main.c
```

## 使用方式

### 直接命令行调用
```bash
# 加载CSV文件
network_analyzer load network_data.csv

# 获取图信息
network_analyzer info

# 按流量排序
network_analyzer sort_traffic

# 查找星型结构（最小20条边）
network_analyzer find_stars 20

# 获取指定IP的子图
network_analyzer get_subgraph 192.168.1.1

# 列出所有子图
network_analyzer list_subgraphs
```

### 通过Python调用
见 `c_network_analyzer.py` 模块

## 数据结构说明

### CSR格式
```
row_ptr: [0, 2, 5, 5, 8]  # 每个节点的边起始位置
edges: [Edge0, Edge1, Edge2, Edge3, Edge4, Edge5, Edge6, Edge7]
```

### EdgeData
```c
typedef struct {
    int target_node;
    int64_t total_data_size;
    double total_duration;
    ProtocolTraffic protocol_traffic[MAX_PROTOCOLS];
} EdgeData;
```

