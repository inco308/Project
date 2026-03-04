import csv
import networkx as nx
from collections import defaultdict, deque
import heapq
import ipaddress


class ProtocolTraffic:
    def __init__(self):
        self.data_size = 0
        self.duration = 0


class EdgeData:
    def __init__(self):
        self.total_data_size = 0
        self.total_duration = 0
        self.protocols = defaultdict(ProtocolTraffic)


class NetworkGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.ip_to_id = {}
        self.id_to_ip = []
        self.next_id = 0

    def get_ip_id(self, ip):
        if ip not in self.ip_to_id:
            self.ip_to_id[ip] = self.next_id
            self.id_to_ip.append(ip)
            self.next_id += 1
            self.graph.add_node(self.ip_to_id[ip], ip=ip)
        return self.ip_to_id[ip]

    def add_session(self, source, destination, protocol, src_port, dst_port, data_size, duration):
        src_id = self.get_ip_id(source)
        dst_id = self.get_ip_id(destination)

        if not self.graph.has_edge(src_id, dst_id):
            edge_data = EdgeData()
            self.graph.add_edge(src_id, dst_id, data=edge_data)

        edge_data = self.graph[src_id][dst_id]['data']
        edge_data.total_data_size += data_size
        edge_data.total_duration += duration
        edge_data.protocols[protocol].data_size += data_size
        edge_data.protocols[protocol].duration += duration

    def get_congestion(self, u, v):
        edge_data = self.graph[u][v]['data']
        if edge_data.total_duration == 0:
            return float('inf')
        return edge_data.total_data_size / edge_data.total_duration

    def get_node_total_traffic(self, node_id):
        total = 0
        for _, _, data in self.graph.out_edges(node_id, data=True):
            total += data['data'].total_data_size
        for _, _, data in self.graph.in_edges(node_id, data=True):
            total += data['data'].total_data_size
        return total

    def get_node_sent_traffic(self, node_id):
        total = 0
        for _, _, data in self.graph.out_edges(node_id, data=True):
            total += data['data'].total_data_size
        return total

    def get_node_received_traffic(self, node_id):
        total = 0
        for _, _, data in self.graph.in_edges(node_id, data=True):
            total += data['data'].total_data_size
        return total


def read_csv(file_path):
    sessions = []
    encodings = ['utf-8-sig', 'utf-8', 'gbk']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        session = {
                            'source': row['Source'],
                            'destination': row['Destination'],
                            'protocol': int(row['Protocol']),
                            'src_port': int(row['SrcPort']),
                            'dst_port': int(row['DstPort']),
                            'data_size': int(row['DataSize']),
                            'duration': float(row['Duration'])
                        }
                        sessions.append(session)
                    except:
                        continue
            break
        except:
            continue
    return sessions


def build_graph(sessions):
    graph = NetworkGraph()
    for session in sessions:
        graph.add_session(
            session['source'],
            session['destination'],
            session['protocol'],
            session['src_port'],
            session['dst_port'],
            session['data_size'],
            session['duration']
        )
    return graph


def sort_nodes_by_traffic(graph):
    nodes = []
    for node_id in graph.graph.nodes():
        ip = graph.id_to_ip[node_id]
        total = graph.get_node_total_traffic(node_id)
        nodes.append((ip, total))
    return sorted(nodes, key=lambda x: (-x[1], x[0]))


def filter_https_nodes(sessions, graph):
    https_ips = set()
    for session in sessions:
        if session['protocol'] == 6 and session['dst_port'] == 443:
            https_ips.add(session['source'])
            https_ips.add(session['destination'])

    result = []
    for ip in https_ips:
        if ip in graph.ip_to_id:
            node_id = graph.ip_to_id[ip]
            total = graph.get_node_total_traffic(node_id)
            result.append((ip, total))
    return sorted(result, key=lambda x: x[1], reverse=True)


def filter_unidirectional_nodes(graph, threshold=0.8):
    result = []
    for node_id in graph.graph.nodes():
        ip = graph.id_to_ip[node_id]
        total = graph.get_node_total_traffic(node_id)
        if total == 0:
            continue
        sent = graph.get_node_sent_traffic(node_id)
        ratio = sent / total
        if ratio > threshold:
            result.append((ip, total, ratio))
    return sorted(result, key=lambda x: x[1], reverse=True)


def find_min_congestion_path(graph, start_ip, end_ip):
    if start_ip not in graph.ip_to_id or end_ip not in graph.ip_to_id:
        return None

    start_id = graph.ip_to_id[start_ip]
    end_id = graph.ip_to_id[end_ip]

    distances = {node: float('inf') for node in graph.graph.nodes()}
    distances[start_id] = 0
    predecessors = {node: None for node in graph.graph.nodes()}
    heap = [(0, start_id)]

    while heap:
        current_dist, u = heapq.heappop(heap)

        if u == end_id:
            break

        if current_dist > distances[u]:
            continue

        for v in graph.graph.successors(u):
            congestion = graph.get_congestion(u, v)
            distance = current_dist + congestion

            if distance < distances[v]:
                distances[v] = distance
                predecessors[v] = u
                heapq.heappush(heap, (distance, v))

    if distances[end_id] == float('inf'):
        return None

    path = []
    current = end_id
    while current is not None:
        path.append(graph.id_to_ip[current])
        current = predecessors[current]
    path.reverse()

    return path, distances[end_id]


def find_min_hop_path(graph, start_ip, end_ip):
    if start_ip not in graph.ip_to_id or end_ip not in graph.ip_to_id:
        return None

    start_id = graph.ip_to_id[start_ip]
    end_id = graph.ip_to_id[end_ip]

    predecessors = {node: None for node in graph.graph.nodes()}
    visited = set()
    queue = deque([start_id])
    visited.add(start_id)

    while queue:
        u = queue.popleft()

        if u == end_id:
            break

        for v in graph.graph.successors(u):
            if v not in visited:
                visited.add(v)
                predecessors[v] = u
                queue.append(v)

    if predecessors[end_id] is None and start_id != end_id:
        return None

    path = []
    current = end_id
    while current is not None:
        path.append(graph.id_to_ip[current])
        current = predecessors[current]
    path.reverse()

    total_congestion = 0
    for i in range(len(path) - 1):
        u = graph.ip_to_id[path[i]]
        v = graph.ip_to_id[path[i + 1]]
        total_congestion += graph.get_congestion(u, v)

    return path, total_congestion


def find_star_structures(graph, min_edges=20):
    stars = []

    for center_id in graph.graph.nodes():
        in_neighbors = list(graph.graph.predecessors(center_id))
        out_neighbors = list(graph.graph.successors(center_id))
        connected = set(in_neighbors + out_neighbors)

        valid_leaf_nodes = []
        for leaf_id in connected:
            leaf_in = list(graph.graph.predecessors(leaf_id))
            leaf_out = list(graph.graph.successors(leaf_id))

            only_connected_to_center = True

            for n in leaf_in:
                if n != center_id:
                    only_connected_to_center = False
                    break

            if only_connected_to_center:
                for n in leaf_out:
                    if n != center_id:
                        only_connected_to_center = False
                        break

            if only_connected_to_center:
                valid_leaf_nodes.append(leaf_id)

        if len(valid_leaf_nodes) >= min_edges:
            center_ip = graph.id_to_ip[center_id]
            leaf_ips = [graph.id_to_ip[leaf] for leaf in valid_leaf_nodes]
            stars.append((center_ip, leaf_ips))

    return stars


def get_star_subgraph(graph, center_ip):
    if center_ip not in graph.ip_to_id:
        return None

    center_id = graph.ip_to_id[center_ip]
    in_neighbors = list(graph.graph.predecessors(center_id))
    out_neighbors = list(graph.graph.successors(center_id))
    connected = set(in_neighbors + out_neighbors)

    valid_leaf_nodes = []
    for leaf_id in connected:
        leaf_in = list(graph.graph.predecessors(leaf_id))
        leaf_out = list(graph.graph.successors(leaf_id))

        only_connected_to_center = True

        for n in leaf_in:
            if n != center_id:
                only_connected_to_center = False
                break

        if only_connected_to_center:
            for n in leaf_out:
                if n != center_id:
                    only_connected_to_center = False
                    break

        if only_connected_to_center:
            valid_leaf_nodes.append(leaf_id)

    subgraph_nodes = [center_ip]
    for leaf_id in valid_leaf_nodes:
        subgraph_nodes.append(graph.id_to_ip[leaf_id])

    subgraph_edges = []
    for u, v, data in graph.graph.edges(data=True):
        if u == center_id or v == center_id:
            if (u == center_id and v in valid_leaf_nodes) or (v == center_id and u in valid_leaf_nodes):
                subgraph_edges.append({
                    'source': graph.id_to_ip[u],
                    'target': graph.id_to_ip[v],
                    'data_size': data['data'].total_data_size
                })

    nodes_with_traffic = []
    for node_id in [center_id] + valid_leaf_nodes:
        ip = graph.id_to_ip[node_id]
        total_traffic = graph.get_node_total_traffic(node_id)
        nodes_with_traffic.append({
            'ip': ip,
            'total_traffic': total_traffic
        })

    return {
        'nodes': nodes_with_traffic,
        'edges': subgraph_edges,
        'center_ip': center_ip
    }


def ip_in_range(ip_str, start_str, end_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        start = ipaddress.ip_address(start_str)
        end = ipaddress.ip_address(end_str)
        return start <= ip <= end
    except:
        return False


class UnionFind:
    def __init__(self, size):
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, x):
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        x_root = self.find(x)
        y_root = self.find(y)

        if x_root == y_root:
            return

        if self.rank[x_root] < self.rank[y_root]:
            self.parent[x_root] = y_root
        else:
            self.parent[y_root] = x_root
            if self.rank[x_root] == self.rank[y_root]:
                self.rank[x_root] += 1


def get_subgraph(graph, target_ip):
    if target_ip not in graph.ip_to_id:
        return None

    target_id = graph.ip_to_id[target_ip]
    uf = UnionFind(len(graph.graph.nodes()))

    for u, v in graph.graph.edges():
        uf.union(u, v)

    target_root = uf.find(target_id)

    subgraph_nodes = []
    subgraph_edges = []

    for node_id in graph.graph.nodes():
        if uf.find(node_id) == target_root:
            ip = graph.id_to_ip[node_id]
            total_traffic = graph.get_node_total_traffic(node_id)
            subgraph_nodes.append({
                'ip': ip,
                'total_traffic': total_traffic
            })

    for u, v, data in graph.graph.edges(data=True):
        if uf.find(u) == target_root and uf.find(v) == target_root:
            subgraph_edges.append({
                'source': graph.id_to_ip[u],
                'target': graph.id_to_ip[v],
                'data_size': data['data'].total_data_size
            })

    return {
        'nodes': subgraph_nodes,
        'edges': subgraph_edges,
        'target_ip': target_ip
    }


def get_subgraph_by_root(graph, root_id):
    uf = UnionFind(len(graph.graph.nodes()))

    for u, v in graph.graph.edges():
        uf.union(u, v)

    subgraph_nodes = []
    subgraph_edges = []

    for node_id in graph.graph.nodes():
        if uf.find(node_id) == root_id:
            ip = graph.id_to_ip[node_id]
            total_traffic = graph.get_node_total_traffic(node_id)
            subgraph_nodes.append({
                'ip': ip,
                'total_traffic': total_traffic
            })

    for u, v, data in graph.graph.edges(data=True):
        if uf.find(u) == root_id and uf.find(v) == root_id:
            subgraph_edges.append({
                'source': graph.id_to_ip[u],
                'target': graph.id_to_ip[v],
                'data_size': data['data'].total_data_size
            })

    return {
        'nodes': subgraph_nodes,
        'edges': subgraph_edges,
        'root_id': root_id
    }


def get_all_subgraphs(graph):
    if len(graph.graph.nodes()) == 0:
        return []

    uf = UnionFind(len(graph.graph.nodes()))

    for u, v in graph.graph.edges():
        uf.union(u, v)

    subgraphs = defaultdict(list)
    for node_id in graph.graph.nodes():
        root = uf.find(node_id)
        subgraphs[root].append(graph.id_to_ip[node_id])

    result = []
    for root, nodes in subgraphs.items():
        result.append({
            'root': root,
            'nodes': nodes,
            'size': len(nodes)
        })

    return sorted(result, key=lambda x: x['size'], reverse=True)


def check_security_rules(sessions, addr1, addr2, addr3, is_allowed=True):
    violating_sessions = []

    for session in sessions:
        source = session['source']
        dest = session['destination']

        if source == addr1:
            in_range = ip_in_range(dest, addr2, addr3)
            if (is_allowed and not in_range) or (not is_allowed and in_range):
                violating_sessions.append(session)
        elif dest == addr1:
            in_range = ip_in_range(source, addr2, addr3)
            if (is_allowed and not in_range) or (not is_allowed and in_range):
                violating_sessions.append(session)

    return violating_sessions