#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
图可视化模块
提供子图HTML可视化功能
"""

import webbrowser
import os
import tempfile


def generate_visualization_html(nodes, edges, target_ip):
    """
    生成图可视化的HTML内容
    
    参数:
        nodes: 节点列表，每个节点包含 'ip' 和 'total_traffic' 字段
        edges: 边列表，每条边包含 'source'、'target' 和 'data_size' 字段
        target_ip: 目标IP地址，用于标题显示
        
    返回:
        str: 完整的HTML字符串
    """
    
    # 转换节点数据为JavaScript格式，根据流量调整节点大小
    nodes_js = []
    for node in nodes:
        size = max(5, min(50, node.get('total_traffic', 0) / 1000000))
        nodes_js.append(f'{{ id: "{node["ip"]}", label: "{node["ip"]}", size: {size:.1f}, color: "#3b82f6" }}')
    
    # 转换边数据为JavaScript格式，根据数据量调整边粗细
    edges_js = []
    for edge in edges:
        size = max(1, min(10, edge.get('data_size', 0) / 1000000))
        edges_js.append(f'{{ source: "{edge["source"]}", target: "{edge["target"]}", size: {size:.1f} }}')
    
    nodes_str = ',\n        '.join(nodes_js)
    edges_str = ',\n        '.join(edges_js)
    
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>子图可视化 - {target_ip}</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            background: #0f172a;
            color: #e2e8f0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            margin-bottom: 20px;
        }}
        .header h1 {{
            color: #60a5fa;
            margin: 0 0 10px 0;
        }}
        .stats {{
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: #1e293b;
            padding: 15px 25px;
            border-radius: 10px;
            border: 1px solid #334155;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: 700;
            color: #60a5fa;
        }}
        .stat-label {{
            font-size: 12px;
            color: #94a3b8;
        }}
        #graph-container {{
            width: 100%;
            height: 700px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 12px;
            position: relative;
        }}
        .legend {{
            margin-top: 20px;
            background: #1e293b;
            padding: 15px;
            border-radius: 10px;
            border: 1px solid #334155;
        }}
        .legend h3 {{
            margin-top: 0;
            color: #94a3b8;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 50%;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 子图可视化 - {target_ip}</h1>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{len(nodes)}</div>
                <div class="stat-label">节点数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(edges)}</div>
                <div class="stat-label">边数</div>
            </div>
        </div>
        
        <div id="graph-container"></div>
        
        <div class="legend">
            <h3>操作说明</h3>
            <div class="legend-item">
                <span>🖱️ 滚轮</span>
                <span>缩放视图</span>
            </div>
            <div class="legend-item">
                <span>✋ 拖拽</span>
                <span>平移视图</span>
            </div>
            <div class="legend-item">
                <span>💡 悬停</span>
                <span>查看完整IP地址</span>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
    <script>
        const nodes = [
            {nodes_str}
        ];

        const edges = [
            {edges_str}
        ];

        function renderGraph(nodes, edges, container) {{
            const width = container.clientWidth;
            const height = container.clientHeight;
            
            const nodePositions = {{}};
            const centerX = width / 2;
            const centerY = height / 2;
            
            const displayNodes = nodes;
            const nodeIdSet = new Set(displayNodes.map(n => n.id));
            const displayEdges = edges.filter(e => nodeIdSet.has(e.source) && nodeIdSet.has(e.target));
            
            displayNodes.forEach((node, i) => {{
                const angle = (2 * Math.PI * i) / displayNodes.length;
                const radius = Math.min(width, height) / 2 - 80;
                nodePositions[node.id] = {{
                    x: centerX + radius * Math.cos(angle),
                    y: centerY + radius * Math.sin(angle),
                    baseSize: Math.max(10, Math.min(25, node.size)),
                    originalNode: node
                }};
            }});

            container.innerHTML = `
                <svg id="graph-svg" width="${{width}}" height="${{height}}" style="background: #0f172a; cursor: grab;">
                    <g id="zoom-group">
                        <g id="edges-group"></g>
                        <g id="nodes-group"></g>
                    </g>
                </svg>
            `;
            
            const svg = document.getElementById('graph-svg');
            const zoomGroup = document.getElementById('zoom-group');
            const edgesGroup = document.getElementById('edges-group');
            const nodesGroup = document.getElementById('nodes-group');
            
            let scale = 1;
            let translateX = 0;
            let translateY = 0;
            let isDragging = false;
            let startX, startY;
            
            function updateGraphVisuals() {{
                edgesGroup.innerHTML = '';
                nodesGroup.innerHTML = '';
                
                const fontSize = Math.max(8, 11 / Math.sqrt(scale));
                const strokeWidth = Math.max(0.5, 1.5 / scale);
                const nodeStrokeWidth = Math.max(1, 2 / scale);
                
                displayEdges.forEach(edge => {{
                    const from = nodePositions[edge.source];
                    const to = nodePositions[edge.target];
                    if (from && to) {{
                        const dx = to.x - from.x;
                        const dy = to.y - from.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        const nodeRadius = from.baseSize;
                        const offset = nodeRadius + 5;
                        const endX = to.x - (dx / dist) * offset;
                        const endY = to.y - (dy / dist) * offset;
                        const startX = from.x + (dx / dist) * nodeRadius;
                        const startY = from.y + (dy / dist) * nodeRadius;
                        
                        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                        line.setAttribute('x1', startX);
                        line.setAttribute('y1', startY);
                        line.setAttribute('x2', endX);
                        line.setAttribute('y2', endY);
                        line.setAttribute('stroke', '#64748b');
                        line.setAttribute('stroke-width', strokeWidth);
                        edgesGroup.appendChild(line);
                        
                        const angle = Math.atan2(dy, dx);
                        const arrowSize = 6 / Math.sqrt(scale);
                        const arrow1X = endX - arrowSize * Math.cos(angle - Math.PI / 6);
                        const arrow1Y = endY - arrowSize * Math.sin(angle - Math.PI / 6);
                        const arrow2X = endX - arrowSize * Math.cos(angle + Math.PI / 6);
                        const arrow2Y = endY - arrowSize * Math.sin(angle + Math.PI / 6);
                        
                        const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
                        polygon.setAttribute('points', `${{endX}},${{endY}} ${{arrow1X}},${{arrow1Y}} ${{arrow2X}},${{arrow2Y}}`);
                        polygon.setAttribute('fill', '#64748b');
                        edgesGroup.appendChild(polygon);
                    }}
                }});

                displayNodes.forEach(node => {{
                    const pos = nodePositions[node.id];
                    if (pos) {{
                        const angle = Math.atan2(pos.y - centerY, pos.x - centerX);
                        const labelOffset = pos.baseSize + 15;
                        const labelX = pos.x + Math.cos(angle) * labelOffset;
                        const labelY = pos.y + Math.sin(angle) * labelOffset;
                        const nodeRadius = pos.baseSize / Math.sqrt(scale);
                        
                        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                        circle.setAttribute('cx', pos.x);
                        circle.setAttribute('cy', pos.y);
                        circle.setAttribute('r', nodeRadius);
                        circle.setAttribute('fill', '#3b82f6');
                        circle.setAttribute('stroke', '#1e40af');
                        circle.setAttribute('stroke-width', nodeStrokeWidth);
                        nodesGroup.appendChild(circle);
                        
                        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
                        text.setAttribute('x', labelX);
                        text.setAttribute('y', labelY);
                        text.setAttribute('text-anchor', 'middle');
                        text.setAttribute('dominant-baseline', 'middle');
                        text.setAttribute('font-family', 'Segoe UI, sans-serif');
                        text.setAttribute('font-size', fontSize);
                        text.setAttribute('fill', '#e2e8f0');
                        text.setAttribute('data-full-label', node.label);
                        text.textContent = node.label;
                        text.style.cursor = 'default';
                        nodesGroup.appendChild(text);
                    }}
                }});
            }}
            
            function updateTransform() {{
                zoomGroup.setAttribute('transform', `translate(${{translateX}}, ${{translateY}}) scale(${{scale}})`);
                updateGraphVisuals();
            }}
            
            updateGraphVisuals();
            
            svg.addEventListener('wheel', (e) => {{
                e.preventDefault();
                const delta = e.deltaY > 0 ? 0.9 : 1.1;
                const newScale = scale * delta;
                if (newScale >= 0.1 && newScale <= 10) {{
                    const rect = svg.getBoundingClientRect();
                    const mouseX = e.clientX - rect.left;
                    const mouseY = e.clientY - rect.top;
                    translateX = mouseX - (mouseX - translateX) * delta;
                    translateY = mouseY - (mouseY - translateY) * delta;
                    scale = newScale;
                    updateTransform();
                }}
            }});
            
            svg.addEventListener('mousedown', (e) => {{
                isDragging = true;
                startX = e.clientX - translateX;
                startY = e.clientY - translateY;
                svg.style.cursor = 'grabbing';
            }});
            
            svg.addEventListener('mousemove', (e) => {{
                if (isDragging) {{
                    translateX = e.clientX - startX;
                    translateY = e.clientY - startY;
                    zoomGroup.setAttribute('transform', `translate(${{translateX}}, ${{translateY}}) scale(${{scale}})`);
                }}
            }});
            
            svg.addEventListener('mouseup', () => {{
                isDragging = false;
                svg.style.cursor = 'grab';
            }});
            
            svg.addEventListener('mouseleave', () => {{
                isDragging = false;
                svg.style.cursor = 'grab';
            }});
        }}

        renderGraph(nodes, edges, document.getElementById('graph-container'));
    </script>
</body>
</html>
"""
    return html


def visualize_subgraph(nodes, edges, target_ip, append_output_func):
    """
    可视化子图，包括：
    - 生成HTML文件
    - 保存到临时目录
    - 用浏览器打开
    
    参数:
        nodes: 子图节点列表
        edges: 子图边列表
        target_ip: 目标IP
        append_output_func: 输出信息的回调函数
    """
    html_content = generate_visualization_html(nodes, edges, target_ip)
    
    temp_dir = tempfile.gettempdir()
    html_path = os.path.join(temp_dir, f"subgraph_visualization_{target_ip.replace('.', '_')}.html")
    
    try:
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        if append_output_func:
            append_output_func(f"可视化文件已生成: {html_path}")
            append_output_func("正在打开浏览器...")
        
        webbrowser.open(f'file:///{html_path}')
        
    except Exception as e:
        if append_output_func:
            append_output_func(f"生成可视化文件失败: {e}")
