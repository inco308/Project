#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C网络分析器 - 简单图形界面
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import json
import threading
import webbrowser
import os
import tempfile
import graph_visualizer
import capture_utils


class CNetworkAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("网络流量分析器 - C版本")
        self.root.geometry("900x700")
        
        self.csv_file = "network_data.csv"
        
        self.create_widgets()
    
    def create_widgets(self):
        # 文件选择区域
        file_frame = ttk.LabelFrame(self.root, text="CSV文件", padding=10)
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.file_label = ttk.Label(file_frame, text=f"当前文件: {self.csv_file}")
        self.file_label.pack(side=tk.LEFT)
        
        btn_frame_file = ttk.Frame(file_frame)
        btn_frame_file.pack(side=tk.RIGHT)
        ttk.Button(btn_frame_file, text="选择文件", command=self.select_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame_file, text="PCAP转CSV", command=self.convert_pcap).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame_file, text="实时捕获", command=self.start_live_capture).pack(side=tk.LEFT, padx=2)
        
        # 操作按钮区域 - 第一行
        btn_frame1 = ttk.Frame(self.root, padding=10)
        btn_frame1.pack(fill=tk.X, padx=10)
        
        ttk.Button(btn_frame1, text="1. 获取图信息", command=self.get_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame1, text="2. 流量排序", command=self.sort_traffic).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame1, text="3. HTTPS筛选", command=self.filter_https).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame1, text="4. 可疑节点", command=self.find_suspicious).pack(side=tk.LEFT, padx=5)
        
        # 操作按钮区域 - 第二行
        btn_frame2 = ttk.Frame(self.root, padding=10)
        btn_frame2.pack(fill=tk.X, padx=10)

        ttk.Button(btn_frame2, text="5. 路径查找", command=self.find_path).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="6. 星型结构", command=self.find_stars).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="7. 获取子图", command=self.get_subgraph).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="8. 子图列表", command=self.list_subgraphs).pack(side=tk.LEFT, padx=5)

        # 操作按钮区域 - 第三行
        btn_frame3 = ttk.Frame(self.root, padding=10)
        btn_frame3.pack(fill=tk.X, padx=10)

        ttk.Button(btn_frame3, text="9. 安全规则检查", command=self.check_security_rules).pack(side=tk.LEFT, padx=5)
        
        # 参数输入区域
        param_frame = ttk.LabelFrame(self.root, text="参数", padding=10)
        param_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(param_frame, text="最小占比 (可疑节点):").pack(side=tk.LEFT)
        self.min_ratio_entry = ttk.Entry(param_frame, width=10)
        self.min_ratio_entry.insert(0, "0.8")
        self.min_ratio_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(param_frame, text="最小边数(星型结构):").pack(side=tk.LEFT)
        self.min_edges_entry = ttk.Entry(param_frame, width=10)
        self.min_edges_entry.insert(0, "5")
        self.min_edges_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(param_frame, text="源IP:").pack(side=tk.LEFT)
        self.source_ip_entry = ttk.Entry(param_frame, width=15)
        self.source_ip_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(param_frame, text="目的IP:").pack(side=tk.LEFT)
        self.target_ip_entry = ttk.Entry(param_frame, width=15)
        self.target_ip_entry.pack(side=tk.LEFT, padx=5)
        
        # 安全规则检查参数
        security_frame = ttk.LabelFrame(self.root, text="安全规则检查参数", padding=10)
        security_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(security_frame, text="目标地址:").pack(side=tk.LEFT)
        self.sec_addr1_entry = ttk.Entry(security_frame, width=15)
        self.sec_addr1_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(security_frame, text="地址范围起始:").pack(side=tk.LEFT)
        self.sec_addr2_entry = ttk.Entry(security_frame, width=15)
        self.sec_addr2_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(security_frame, text="地址范围结束:").pack(side=tk.LEFT)
        self.sec_addr3_entry = ttk.Entry(security_frame, width=15)
        self.sec_addr3_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(security_frame, text="规则类型:").pack(side=tk.LEFT)
        self.sec_rule_type = tk.StringVar(value="1")
        ttk.Radiobutton(security_frame, text="允许", variable=self.sec_rule_type, value="1").pack(side=tk.LEFT)
        ttk.Radiobutton(security_frame, text="禁止", variable=self.sec_rule_type, value="0").pack(side=tk.LEFT, padx=5)
        
        # 实时捕获参数
        capture_frame = ttk.LabelFrame(self.root, text="实时捕获参数", padding=10)
        capture_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(capture_frame, text="网络接口:").pack(side=tk.LEFT)
        self.capture_interface_combo = ttk.Combobox(capture_frame, width=40, state="readonly")
        self.capture_interface_combo.pack(side=tk.LEFT, padx=5)
        ttk.Button(capture_frame, text="刷新", command=self.refresh_interfaces).pack(side=tk.LEFT, padx=2)
        
        ttk.Label(capture_frame, text="持续秒数:").pack(side=tk.LEFT, padx=(10, 0))
        self.capture_duration_entry = ttk.Entry(capture_frame, width=8)
        self.capture_duration_entry.insert(0, "30")
        self.capture_duration_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(capture_frame, text="输出CSV:").pack(side=tk.LEFT)
        self.capture_output_entry = ttk.Entry(capture_frame, width=20)
        self.capture_output_entry.insert(0, "network_data.csv")
        self.capture_output_entry.pack(side=tk.LEFT, padx=5)
        
        # 输出区域
        output_frame = ttk.LabelFrame(self.root, text="输出", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # 输出区域顶部按钮
        output_btn_frame = ttk.Frame(output_frame)
        output_btn_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(output_btn_frame, text="清空输出", command=self.clear_output).pack(side=tk.RIGHT)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, 
            wrap=tk.WORD, 
            height=20,
            font=("Consolas", 10)
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 初始化接口列表
        self.refresh_interfaces()
    
    def select_file(self):
        filename = filedialog.askopenfilename(
            title="选择CSV文件",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")]
        )
        if filename:
            self.csv_file = filename
            self.file_label.config(text=f"当前文件: {self.csv_file}")
            self.append_output(f"已选择文件: {self.csv_file}")
    
    def append_output(self, text):
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()
    
    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
    
    def refresh_interfaces(self):
        """刷新网络接口列表"""
        interfaces = capture_utils.get_interfaces()
        if interfaces:
            self.capture_interface_combo['values'] = [name for (id, name) in interfaces]
            self.capture_interface_combo.current(0)
        else:
            self.capture_interface_combo['values'] = ["未找到可用接口，请检查tshark是否安装"]
            self.capture_interface_combo.current(0)
    
    def convert_pcap(self):
        """转换PCAP文件到CSV"""
        pcap_file = filedialog.askopenfilename(
            title="选择PCAP文件",
            filetypes=[("PCAP文件", "*.pcap *.pcapng"), ("所有文件", "*.*")]
        )
        if not pcap_file:
            return
        
        output_csv = filedialog.asksaveasfilename(
            title="保存CSV文件",
            defaultextension=".csv",
            filetypes=[("CSV文件", "*.csv"), ("所有文件", "*.*")],
            initialfile="network_data.csv"
        )
        if not output_csv:
            return
        
        self.append_output("=" * 50)
        self.append_output("转换PCAP文件到CSV...")
        self.root.update()
        
        try:
            session_count = capture_utils.extract_from_pcap(pcap_file, output_csv)
            self.append_output(f"共提取到 {session_count} 个会话")
            self.append_output(f"数据已保存到: {output_csv}")
            self.csv_file = output_csv
            self.file_label.config(text=f"当前文件: {self.csv_file}")
        except Exception as e:
            self.append_output(f"转换失败: {e}")
        
        self.append_output("=" * 50)
    
    def start_live_capture(self):
        """开始实时捕获"""
        selected_index = self.capture_interface_combo.current()
        if selected_index < 0:
            messagebox.showwarning("警告", "请选择网络接口")
            return
        
        interfaces = capture_utils.get_interfaces()
        if selected_index >= len(interfaces):
            messagebox.showwarning("警告", "无效的接口选择")
            return
        
        interface_id = interfaces[selected_index][0]
        duration_str = self.capture_duration_entry.get().strip()
        output_csv = self.capture_output_entry.get().strip()
        
        if not duration_str:
            messagebox.showwarning("警告", "请输入持续秒数")
            return
        if not output_csv:
            messagebox.showwarning("警告", "请输入输出CSV文件名")
            return
        
        try:
            duration = int(duration_str)
        except ValueError:
            messagebox.showwarning("警告", "持续秒数必须是整数")
            return
        
        self.append_output("=" * 50)
        self.append_output(f"开始实时捕获 (接口: {interface_id}, 时长: {duration}s)...")
        self.root.update()
        
        temp_pcap = 'temp_capture.pcap'
        
        try:
            session_count = capture_utils.capture_and_extract(interface_id, duration, output_csv, temp_pcap)
            self.append_output("捕获完成！")
            
            if session_count > 0:
                self.append_output(f"共提取到 {session_count} 个会话")
                self.append_output(f"数据已保存到: {output_csv}")
                self.csv_file = output_csv
                self.file_label.config(text=f"当前文件: {self.csv_file}")
            else:
                if os.path.exists(temp_pcap):
                    file_size = os.path.getsize(temp_pcap)
                    if file_size == 0:
                        self.append_output("⚠️ 捕获到的文件为空，请检查网络连接")
                    else:
                        self.append_output("⚠️ 未提取到会话数据")
                else:
                    self.append_output("❌ 未生成捕获文件")
                    
        except FileNotFoundError:
            self.append_output("❌ 未找到 tshark，请确保已安装 Wireshark 并添加到系统 PATH")
        except Exception as e:
            self.append_output(f"❌ 错误: {e}")
        
        self.append_output("=" * 50)
    
    def run_command(self, args):
        cmd = ["network_analyzer.exe", self.csv_file] + args
        self.status_var.set(f"正在执行: {' '.join(args)}...")
        self.root.update()
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                self.append_output(f"[错误] 命令执行失败: {result.stderr}")
                return None
            
            try:
                return json.loads(result.stdout.strip())
            except json.JSONDecodeError:
                return result.stdout.strip()
                
        except Exception as e:
            self.append_output(f"[错误] {e}")
            return None
        finally:
            self.status_var.set("就绪")
    
    def get_info(self):
        self.append_output("=" * 50)
        self.append_output("获取图信息...")
        info = self.run_command(["info"])
        if info:
            if isinstance(info, dict):
                self.append_output(f"节点数: {info.get('node_count', 0)}")
                self.append_output(f"边数: {info.get('edge_count', 0)}")
                self.append_output(f"会话数: {info.get('session_count', 0)}")
            else:
                self.append_output(str(info))
        self.append_output("=" * 50)
    
    def sort_traffic(self):
        self.append_output("=" * 50)
        self.append_output("按流量排序节点...")
        result = self.run_command(["sort_traffic"])
        if result:
            if isinstance(result, list):
                self.append_output(f"找到 {len(result)} 个节点")
                for i, (ip, traffic) in enumerate(result):
                    self.append_output(f"  {i+1:2d}. {ip:15s} - {traffic:,} bytes")
            else:
                self.append_output(str(result))
        self.append_output("=" * 50)
    
    def find_stars(self):
        min_edges = self.min_edges_entry.get() or "5"
        self.append_output("=" * 50)
        self.append_output(f"查找星型结构 (最小边数: {min_edges})...")
        result = self.run_command(["find_stars", min_edges])
        if result:
            if isinstance(result, list):
                self.append_output(f"找到 {len(result)} 个星型结构")
                for i, star in enumerate(result):
                    display_text = star.get('display_text')
                    if display_text:
                        self.append_output(f"  星型 {i+1}:\n{display_text}")
                    else:
                        self.append_output(f"  星型 {i+1}:\n中心: {star.get('center', 'N/A')}, 叶节点数: {len(star.get('leaves', []))}")
            else:
                self.append_output(str(result))
        self.append_output("=" * 50)
    
    def get_subgraph(self):
        target_ip = self.target_ip_entry.get()
        if not target_ip:
            messagebox.showwarning("警告", "请输入目标IP地址")
            return
        
        self.append_output("=" * 50)
        self.append_output(f"获取子图 (IP: {target_ip})...")
        result = self.run_command(["get_subgraph", target_ip])
        if not result or not isinstance(result, dict):
            self.append_output("获取子图数据失败")
            self.append_output("=" * 50)
            return
        
        nodes = result.get('nodes', [])
        edges = result.get('edges', [])
        
        self.append_output(f"子图节点数: {len(nodes)}")
        self.append_output(f"子图边数: {len(edges)}")
        
        # 调用可视化模块
        graph_visualizer.visualize_subgraph(nodes, edges, target_ip, self.append_output)
        
        self.append_output("=" * 50)
    
    def list_subgraphs(self):
        self.append_output("=" * 50)
        self.append_output("列出所有子图...")
        result = self.run_command(["list_subgraphs"])
        if result:
            if isinstance(result, list):
                self.append_output(f"找到 {len(result)} 个子图")
                for i, sg in enumerate(result):
                    size = sg.get('size', 0)
                    nodes = sg.get('nodes', [])
                    display_nodes = nodes[:3]
                    nodes_str = ", ".join(display_nodes)
                    if len(nodes) > 3:
                        nodes_str += " ..."
                    self.append_output(f"  子图 {i+1}: {size} 个节点, 节点: {nodes_str}")
            else:
                self.append_output(str(result))
        self.append_output("=" * 50)
    
    def filter_https(self):
        self.append_output("=" * 50)
        self.append_output("筛选HTTPS节点...")
        result = self.run_command(["filter_https"])
        if result:
            if isinstance(result, list):
                self.append_output(f"找到 {len(result)} 个HTTPS节点")
                for i, node in enumerate(result):
                    ip = node.get('ip', 'N/A')
                    total = node.get('total_traffic', 0)
                    self.append_output(f"  {i+1:2d}. {ip:15s} - 总流量: {total:,} bytes")
            else:
                self.append_output(str(result))
        self.append_output("=" * 50)
    
    def find_suspicious(self):
        min_ratio = self.min_ratio_entry.get() or "0.8"
        self.append_output("=" * 50)
        self.append_output(f"查找可疑节点 (最小占比: {min_ratio})...")
        result = self.run_command(["find_suspicious", min_ratio])
        if result:
            if isinstance(result, list):
                self.append_output(f"找到 {len(result)} 个可疑节点")
                for i, node in enumerate(result):
                    ip = node.get('ip', 'N/A')
                    total = node.get('total_traffic', 0)
                    ratio = node.get('outgoing_ratio', 0)
                    self.append_output(f"  {i+1:2d}. {ip:15s} - 总流量: {total:,} bytes, 占比: {ratio*100:.2f}%")
            else:
                self.append_output(str(result))
        self.append_output("=" * 50)
    
    def find_path(self):
        source_ip = self.source_ip_entry.get()
        dest_ip = self.target_ip_entry.get()
        if not source_ip or not dest_ip:
            messagebox.showwarning("警告", "请输入源IP和目标IP地址")
            return
        
        self.append_output("=" * 50)
        self.append_output(f"查找路径 (源IP: {source_ip}, 目的IP: {dest_ip})...")
        result = self.run_command(["find_path", source_ip, dest_ip])
        if result:
            if isinstance(result, dict):
                min_congestion = result.get('min_congestion_path')
                min_hop = result.get('min_hop_path')
                
                self.append_output("\n拥塞程度最小路径:")
                if min_congestion:
                    hop_count = min_congestion.get('hop_count', -1)
                    if hop_count >= 0 and min_congestion.get('path'):
                        path_str = " -> ".join(min_congestion['path'])
                        self.append_output(f"  路径: {path_str}")
                        self.append_output(f"  跳数: {hop_count}")
                        self.append_output(f"  总拥塞程度: {min_congestion.get('total_congestion', 0):.2f}")
                    else:
                        self.append_output("  无")
                else:
                    self.append_output("  无")
                
                self.append_output("\n跳数最小路径:")
                if min_hop:
                    hop_count = min_hop.get('hop_count', -1)
                    if hop_count >= 0 and min_hop.get('path'):
                        path_str = " -> ".join(min_hop['path'])
                        self.append_output(f"  路径: {path_str}")
                        self.append_output(f"  跳数: {hop_count}")
                        self.append_output(f"  总拥塞程度: {min_hop.get('total_congestion', 0):.2f}")
                    else:
                        self.append_output("  无")
                else:
                    self.append_output("  无")
            else:
                self.append_output(str(result))
        else:
            self.append_output("\n拥塞程度最小路径:\n  无")
            self.append_output("\n跳数最小路径:\n  无")
        self.append_output("=" * 50)
    
    def check_security_rules(self):
        addr1 = self.sec_addr1_entry.get()
        addr2 = self.sec_addr2_entry.get()
        addr3 = self.sec_addr3_entry.get()
        is_allowed = self.sec_rule_type.get()
        
        if not addr1 or not addr2 or not addr3:
            messagebox.showwarning("警告", "请填写所有安全规则检查参数")
            return
        
        self.append_output("=" * 50)
        rule_desc = "允许" if is_allowed == "1" else "禁止"
        self.append_output(f"安全规则检查 (地址1: {addr1}, 范围: {addr2}-{addr3}, 规则: {rule_desc})...")
        result = self.run_command(["check_security", addr1, addr2, addr3, is_allowed])
        if result:
            if isinstance(result, list):
                self.append_output(f"找到 {len(result)} 个违规会话")
                for i, session in enumerate(result):
                    self.append_output(f"  违规会话 {i+1}:")
                    self.append_output(f"    源: {session.get('source', 'N/A')}")
                    self.append_output(f"    目标: {session.get('destination', 'N/A')}")
                    self.append_output(f"    协议: {session.get('protocol', 0)}")
                    self.append_output(f"    源端口: {session.get('src_port', 0)}")
                    self.append_output(f"    目标端口: {session.get('dst_port', 0)}")
                    self.append_output(f"    数据大小: {session.get('data_size', 0):,} bytes")
                    self.append_output(f"    持续时间: {session.get('duration', 0):.2f} s")
            else:
                self.append_output(str(result))
        self.append_output("=" * 50)


def main():
    root = tk.Tk()
    app = CNetworkAnalyzerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
