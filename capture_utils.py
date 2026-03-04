#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络流量捕获与转换模块
提供PCAP文件解析和实时流量捕获功能
"""

from scapy.all import rdpcap, IP, TCP, UDP
import csv
from collections import defaultdict
import subprocess
import os


def extract_from_pcap(pcap_file, output_csv):
    """
    从PCAP文件提取会话数据并保存到CSV
    
    参数:
        pcap_file: 输入的PCAP文件路径
        output_csv: 输出的CSV文件路径
        
    返回:
        int: 提取到的会话数量
    """
    # 读取PCAP文件中的所有数据包
    packets = rdpcap(pcap_file)
    
    # 使用字典存储会话，键为(源IP, 目标IP, 源端口, 目标端口, 协议)
    sessions = defaultdict(lambda: {
        'protocol': 0,
        'src_port': 0,
        'dst_port': 0,
        'data_size': 0,
        'start_time': None,
        'end_time': None
    })

    # 遍历每个数据包，聚合到会话中
    for pkt in packets:
        if IP in pkt:
            ip = pkt[IP]
            source = ip.src
            destination = ip.dst

            protocol = ip.proto
            src_port = 0
            dst_port = 0

            # 获取TCP或UDP的端口信息
            if TCP in pkt:
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
            elif UDP in pkt:
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport

            # 会话唯一标识
            key = (source, destination, src_port, dst_port, protocol)
            session = sessions[key]

            # 如果是会话的第一个包，初始化协议和端口
            if session['protocol'] == 0:
                session['protocol'] = protocol
                session['src_port'] = src_port
                session['dst_port'] = dst_port

            # 累加数据大小
            session['data_size'] += len(pkt)

            # 更新会话的开始和结束时间
            pkt_time = pkt.time
            if session['start_time'] is None or pkt_time < session['start_time']:
                session['start_time'] = pkt_time
            if session['end_time'] is None or pkt_time > session['end_time']:
                session['end_time'] = pkt_time

    # 将会话数据写入CSV文件
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'Source', 'Destination', 'Protocol',
            'SrcPort', 'DstPort', 'DataSize', 'Duration'
        ])
        writer.writeheader()

        for (source, destination, src_port, dst_port, protocol), session in sessions.items():
            duration = 0.0
            if session['start_time'] is not None and session['end_time'] is not None:
                duration = session['end_time'] - session['start_time']

            writer.writerow({
                'Source': source,
                'Destination': destination,
                'Protocol': protocol,
                'SrcPort': src_port,
                'DstPort': dst_port,
                'DataSize': session['data_size'],
                'Duration': max(0.001, duration)
            })

    return len(sessions)


def get_interfaces():
    """
    获取可用网络接口列表
    
    返回:
        list: 接口列表，每个元素为(接口编号, 完整接口名称)的元组
              例如: [('1', '1. \\Device\\NPF_{...} (本地连接)'), ...]
    """
    interfaces = []
    try:
        # 调用tshark获取接口列表
        result = subprocess.run(
            ['tshark', '-D'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if '.' in line:
                    parts = line.split('.', 1)
                    if len(parts) == 2:
                        interface_id = parts[0].strip()
                        full_name = line.strip()
                        interfaces.append((interface_id, full_name))
    except Exception:
        # 如果tshark调用失败，返回空列表
        pass
    return interfaces


def capture_and_extract(interface, duration, output_csv, temp_pcap='temp_capture.pcap'):
    """
    实时捕获网络流量并提取为CSV
    
    参数:
        interface: 网络接口编号
        duration: 捕获持续时间（秒）
        output_csv: 输出的CSV文件路径
        temp_pcap: 临时PCAP文件路径
        
    返回:
        int: 提取到的会话数量，失败返回0
    """
    # 构建tshark命令
    tshark_cmd = [
        'tshark',
        '-i', str(interface),
        '-a', f'duration:{duration}',
        '-w', temp_pcap
    ]

    # 执行捕获命令
    process = subprocess.Popen(tshark_cmd)
    process.wait()

    # 检查临时PCAP文件并提取会话
    if os.path.exists(temp_pcap):
        file_size = os.path.getsize(temp_pcap)
        if file_size > 0:
            session_count = extract_from_pcap(temp_pcap, output_csv)
            return session_count
    return 0

