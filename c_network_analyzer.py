"""
Network Analyzer C Wrapper
通过subprocess调用C程序进行网络流量分析
"""

import subprocess
import json
import os


class CNetworkAnalyzer:
    def __init__(self, exe_path='network_analyzer.exe', csv_path=None):
        self.exe_path = exe_path
        self.csv_path = csv_path

    def _run_command(self, args):
        """
        运行C程序命令
        
        Args:
            args: 命令参数列表（不包括csv文件）
            
        Returns:
            解析后的JSON输出
        """
        if not self.csv_path:
            return {'error': 'No CSV file specified'}
        
        cmd = [self.exe_path, self.csv_path] + args
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"Error: {result.stderr}")
                return None
            
            try:
                return json.loads(result.stdout.strip())
            except json.JSONDecodeError:
                return result.stdout.strip()
                
        except Exception as e:
            print(f"Error running command: {e}")
            return None

    def load_csv(self, file_path):
        """
        设置CSV文件路径
        
        Args:
            file_path: CSV文件路径
        """
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        self.csv_path = file_path
        return self.get_info()

    def get_info(self):
        """获取图信息"""
        return self._run_command(['info'])

    def sort_traffic(self):
        """按流量排序节点"""
        return self._run_command(['sort_traffic'])

    def find_stars(self, min_edges=20):
        """
        查找星型结构
        
        Args:
            min_edges: 最小边数
            
        Returns:
            星型结构列表
        """
        return self._run_command(['find_stars', str(min_edges)])

    def get_subgraph(self, target_ip):
        """
        获取指定IP的子图
        
        Args:
            target_ip: 目标IP
            
        Returns:
            子图数据
        """
        return self._run_command(['get_subgraph', target_ip])

    def list_subgraphs(self):
        """列出所有子图"""
        return self._run_command(['list_subgraphs'])
    
    def filter_https(self):
        """筛选HTTPS节点"""
        return self._run_command(['filter_https'])
    
    def find_suspicious(self, min_ratio=0.8):
        """查找可疑节点"""
        return self._run_command(['find_suspicious', str(min_ratio)])
    
    def find_path(self, source_ip, dest_ip):
        """查找路径"""
        return self._run_command(['find_path', source_ip, dest_ip])


# 全局实例
_c_analyzer = None


def get_c_analyzer(csv_path=None):
    """获取C分析器单例"""
    global _c_analyzer
    if _c_analyzer is None:
        _c_analyzer = CNetworkAnalyzer(csv_path=csv_path)
    elif csv_path:
        _c_analyzer.csv_path = csv_path
    return _c_analyzer
