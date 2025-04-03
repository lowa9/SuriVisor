"""网络数据包工具模块

提供网络数据包处理的基础工具函数，包括：
- 数据包解析
- 数据包重组
- 流量统计
- 异常检测辅助函数
"""

from typing import Dict, List, Tuple, Optional
import logging
from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP  # 添加这行
from scapy.utils import rdpcap, wrpcap
from collections import defaultdict
import numpy as np

class PacketAnalyzer:
    """数据包分析类
    
    提供数据包分析的基础功能
    """
    
    def __init__(self):
        self.packets: List[Packet] = []
        self.flow_stats: Dict[str, Dict] = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'end_time': None
        })
    
    def load_pcap(self, file_path: str) -> None:
        """加载PCAP文件
        
        Args:
            file_path: PCAP文件路径
        """
        try:
            self.packets = rdpcap(file_path)
            logging.info(f"成功加载PCAP文件: {file_path}")
        except Exception as e:
            logging.error(f"加载PCAP文件失败: {e}")
            raise
    
    def get_flow_key(self, packet: Packet) -> Optional[str]:
        """获取流标识
        
        Args:
            packet: 数据包
        
        Returns:
            流标识字符串，格式为'src_ip:src_port-dst_ip:dst_port'
        """
        if IP in packet and (TCP in packet or UDP in packet):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            else:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        return None
    
    def analyze_flows(self) -> Dict[str, Dict]:
        """分析流量统计
        
        Returns:
            流量统计信息
        """
        for packet in self.packets:
            flow_key = self.get_flow_key(packet)
            if flow_key:
                stats = self.flow_stats[flow_key]
                stats['packet_count'] += 1
                if IP in packet:
                    stats['byte_count'] += len(packet[IP])
                if not stats['start_time']:
                    stats['start_time'] = float(packet.time)
                stats['end_time'] = float(packet.time)
        
        return dict(self.flow_stats)
    
    def calculate_packet_loss_ratio(self, flow_key: str) -> float:
        """计算丢包率
        
        Args:
            flow_key: 流标识
        
        Returns:
            丢包率（0-1之间的浮点数）
        """
        if flow_key not in self.flow_stats:
            return 0.0
        
        # 通过TCP序列号分析丢包
        seq_numbers = []
        for packet in self.packets:
            if self.get_flow_key(packet) == flow_key and TCP in packet:
                seq_numbers.append(packet[TCP].seq)
        
        if not seq_numbers:
            return 0.0
        
        # 计算预期的包数和实际的包数
        expected_packets = max(seq_numbers) - min(seq_numbers) + 1
        actual_packets = len(set(seq_numbers))
        
        return 1 - (actual_packets / expected_packets) if expected_packets > 0 else 0.0
    
    def calculate_reorder_ratio(self, flow_key: str) -> float:
        """计算乱序率
        
        Args:
            flow_key: 流标识
        
        Returns:
            乱序率（0-1之间的浮点数）
        """
        if flow_key not in self.flow_stats:
            return 0.0
        
        # 收集TCP序列号
        seq_numbers = []
        for packet in self.packets:
            if self.get_flow_key(packet) == flow_key and TCP in packet:
                seq_numbers.append(packet[TCP].seq)
        
        if len(seq_numbers) < 2:
            return 0.0
        
        # 计算乱序包的数量
        reorder_count = 0
        sorted_seq = sorted(seq_numbers)
        for i in range(len(seq_numbers)):
            if seq_numbers[i] != sorted_seq[i]:
                reorder_count += 1
        
        return reorder_count / len(seq_numbers)
    
    def get_flow_duration(self, flow_key: str) -> float:
        """获取流持续时间
        
        Args:
            flow_key: 流标识
        
        Returns:
            流持续时间（秒）
        """
        stats = self.flow_stats.get(flow_key)
        if stats and stats['start_time'] is not None and stats['end_time'] is not None:
            return stats['end_time'] - stats['start_time']
        return 0.0
    
    def get_flow_rate(self, flow_key: str) -> float:
        """计算流速率
        
        Args:
            flow_key: 流标识
        
        Returns:
            字节/秒
        """
        duration = self.get_flow_duration(flow_key)
        if duration > 0:
            return self.flow_stats[flow_key]['byte_count'] / duration
        return 0.0

class PacketReassembler:
    """数据包重组类
    
    提供TCP流重组功能
    """
    
    def __init__(self):
        self.flows: Dict[str, List[Tuple[int, bytes]]] = defaultdict(list)
    
    def add_packet(self, packet: Packet) -> None:
        """添加数据包到重组队列
        
        Args:
            packet: 数据包
        """
        if IP in packet and TCP in packet:
            flow_key = f"{packet[IP].src}:{packet[TCP].sport}-{packet[IP].dst}:{packet[TCP].dport}"
            payload = bytes(packet[TCP].payload)
            if payload:
                self.flows[flow_key].append((packet[TCP].seq, payload))
    
    def reassemble_flow(self, flow_key: str) -> bytes:
        """重组TCP流
        
        Args:
            flow_key: 流标识
        
        Returns:
            重组后的数据
        """
        if flow_key not in self.flows:
            return b''
        
        # 按序列号排序
        sorted_segments = sorted(self.flows[flow_key], key=lambda x: x[0])
        reassembled = b''
        
        # 合并数据段
        for _, payload in sorted_segments:
            reassembled += payload
        
        return reassembled

# 导出类
__all__ = ['PacketAnalyzer', 'PacketReassembler']