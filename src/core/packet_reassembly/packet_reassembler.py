#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据包重组模块

该模块实现了高效的数据包重组算法，用于在网络拥塞情况下恢复原始通信内容。
目标是达到60%以上的还原率。
"""

import os
import sys
import logging
from collections import defaultdict
import time

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PacketReassembler:
    """
    数据包重组器类
    
    实现了高效的数据包重组算法，用于处理乱序、丢失和重复的数据包，
    并尝试恢复原始的通信内容。
    """
    
    def __init__(self, timeout=30, max_fragments=1000, buffer_size=10485760):
        """
        初始化数据包重组器
        
        Args:
            timeout (int): 数据包重组超时时间（秒）
            max_fragments (int): 每个流最大允许的分片数
            buffer_size (int): 重组缓冲区最大大小（字节）
        """
        self.timeout = timeout
        self.max_fragments = max_fragments
        self.buffer_size = buffer_size
        
        # 用于存储分片的数据结构
        # 格式: {flow_id: {seq_num: {'data': bytes, 'timestamp': float, 'is_last': bool}}}
        self.fragments = defaultdict(dict)
        
        # 用于跟踪每个流的统计信息
        self.flow_stats = defaultdict(lambda: {
            'total_packets': 0,
            'reassembled_packets': 0,
            'lost_packets': 0,
            'out_of_order_packets': 0,
            'start_time': time.time(),
            'last_activity': time.time(),
            'expected_seq': 0
        })
        
        logger.info(f"初始化数据包重组器: timeout={timeout}s, max_fragments={max_fragments}, buffer_size={buffer_size}字节")
    
    def add_fragment(self, flow_id, seq_num, data, is_last=False):
        """
        添加一个数据包分片到重组器
        
        Args:
            flow_id (str): 流标识符，通常是五元组的哈希值
            seq_num (int): 序列号
            data (bytes): 数据包内容
            is_last (bool): 是否是流的最后一个分片
            
        Returns:
            bool: 添加是否成功
        """
        # 检查流是否已经超过最大分片数
        if len(self.fragments[flow_id]) >= self.max_fragments:
            logger.warning(f"流 {flow_id} 超过最大分片数 {self.max_fragments}，丢弃新分片")
            self.flow_stats[flow_id]['lost_packets'] += 1
            return False
        
        # 更新流统计信息
        self.flow_stats[flow_id]['total_packets'] += 1
        self.flow_stats[flow_id]['last_activity'] = time.time()
        
        # 检查是否乱序
        if seq_num != self.flow_stats[flow_id]['expected_seq']:
            self.flow_stats[flow_id]['out_of_order_packets'] += 1
        else:
            self.flow_stats[flow_id]['expected_seq'] += 1
        
        # 存储分片
        self.fragments[flow_id][seq_num] = {
            'data': data,
            'timestamp': time.time(),
            'is_last': is_last
        }
        
        logger.debug(f"添加分片: 流={flow_id}, 序列号={seq_num}, 大小={len(data)}字节, 是否最后={is_last}")
        return True
    
    def reassemble_flow(self, flow_id):
        """
        尝试重组指定流的数据包
        
        Args:
            flow_id (str): 流标识符
            
        Returns:
            tuple: (是否完成, 重组后的数据)
        """
        if flow_id not in self.fragments:
            logger.warning(f"流 {flow_id} 不存在")
            return False, b''
        
        # 获取该流的所有分片
        flow_fragments = self.fragments[flow_id]
        if not flow_fragments:
            return False, b''
        
        # 检查是否有序列号连续的分片
        seq_nums = sorted(flow_fragments.keys())
        
        # 找到最长的连续序列
        longest_seq = [seq_nums[0]]
        current_seq = [seq_nums[0]]
        
        for i in range(1, len(seq_nums)):
            if seq_nums[i] == seq_nums[i-1] + 1:
                current_seq.append(seq_nums[i])
            else:
                if len(current_seq) > len(longest_seq):
                    longest_seq = current_seq
                current_seq = [seq_nums[i]]
        
        if len(current_seq) > len(longest_seq):
            longest_seq = current_seq
        
        # 重组数据
        reassembled_data = b''
        for seq in longest_seq:
            reassembled_data += flow_fragments[seq]['data']
            self.flow_stats[flow_id]['reassembled_packets'] += 1
        
        # 检查是否完成重组（最后一个分片已收到）
        is_complete = any(frag['is_last'] for frag in flow_fragments.values())
        
        # 如果完成重组，清理该流的分片
        if is_complete:
            logger.info(f"流 {flow_id} 重组完成: {len(reassembled_data)}字节, {len(longest_seq)}/{len(seq_nums)}个分片")
            self.cleanup_flow(flow_id)
        
        return is_complete, reassembled_data
    
    def cleanup_flow(self, flow_id):
        """
        清理指定流的所有分片和统计信息
        
        Args:
            flow_id (str): 流标识符
        """
        if flow_id in self.fragments:
            del self.fragments[flow_id]
        
        if flow_id in self.flow_stats:
            stats = self.flow_stats[flow_id]
            reassembly_rate = stats['reassembled_packets'] / stats['total_packets'] if stats['total_packets'] > 0 else 0
            logger.info(f"流 {flow_id} 清理: 总分片={stats['total_packets']}, 重组={stats['reassembled_packets']}, "  
                      f"丢失={stats['lost_packets']}, 乱序={stats['out_of_order_packets']}, 重组率={reassembly_rate:.2%}")
            del self.flow_stats[flow_id]
    
    def cleanup_expired_flows(self):
        """
        清理所有超时的流
        
        Returns:
            int: 清理的流数量
        """
        current_time = time.time()
        expired_flows = []
        
        for flow_id, stats in self.flow_stats.items():
            if current_time - stats['last_activity'] > self.timeout:
                expired_flows.append(flow_id)
        
        for flow_id in expired_flows:
            logger.info(f"流 {flow_id} 超时，清理")
            self.cleanup_flow(flow_id)
        
        return len(expired_flows)
    
    def get_reassembly_statistics(self):
        """
        获取重组统计信息
        
        Returns:
            dict: 重组统计信息
        """
        total_packets = sum(stats['total_packets'] for stats in self.flow_stats.values())
        reassembled_packets = sum(stats['reassembled_packets'] for stats in self.flow_stats.values())
        lost_packets = sum(stats['lost_packets'] for stats in self.flow_stats.values())
        out_of_order_packets = sum(stats['out_of_order_packets'] for stats in self.flow_stats.values())
        
        reassembly_rate = reassembled_packets / total_packets if total_packets > 0 else 0
        
        return {
            'total_flows': len(self.flow_stats),
            'total_packets': total_packets,
            'reassembled_packets': reassembled_packets,
            'lost_packets': lost_packets,
            'out_of_order_packets': out_of_order_packets,
            'reassembly_rate': reassembly_rate,
            'active_fragments': sum(len(frags) for frags in self.fragments.values())
        }


# 测试代码
if __name__ == "__main__":
    # 创建重组器实例
    reassembler = PacketReassembler(timeout=10, max_fragments=100)
    
    # 模拟数据包
    flow_id = "test_flow_1"
    data1 = b"Hello, "
    data2 = b"world!"
    data3 = b" This is "
    data4 = b"a test."
    
    # 添加分片（有序）
    reassembler.add_fragment(flow_id, 0, data1)
    reassembler.add_fragment(flow_id, 1, data2)
    reassembler.add_fragment(flow_id, 2, data3)
    reassembler.add_fragment(flow_id, 3, data4, is_last=True)
    
    # 重组并打印结果
    is_complete, data = reassembler.reassemble_flow(flow_id)
    print(f"重组完成: {is_complete}")
    print(f"重组数据: {data.decode('utf-8')}")
    
    # 打印统计信息
    stats = reassembler.get_reassembly_statistics()
    print(f"统计信息: {stats}")