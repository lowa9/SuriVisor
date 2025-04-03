#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
增强型数据包重组模块

该模块实现了高级的数据包重组算法，用于在复杂网络环境下高效恢复原始通信内容。
目标是达到80%以上的还原率，并支持多种协议的数据包重组。
"""

import os
import sys
import logging
from collections import defaultdict, deque
import time
import heapq
import threading
import ipaddress

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EnhancedPacketReassembler:
    """
    增强型数据包重组器类
    
    实现了高级的数据包重组算法，支持TCP、UDP和IP分片的重组，
    能够处理复杂网络环境下的乱序、丢失、重复和重传数据包。
    """
    
    def __init__(self, timeout=60, max_fragments=2000, buffer_size=20971520, 
                 cleanup_interval=300, enable_adaptive_timeout=True):
        """
        初始化增强型数据包重组器
        
        Args:
            timeout (int): 数据包重组超时时间（秒）
            max_fragments (int): 每个流最大允许的分片数
            buffer_size (int): 重组缓冲区最大大小（字节）
            cleanup_interval (int): 清理间隔（秒）
            enable_adaptive_timeout (bool): 是否启用自适应超时
        """
        self.timeout = timeout
        self.max_fragments = max_fragments
        self.buffer_size = buffer_size
        self.cleanup_interval = cleanup_interval
        self.enable_adaptive_timeout = enable_adaptive_timeout
        
        # 用于存储TCP流的数据结构
        # 格式: {flow_id: {
        #   'fragments': {seq_num: {'data': bytes, 'timestamp': float, 'flags': dict}},
        #   'next_seq': int,
        #   'last_activity': float,
        #   'adaptive_timeout': float,
        #   'reassembled_data': bytes,
        #   'is_complete': bool
        # }}
        self.tcp_streams = defaultdict(lambda: {
            'fragments': {},
            'next_seq': 0,
            'last_activity': time.time(),
            'adaptive_timeout': timeout,
            'reassembled_data': b'',
            'is_complete': False
        })
        
        # 用于存储UDP流的数据结构
        self.udp_streams = defaultdict(lambda: {
            'fragments': {},
            'last_activity': time.time(),
            'reassembled_data': b'',
            'is_complete': False
        })
        
        # 用于存储IP分片的数据结构
        # 格式: {(src_ip, dst_ip, id): {
        #   'fragments': {offset: {'data': bytes, 'timestamp': float, 'more_fragments': bool}},
        #   'last_activity': float,
        #   'total_length': int,
        #   'is_complete': bool
        # }}
        self.ip_fragments = defaultdict(lambda: {
            'fragments': {},
            'last_activity': time.time(),
            'total_length': 0,
            'is_complete': False
        })
        
        # 用于跟踪每个流的统计信息
        self.flow_stats = defaultdict(lambda: {
            'total_packets': 0,
            'reassembled_packets': 0,
            'lost_packets': 0,
            'out_of_order_packets': 0,
            'retransmitted_packets': 0,
            'duplicate_packets': 0,
            'start_time': time.time(),
            'last_activity': time.time(),
            'expected_seq': 0,
            'protocol': 'unknown'
        })
        
        # 启动清理线程
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
        logger.info(f"初始化增强型数据包重组器: timeout={timeout}s, max_fragments={max_fragments}, "
                  f"buffer_size={buffer_size}字节, 自适应超时={enable_adaptive_timeout}")
    
    def __del__(self):
        """
        析构函数，确保清理线程停止
        """
        self.running = False
        if hasattr(self, 'cleanup_thread') and self.cleanup_thread.is_alive():
            self.cleanup_thread.join(timeout=1)
    
    def _cleanup_loop(self):
        """
        定期清理过期流的循环
        """
        while self.running:
            time.sleep(self.cleanup_interval)
            self.cleanup_expired_flows()
    
    def add_tcp_packet(self, flow_id, seq_num, data, flags=None, timestamp=None):
        """
        添加TCP数据包到重组器
        
        Args:
            flow_id (str): 流标识符，通常是五元组的哈希值
            seq_num (int): 序列号
            data (bytes): 数据包内容
            flags (dict): TCP标志，如{'fin': False, 'syn': False, 'rst': False, 'psh': False, 'ack': True}
            timestamp (float): 数据包时间戳，如果为None则使用当前时间
            
        Returns:
            bool: 添加是否成功
        """
        if timestamp is None:
            timestamp = time.time()
        
        if flags is None:
            flags = {}
        
        # 更新流统计信息
        if flow_id not in self.flow_stats:
            self.flow_stats[flow_id] = {
                'total_packets': 0,
                'reassembled_packets': 0,
                'lost_packets': 0,
                'out_of_order_packets': 0,
                'retransmitted_packets': 0,
                'duplicate_packets': 0,
                'start_time': timestamp,
                'last_activity': timestamp,
                'expected_seq': seq_num,
                'protocol': 'tcp'
            }
        
        self.flow_stats[flow_id]['total_packets'] += 1
        self.flow_stats[flow_id]['last_activity'] = timestamp
        
        # 获取TCP流
        tcp_stream = self.tcp_streams[flow_id]
        tcp_stream['last_activity'] = timestamp
        
        # 检查是否是SYN包，如果是则重置流
        if flags.get('syn', False) and not flags.get('ack', False):
            tcp_stream['fragments'] = {}
            tcp_stream['next_seq'] = seq_num + 1  # SYN占用一个序列号
            tcp_stream['reassembled_data'] = b''
            tcp_stream['is_complete'] = False
            self.flow_stats[flow_id]['expected_seq'] = seq_num + 1
            logger.debug(f"TCP流 {flow_id} 重置 (SYN): next_seq={tcp_stream['next_seq']}")
            return True
        
        # 检查是否是重置包
        if flags.get('rst', False):
            tcp_stream['is_complete'] = True
            logger.debug(f"TCP流 {flow_id} 被重置 (RST)")
            return True
        
        # 检查是否是FIN包
        if flags.get('fin', False):
            # 添加FIN标记但不处理数据
            tcp_stream['fragments'][seq_num] = {
                'data': b'',
                'timestamp': timestamp,
                'flags': flags,
                'fin': True
            }
            logger.debug(f"TCP流 {flow_id} 收到FIN: seq={seq_num}")
            return True
        
        # 如果没有数据，不处理
        if not data:
            return True
        
        # 检查是否超过最大分片数
        if len(tcp_stream['fragments']) >= self.max_fragments:
            # 尝试先重组一次，看能否释放一些空间
            self._reassemble_tcp_stream(flow_id)
            
            # 如果仍然超过限制，丢弃新分片
            if len(tcp_stream['fragments']) >= self.max_fragments:
                logger.warning(f"TCP流 {flow_id} 超过最大分片数 {self.max_fragments}，丢弃新分片")
                self.flow_stats[flow_id]['lost_packets'] += 1
                return False
        
        # 检查是否是重传包
        if seq_num in tcp_stream['fragments']:
            existing_fragment = tcp_stream['fragments'][seq_num]
            if existing_fragment['data'] == data:
                self.flow_stats[flow_id]['duplicate_packets'] += 1
                logger.debug(f"TCP流 {flow_id} 收到重复包: seq={seq_num}, 大小={len(data)}字节")
                return True
            else:
                self.flow_stats[flow_id]['retransmitted_packets'] += 1
                logger.debug(f"TCP流 {flow_id} 收到重传包: seq={seq_num}, 大小={len(data)}字节")
        
        # 检查是否乱序
        expected_seq = self.flow_stats[flow_id]['expected_seq']
        if seq_num != expected_seq:
            self.flow_stats[flow_id]['out_of_order_packets'] += 1
            logger.debug(f"TCP流 {flow_id} 收到乱序包: seq={seq_num}, 期望={expected_seq}")
        else:
            self.flow_stats[flow_id]['expected_seq'] = seq_num + len(data)
        
        # 存储分片
        tcp_stream['fragments'][seq_num] = {
            'data': data,
            'timestamp': timestamp,
            'flags': flags
        }
        
        logger.debug(f"添加TCP分片: 流={flow_id}, 序列号={seq_num}, 大小={len(data)}字节")
        
        # 尝试重组
        self._reassemble_tcp_stream(flow_id)
        
        return True
    
    def add_udp_packet(self, flow_id, data, timestamp=None):
        """
        添加UDP数据包到重组器
        
        Args:
            flow_id (str): 流标识符
            data (bytes): 数据包内容
            timestamp (float): 数据包时间戳，如果为None则使用当前时间
            
        Returns:
            bool: 添加是否成功
        """
        if timestamp is None:
            timestamp = time.time()
        
        # 更新流统计信息
        if flow_id not in self.flow_stats:
            self.flow_stats[flow_id] = {
                'total_packets': 1,
                'reassembled_packets': 0,
                'lost_packets': 0,
                'out_of_order_packets': 0,
                'retransmitted_packets': 0,
                'duplicate_packets': 0,
                'start_time': timestamp,
                'last_activity': timestamp,
                'expected_seq': 0,
                'protocol': 'udp'
            }
        else:
            self.flow_stats[flow_id]['total_packets'] += 1
            self.flow_stats[flow_id]['last_activity'] = timestamp
        
        # 获取UDP流
        udp_stream = self.udp_streams[flow_id]
        udp_stream['last_activity'] = timestamp
        
        # 对于UDP，我们简单地按照接收顺序追加数据
        packet_id = len(udp_stream['fragments'])
        udp_stream['fragments'][packet_id] = {
            'data': data,
            'timestamp': timestamp
        }
        
        # 更新重组数据
        udp_stream['reassembled_data'] += data
        self.flow_stats[flow_id]['reassembled_packets'] += 1
        
        logger.debug(f"添加UDP分片: 流={flow_id}, ID={packet_id}, 大小={len(data)}字节")
        return True
    
    def add_ip_fragment(self, src_ip, dst_ip, id, offset, data, more_fragments, timestamp=None):
        """
        添加IP分片到重组器
        
        Args:
            src_ip (str): 源IP地址
            dst_ip (str): 目标IP地址
            id (int): IP标识
            offset (int): 分片偏移（以8字节为单位）
            data (bytes): 分片数据
            more_fragments (bool): 是否有更多分片
            timestamp (float): 数据包时间戳，如果为None则使用当前时间
            
        Returns:
            bool: 添加是否成功
        """
        if timestamp is None:
            timestamp = time.time()
        
        # 创建IP分片标识符
        fragment_id = (src_ip, dst_ip, id)
        flow_id = f"{src_ip}_{dst_ip}_{id}"
        
        # 更新流统计信息
        if flow_id not in self.flow_stats:
            self.flow_stats[flow_id] = {
                'total_packets': 1,
                'reassembled_packets': 0,
                'lost_packets': 0,
                'out_of_order_packets': 0,
                'retransmitted_packets': 0,
                'duplicate_packets': 0,
                'start_time': timestamp,
                'last_activity': timestamp,
                'expected_seq': 0,
                'protocol': 'ip'
            }
        else:
            self.flow_stats[flow_id]['total_packets'] += 1
            self.flow_stats[flow_id]['last_activity'] = timestamp
        
        # 获取IP分片集合
        ip_fragment_set = self.ip_fragments[fragment_id]
        ip_fragment_set['last_activity'] = timestamp
        
        # 检查是否超过最大分片数
        if len(ip_fragment_set['fragments']) >= self.max_fragments:
            logger.warning(f"IP分片集 {fragment_id} 超过最大分片数 {self.max_fragments}，丢弃新分片")
            self.flow_stats[flow_id]['lost_packets'] += 1
            return False
        
        # 检查是否是重复分片
        if offset in ip_fragment_set['fragments']:
            existing_fragment = ip_fragment_set['fragments'][offset]
            if existing_fragment['data'] == data:
                self.flow_stats[flow_id]['duplicate_packets'] += 1
                logger.debug(f"IP分片集 {fragment_id} 收到重复分片: offset={offset}, 大小={len(data)}字节")
                return True
            else:
                self.flow_stats[flow_id]['retransmitted_packets'] += 1
                logger.debug(f"IP分片集 {fragment_id} 收到重传分片: offset={offset}, 大小={len(data)}字节")
        
        # 存储分片
        ip_fragment_set['fragments'][offset] = {
            'data': data,
            'timestamp': timestamp,
            'more_fragments': more_fragments
        }
        
        # 更新总长度
        fragment_end = offset * 8 + len(data)
        if fragment_end > ip_fragment_set['total_length']:
            ip_fragment_set['total_length'] = fragment_end
        
        logger.debug(f"添加IP分片: ID={fragment_id}, 偏移={offset}, 大小={len(data)}字节, 更多分片={more_fragments}")
        
        # 尝试重组
        self._reassemble_ip_fragments(fragment_id)
        
        return True
    
    def _reassemble_tcp_stream(self, flow_id):
        """
        尝试重组TCP流
        
        Args:
            flow_id (str): 流标识符
            
        Returns:
            bool: 是否有新数据被重组
        """
        if flow_id not in self.tcp_streams:
            return False
        
        tcp_stream = self.tcp_streams[flow_id]
        fragments = tcp_stream['fragments']
        next_seq = tcp_stream['next_seq']
        reassembled = False
        
        # 按序列号排序分片
        sorted_seqs = sorted(fragments.keys())
        
        # 尝试按顺序重组
        while sorted_seqs:
            # 找到下一个期望的序列号
            if next_seq in fragments:
                fragment = fragments[next_seq]
                data = fragment['data']
                
                # 添加到重组数据
                tcp_stream['reassembled_data'] += data
                self.flow_stats[flow_id]['reassembled_packets'] += 1
                
                # 更新下一个期望的序列号
                next_seq += len(data)
                tcp_stream['next_seq'] = next_seq
                
                # 检查是否有FIN标志
                if fragment.get('fin', False):
                    tcp_stream['is_complete'] = True
                    logger.info(f"TCP流 {flow_id} 重组完成 (FIN): {len(tcp_stream['reassembled_data'])}字节")
                
                # 移除已处理的分片
                del fragments[sorted_seqs[0]]
                sorted_seqs.pop(0)
                reassembled = True
            else:
                # 没有找到下一个期望的序列号，尝试处理乱序分片
                # 查找序列号最接近next_seq的分片
                closest_seq = None
                for seq in sorted_seqs:
                    if seq > next_seq:
                        if closest_seq is None or seq < closest_seq:
                            closest_seq = seq
                
                if closest_seq is not None and closest_seq - next_seq < 1000:  # 允许小的序列号间隙
                    # 填充缺失的数据（用零字节）
                    missing_bytes = closest_seq - next_seq
                    logger.debug(f"TCP流 {flow_id} 填充缺失数据: {missing_bytes}字节")
                    tcp_stream['reassembled_data'] += b'\x00' * missing_bytes
                    next_seq = closest_seq
                    # 继续循环，不删除sorted_seqs中的元素
                else:
                    # 间隙太大或没有找到合适的分片，退出循环
                    break
        
        # 更新自适应超时
        if self.enable_adaptive_timeout and reassembled:
            # 根据重组效率调整超时时间
            reassembly_rate = self.flow_stats[flow_id]['reassembled_packets'] / self.flow_stats[flow_id]['total_packets']
            if reassembly_rate > 0.8:
                # 高效率，可以减少超时时间
                tcp_stream['adaptive_timeout'] = max(self.timeout / 2, 10)  # 最小10秒
            elif reassembly_rate < 0.5:
                # 低效率，增加超时时间
                tcp_stream['adaptive_timeout'] = min(self.timeout * 2, 300)  # 最大300秒
        
        return reassembled
    
    def _reassemble_ip_fragments(self, fragment_id):
        """
        尝试重组IP分片
        
        Args:
            fragment_id (tuple): 分片标识符 (src_ip, dst_ip, id)
            
        Returns:
            tuple: (是否完成, 重组后的数据)
        """
        if fragment_id not in self.ip_fragments:
            return False, b''
        
        ip_fragment_set = self.ip_fragments[fragment_id]
        fragments = ip_fragment_set['fragments']
        
        # 检查是否有所有分片
        if not fragments:
            return False, b''
        
        # 检查是否有最后一个分片（more_fragments=False）
        has_last_fragment = any(not frag['more_fragments'] for frag in fragments.values())
        if not has_last_fragment:
            return False, b''
        
        # 检查是否有所有偏移的分片
        offsets = sorted(fragments.keys())
        
        # 第一个偏移必须是0
        if offsets[0] != 0:
            return False, b''
        
        # 检查是否有间隙
        reassembled_data = bytearray(ip_fragment_set['total_length'])
        all_fragments_present = True
        
        for i, offset in enumerate(offsets):
            fragment = fragments[offset]
            data = fragment['data']
            offset_bytes = offset * 8
            
            # 复制数据到正确的位置
            reassembled_data[offset_bytes:offset_bytes + len(data)] = data
            
            # 检查是否有间隙
            if i < len(offsets) - 1:
                next_offset = offsets[i + 1] * 8
                current_end = offset_bytes + len(data)
                if current_end < next_offset:
                    all_fragments_present = False
                    break
        
        # 如果所有分片都存在，标记为完成并返回重组数据
        if all_fragments_present:
            ip_fragment_set['is_complete'] = True
            flow_id = f"{fragment_id[0]}_{fragment_id[1]}_{fragment_id[2]}"
            self.flow_stats[flow_id]['reassembled_packets'] += len(fragments)
            
            logger.info(f"IP分片集 {fragment_id} 重组完成: {len(reassembled_data)}字节, {len(fragments)}个分片")
            return True, bytes(reassembled_data)
        
        return False, b''
    
    def get_reassembled_tcp_data(self, flow_id):
        """
        获取重组后的TCP数据
        
        Args:
            flow_id (str): 流标识符
            
        Returns:
            tuple: (是否完成, 重组后的数据)
        """
        if flow_id not in self.tcp_streams:
            return False, b''
        
        tcp_stream = self.tcp_streams[flow_id]
        
        # 尝试重组一次，确保获取最新数据
        self._reassemble_tcp_stream(flow_id)
        
        return tcp_stream['is_complete'], tcp_stream['reassembled_data']
    
    def get_reassembled_udp_data(self, flow_id):
        """
        获取重组后的UDP数据
        
        Args:
            flow_id (str): 流标识符
            
        Returns:
            bytes: 重组后的数据
        """
        if flow_id not in self.udp_streams:
            return b''
        
        return self.udp_streams[flow_id]['reassembled_data']
    
    def get_reassembled_ip_data(self, src_ip, dst_ip, id):
        """
        获取重组后的IP数据
        
        Args:
            src_ip (str): 源IP地址
            dst_ip (str): 目标IP地址
            id (int): IP标识
            
        Returns:
            tuple: (是否完成, 重组后的数据)
        """
        fragment_id = (src_ip, dst_ip, id)
        
        if fragment_id not in self.ip_fragments:
            return False, b''
        
        # 尝试重组一次，确保获取最新数据
        return self._reassemble_ip_fragments(fragment_id)
    
    def cleanup_flow(self, flow_id):
        """
        清理指定流的所有分片和统计信息
        
        Args:
            flow_id (str): 流标识符
        """
        # 清理TCP流
        if flow_id in self.tcp_streams:
            del self.tcp_streams[flow_id]
        
        # 清理UDP流
        if flow_id in self.udp_streams:
            del self.udp_streams[flow_id]
        
        # 清理统计信息
        if flow_id in self.flow_stats:
            stats = self.flow_stats[flow_id]
            reassembly_rate = stats['reassembled_packets'] / stats['total_packets'] if stats['total_packets'] > 0 else 0
            logger.info(f"流 {flow_id} 清理: 总分片={stats['total_packets']}, 重组={stats['reassembled_packets']}, "
                      f"丢失={stats['lost_packets']}, 乱序={stats['out_of_order_packets']}, "
                      f"重传={stats['retransmitted_packets']}, 重复={stats['duplicate_packets']}, "
                      f"重组率={reassembly_rate:.2%}")
            del self.flow_stats[flow_id]
    
    def cleanup_ip_fragment(self, src_ip, dst_ip, id):
        """
        清理指定IP分片集
        
        Args:
            src_ip (str): 源IP地址
            dst_ip (str): 目标IP地址
            id (int): IP标识
        """
        fragment_id = (src_ip, dst_ip, id)
        
        if fragment_id in self.ip_fragments:
            del self.ip_fragments[fragment_id]
            
            # 清理相关统计信息
            flow_id = f"{src_ip}_{dst_ip}_{id}"
            if flow_id in self.flow_stats:
                del self.flow_stats[flow_id]
                
    def get_reassembly_statistics(self):
        """
        获取重组统计信息
        
        Returns:
            dict: 重组统计信息
        """
        # 计算总体统计信息
        total_packets = sum(stats['total_packets'] for stats in self.flow_stats.values())
        reassembled_packets = sum(stats['reassembled_packets'] for stats in self.flow_stats.values())
        lost_packets = sum(stats['lost_packets'] for stats in self.flow_stats.values())
        out_of_order_packets = sum(stats['out_of_order_packets'] for stats in self.flow_stats.values())
        retransmitted_packets = sum(stats['retransmitted_packets'] for stats in self.flow_stats.values())
        duplicate_packets = sum(stats['duplicate_packets'] for stats in self.flow_stats.values())
        
        # 计算协议分布
        protocol_stats = {
            'tcp': 0,
            'udp': 0,
            'ip': 0,
            'unknown': 0
        }
        
        for stats in self.flow_stats.values():
            protocol = stats.get('protocol', 'unknown')
            protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1
        
        # 计算重组率
        reassembly_rate = reassembled_packets / total_packets if total_packets > 0 else 0
        
        # 获取活跃流数量
        active_tcp_flows = len(self.tcp_streams)
        active_udp_flows = len(self.udp_streams)
        active_ip_fragments = len(self.ip_fragments)
        
        return {
            'timestamp': time.time(),
            'total_packets': total_packets,
            'reassembled_packets': reassembled_packets,
            'lost_packets': lost_packets,
            'out_of_order_packets': out_of_order_packets,
            'retransmitted_packets': retransmitted_packets,
            'duplicate_packets': duplicate_packets,
            'reassembly_rate': reassembly_rate,
            'active_tcp_flows': active_tcp_flows,
            'active_udp_flows': active_udp_flows,
            'active_ip_fragments': active_ip_fragments,
            'protocol_stats': protocol_stats
        }
    
    def cleanup_expired_flows(self):
        """
        清理所有超时的流
        
        Returns:
            int: 清理的流数量
        """
        current_time = time.time()
        expired_count = 0
        
        # 清理TCP流
        expired_tcp_flows = []
        for flow_id, stream in self.tcp_streams.items():
            timeout = stream['adaptive_timeout'] if self.enable_adaptive_timeout else self.timeout
            if current_time - stream['last_activity'] > timeout:
                expired_tcp_flows.append(flow_id)
        
        for flow_id in expired_tcp_flows:
            logger.info(f"TCP流 {flow_id} 超时，清理")
            self.cleanup_flow(flow_id)
            expired_count += 1
        
        # 清理UDP流
        expired_udp_flows = []
        for flow_id, stream in self.udp_streams.items():
            if current_time - stream['last_activity'] > self.timeout:
                expired_udp_flows.append(flow_id)
        
        for flow_id in expired_udp_flows:
            logger.info(f"UDP流 {flow_id} 超时，清理")
            self.cleanup_flow(flow_id)
            expired_count += 1
        
        # 清理IP分片
        expired_ip_fragments = []
        for fragment_id, fragment_set in self.ip_fragments.items():
            if current_time - fragment_set['last_activity'] > self.timeout:
                expired_ip_fragments.append(fragment_id)
        
        for fragment_id in expired_ip_fragments:
            src_ip, dst_ip, id = fragment_id
            logger.info(f"IP分片集 {fragment_id} 超时，清理")
            self.cleanup_ip_fragment(src_ip, dst_ip, id)
            expired_count += 1
        
        return expired_count
            src_ip, dst_ip, id = fragment_id
            logger.info(f"IP分片集 {fragment_i