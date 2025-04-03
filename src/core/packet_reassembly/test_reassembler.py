#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
数据包重组算法测试脚本

该脚本用于测试数据包重组算法的性能，模拟不同的网络条件（丢包、乱序、延迟等），
并评估算法的还原率是否达到60%以上的目标。
"""

import os
import sys
import time
import random
import logging
from collections import defaultdict

# 导入数据包重组器
from packet_reassembler import PacketReassembler

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkSimulator:
    """
    网络模拟器类
    
    用于模拟各种网络条件，如丢包、乱序、延迟等，以测试数据包重组算法的性能。
    """
    
    def __init__(self, packet_loss_rate=0.1, out_of_order_rate=0.2, delay_rate=0.15, duplicate_rate=0.05):
        """
        初始化网络模拟器
        
        Args:
            packet_loss_rate (float): 丢包率 (0.0-1.0)
            out_of_order_rate (float): 乱序率 (0.0-1.0)
            delay_rate (float): 延迟率 (0.0-1.0)
            duplicate_rate (float): 重复率 (0.0-1.0)
        """
        self.packet_loss_rate = packet_loss_rate
        self.out_of_order_rate = out_of_order_rate
        self.delay_rate = delay_rate
        self.duplicate_rate = duplicate_rate
        
        # 用于存储延迟的数据包
        self.delayed_packets = []
        
        logger.info(f"初始化网络模拟器: 丢包率={packet_loss_rate:.1%}, 乱序率={out_of_order_rate:.1%}, "
                  f"延迟率={delay_rate:.1%}, 重复率={duplicate_rate:.1%}")
    
    def process_packets(self, packets):
        """
        处理数据包，模拟网络条件
        
        Args:
            packets (list): 原始数据包列表，每个数据包是一个元组 (seq_num, data, is_last)
            
        Returns:
            list: 经过网络条件模拟后的数据包列表
        """
        processed_packets = []
        delayed_packets = []
        
        for packet in packets:
            seq_num, data, is_last = packet
            
            # 模拟丢包
            if random.random() < self.packet_loss_rate:
                logger.debug(f"丢弃数据包: seq_num={seq_num}")
                continue
            
            # 模拟延迟
            if random.random() < self.delay_rate:
                delay_time = random.uniform(0.5, 2.0)  # 延迟0.5-2秒
                logger.debug(f"延迟数据包: seq_num={seq_num}, delay={delay_time:.2f}s")
                delayed_packets.append((seq_num, data, is_last, delay_time))
                continue
            
            # 模拟重复
            if random.random() < self.duplicate_rate:
                logger.debug(f"重复数据包: seq_num={seq_num}")
                processed_packets.append((seq_num, data, is_last))
            
            processed_packets.append((seq_num, data, is_last))
        
        # 处理延迟的数据包
        for packet in delayed_packets:
            seq_num, data, is_last, _ = packet
            processed_packets.append((seq_num, data, is_last))
        
        # 模拟乱序（打乱数据包顺序）
        if random.random() < self.out_of_order_rate:
            logger.debug("打乱数据包顺序")
            random.shuffle(processed_packets)
        
        return processed_packets


def generate_test_data(num_flows=5, packets_per_flow=100, packet_size=1024):
    """
    生成测试数据
    
    Args:
        num_flows (int): 流的数量
        packets_per_flow (int): 每个流的数据包数量
        packet_size (int): 每个数据包的大小（字节）
        
    Returns:
        dict: 测试数据，格式为 {flow_id: [(seq_num, data, is_last), ...]}
    """
    test_data = {}
    
    for flow_id in range(num_flows):
        flow_id_str = f"flow_{flow_id}"
        packets = []
        
        for seq_num in range(packets_per_flow):
            # 生成随机数据
            data = os.urandom(packet_size)
            is_last = (seq_num == packets_per_flow - 1)
            
            packets.append((seq_num, data, is_last))
        
        test_data[flow_id_str] = packets
    
    return test_data


def run_reassembly_test(test_data, network_conditions):
    """
    运行重组测试
    
    Args:
        test_data (dict): 测试数据，格式为 {flow_id: [(seq_num, data, is_last), ...]}
        network_conditions (list): 网络条件列表，每个条件是一个字典
        
    Returns:
        dict: 测试结果
    """
    results = {}
    
    for condition_name, condition_params in network_conditions.items():
        logger.info(f"测试网络条件: {condition_name}")
        
        # 创建网络模拟器
        simulator = NetworkSimulator(**condition_params)
        
        # 创建数据包重组器
        reassembler = PacketReassembler(timeout=30, max_fragments=1000)
        
        # 跟踪原始数据和重组数据
        original_data = {}
        reassembled_data = {}
        
        # 处理每个流
        for flow_id, packets in test_data.items():
            # 保存原始数据
            original_data[flow_id] = b''.join([data for _, data, _ in packets])
            
            # 模拟网络条件
            processed_packets = simulator.process_packets(packets)
            
            # 添加到重组器
            for seq_num, data, is_last in processed_packets:
                reassembler.add_fragment(flow_id, seq_num, data, is_last)
            
            # 尝试重组
            is_complete, data = reassembler.reassemble_flow(flow_id)
            reassembled_data[flow_id] = data
        
        # 计算还原率
        total_original_size = sum(len(data) for data in original_data.values())
        total_reassembled_size = sum(len(data) for data in reassembled_data.values())
        
        # 计算准确性（字节级别的匹配）
        correct_bytes = 0
        for flow_id in original_data:
            orig = original_data[flow_id]
            reasm = reassembled_data[flow_id]
            
            # 计算匹配的字节数
            min_len = min(len(orig), len(reasm))
            for i in range(min_len):
                if orig[i] == reasm[i]:
                    correct_bytes += 1
        
        accuracy = correct_bytes / total_original_size if total_original_size > 0 else 0
        reassembly_rate = total_reassembled_size / total_original_size if total_original_size > 0 else 0
        
        # 获取重组器统计信息
        stats = reassembler.get_reassembly_statistics()
        
        results[condition_name] = {
            'accuracy': accuracy,
            'reassembly_rate': reassembly_rate,
            'stats': stats
        }
        
        logger.info(f"测试结果 - {condition_name}: 准确率={accuracy:.2%}, 还原率={reassembly_rate:.2%}")
    
    return results


def main():
    """
    主函数
    """
    # 定义不同的网络条件
    network_conditions = {
        '理想网络': {
            'packet_loss_rate': 0.0,
            'out_of_order_rate': 0.0,
            'delay_rate': 0.0,
            'duplicate_rate': 0.0
        },
        '轻度拥塞': {
            'packet_loss_rate': 0.05,
            'out_of_order_rate': 0.1,
            'delay_rate': 0.1,
            'duplicate_rate': 0.02
        },
        '中度拥塞': {
            'packet_loss_rate': 0.1,
            'out_of_order_rate': 0.2,
            'delay_rate': 0.15,
            'duplicate_rate': 0.05
        },
        '重度拥塞': {
            'packet_loss_rate': 0.2,
            'out_of_order_rate': 0.3,
            'delay_rate': 0.2,
            'duplicate_rate': 0.1
        },
        '极端条件': {
            'packet_loss_rate': 0.3,
            'out_of_order_rate': 0.4,
            'delay_rate': 0.3,
            'duplicate_rate': 0.15
        }
    }
    
    # 生成测试数据
    logger.info("生成测试数据...")
    test_data = generate_test_data(num_flows=5, packets_per_flow=100, packet_size=1024)
    
    # 运行测试
    logger.info("开始测试...")
    results = run_reassembly_test(test_data, network_conditions)
    
    # 打印总结
    print("\n测试结果总结:")
    print("-" * 80)
    print(f"{'网络条件':<15} {'准确率':<10} {'还原率':<10} {'是否达标':<10}")
    print("-" * 80)
    
    for condition, result in results.items():
        accuracy = result['accuracy']
        reassembly_rate = result['reassembly_rate']
        is_qualified = "是" if reassembly_rate >= 0.6 else "否"
        
        print(f"{condition:<15} {accuracy:.2%}     {reassembly_rate:.2%}     {is_qualified:<10}")
    
    print("-" * 80)
    
    # 检查是否达到目标
    target_achieved = all(result['reassembly_rate'] >= 0.6 for result in results.values())
    if target_achieved:
        print("\n恭喜！数据包重组算法在所有测试条件下都达到了60%以上的还原率目标。")
    else:
        print("\n警告：数据包重组算法在某些测试条件下未达到60%的还原率目标，需要进一步优化。")


if __name__ == "__main__":
    main()