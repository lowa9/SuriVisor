#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
流量分析模块测试脚本

该脚本用于测试流量分析模块的性能，模拟不同类型的网络攻击场景，
并评估分类准确率是否达到60%以上的目标。
"""

import os
import sys
import time
import random
import logging
import json
from collections import defaultdict
from datetime import datetime

# 导入流量分析器
from traffic_analyzer import TrafficAnalyzer

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TrafficGenerator:
    """
    流量生成器类
    
    用于生成模拟的网络流量数据，包括正常流量和各种攻击流量。
    """
    
    def __init__(self):
        """
        初始化流量生成器
        """
        self.local_networks = ["192.168.1.", "10.0.0."]
        self.external_networks = ["203.0.113.", "198.51.100.", "8.8.8."]
        self.common_ports = [80, 443, 22, 25, 53, 3389, 3306, 5432]
        
        logger.info("初始化流量生成器")
    
    def _generate_ip(self, is_local=True):
        """
        生成IP地址
        
        Args:
            is_local (bool): 是否生成本地IP
            
        Returns:
            str: IP地址
        """
        if is_local:
            prefix = random.choice(self.local_networks)
        else:
            prefix = random.choice(self.external_networks)
        
        return f"{prefix}{random.randint(1, 254)}"
    
    def _generate_port(self, is_common=True):
        """
        生成端口号
        
        Args:
            is_common (bool): 是否生成常用端口
            
        Returns:
            int: 端口号
        """
        if is_common:
            return random.choice(self.common_ports)
        else:
            return random.randint(1024, 65535)
    
    def generate_normal_traffic(self, flow_count=10, packets_per_flow=100):
        """
        生成正常流量
        
        Args:
            flow_count (int): 流的数量
            packets_per_flow (int): 每个流的数据包数量
            
        Returns:
            dict: 生成的流量数据
        """
        flows = {}
        
        for i in range(flow_count):
            flow_id = f"normal_flow_{i}"
            src_ip = self._generate_ip(is_local=True)
            dst_ip = self._generate_ip(is_local=random.random() < 0.7)  # 70%是本地流量
            src_port = self._generate_port(is_common=False)
            dst_port = self._generate_port(is_common=True)
            
            packets = []
            start_time = time.time()
            
            for j in range(packets_per_flow):
                # 正常流量的特点：包大小适中，时间间隔合理，SYN包只在开始
                packet = {
                    "timestamp": start_time + j * random.uniform(0.1, 1.0),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "size": random.randint(64, 1500),
                    "flags": {"syn": j == 0, "ack": j > 0, "fin": j == packets_per_flow - 1}
                }
                packets.append(packet)
            
            flows[flow_id] = {"packets": packets, "metadata": {"type": "normal"}}
        
        logger.info(f"生成了{flow_count}个正常流量")
        return flows
    
    def generate_port_scan_traffic(self, flow_count=5, target_count=3):
        """
        生成端口扫描流量
        
        Args:
            flow_count (int): 流的数量
            target_count (int): 每个流扫描的目标数量
            
        Returns:
            dict: 生成的流量数据
        """
        flows = {}
        
        for i in range(flow_count):
            flow_id = f"port_scan_flow_{i}"
            src_ip = self._generate_ip(is_local=True)
            
            all_packets = []
            start_time = time.time()
            
            # 对多个目标进行扫描
            for t in range(target_count):
                dst_ip = self._generate_ip(is_local=True)
                
                # 扫描多个端口
                for port in range(1, 101):  # 扫描100个端口
                    packet = {
                        "timestamp": start_time + len(all_packets) * 0.01,  # 快速扫描
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": random.randint(50000, 60000),
                        "dst_port": port,
                        "protocol": "TCP",
                        "size": random.randint(40, 60),  # 小包
                        "flags": {"syn": True, "ack": False}  # SYN扫描
                    }
                    all_packets.append(packet)
            
            flows[flow_id] = {"packets": all_packets, "metadata": {"type": "port_scan"}}
        
        logger.info(f"生成了{flow_count}个端口扫描流量")
        return flows
    
    def generate_ddos_traffic(self, flow_count=5, source_count=20, packets_per_source=50):
        """
        生成DDoS攻击流量
        
        Args:
            flow_count (int): 流的数量
            source_count (int): 每个流的源IP数量
            packets_per_source (int): 每个源IP发送的数据包数量
            
        Returns:
            dict: 生成的流量数据
        """
        flows = {}
        
        for i in range(flow_count):
            flow_id = f"ddos_flow_{i}"
            dst_ip = self._generate_ip(is_local=True)  # 目标是本地服务器
            dst_port = self._generate_port(is_common=True)  # 目标是常用服务端口
            
            all_packets = []
            start_time = time.time()
            
            # 多个源IP同时发送请求
            for s in range(source_count):
                src_ip = self._generate_ip(is_local=False)  # 源是外部IP
                src_port = random.randint(10000, 65000)
                
                for p in range(packets_per_source):
                    # DDoS特点：大量小包，高频率，多为SYN包
                    packet = {
                        "timestamp": start_time + p * 0.001,  # 非常高频
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": "TCP",
                        "size": random.randint(40, 100),  # 小包
                        "flags": {"syn": True, "ack": False}  # SYN洪水
                    }
                    all_packets.append(packet)
            
            # 打乱数据包顺序，模拟真实网络环境
            random.shuffle(all_packets)
            
            flows[flow_id] = {"packets": all_packets, "metadata": {"type": "ddos"}}
        
        logger.info(f"生成了{flow_count}个DDoS攻击流量")
        return flows
    
    def generate_brute_force_traffic(self, flow_count=5, attempts_per_flow=100):
        """
        生成暴力破解攻击流量
        
        Args:
            flow_count (int): 流的数量
            attempts_per_flow (int): 每个流的尝试次数
            
        Returns:
            dict: 生成的流量数据
        """
        flows = {}
        
        for i in range(flow_count):
            flow_id = f"brute_force_flow_{i}"
            src_ip = self._generate_ip(is_local=False)  # 攻击者IP
            dst_ip = self._generate_ip(is_local=True)   # 目标服务器
            dst_port = random.choice([22, 3389, 21, 25, 110])  # SSH, RDP, FTP, SMTP, POP3
            
            packets = []
            login_attempts = []
            start_time = time.time()
            
            # 用户名列表
            usernames = ["admin", "root", "user", "guest", "administrator"]
            
            for j in range(attempts_per_flow):
                # 每次尝试包含请求和响应
                request_time = start_time + j * random.uniform(0.5, 2.0)  # 较快的尝试频率
                
                # 登录请求包
                request = {
                    "timestamp": request_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": random.randint(50000, 60000),
                    "dst_port": dst_port,
                    "protocol": "TCP",
                    "size": random.randint(100, 300),
                    "flags": {"ack": True}
                }
                packets.append(request)
                
                # 登录响应包
                response = {
                    "timestamp": request_time + random.uniform(0.1, 0.3),
                    "src_ip": dst_ip,
                    "dst_ip": src_ip,
                    "src_port": dst_port,
                    "dst_port": request["src_port"],
                    "protocol": "TCP",
                    "size": random.randint(100, 300),
                    "flags": {"ack": True}
                }
                packets.append(response)
                
                # 记录登录尝试
                success = j == attempts_per_flow - 1  # 最后一次尝试成功
                login_attempts.append({
                    "timestamp": request_time,
                    "username": random.choice(usernames),
                    "success": success
                })
            
            flows[flow_id] = {
                "packets": packets, 
                "metadata": {
                    "type": "brute_force",
                    "login_attempts": login_attempts
                }
            }
        
        logger.info(f"生成了{flow_count}个暴力破解攻击流量")
        return flows
    
    def generate_arp_spoofing_traffic(self, flow_count=5, packets_per_flow=100):
        """
        生成ARP欺骗攻击流量
        
        Args:
            flow_count (int): 流的数量
            packets_per_flow (int): 每个流的数据包数量
            
        Returns:
            dict: 生成的流量数据
        """
        flows = {}
        
        for i in range(flow_count):
            flow_id = f"arp_spoofing_flow_{i}"
            attacker_ip = self._generate_ip(is_local=True)
            attacker_mac = ":'.join(['%02x' % random.randint(0, 255) for _ in range(6)])
            gateway_ip = self._generate_ip(is_local=True).rsplit('.', 1)[0] + ".1"  # 网关IP
            target_ip = self._generate_ip(is_local=True)
            
            packets = []
            start_time = time.time()
            
            for j in range(packets_per_flow):
                # ARP欺骗特点：大量无故ARP响应，IP-MAC映射异常
                is_gratuitous = random.random() < 0.7  # 70%是无故ARP
                
                packet = {
                    "timestamp": start_time + j * random.uniform(0.5, 2.0),
                    "protocol": "ARP",
                    "size": random.randint(40, 60),
                    "arp_operation": 2,  # ARP响应
                    "arp_sender_ip": gateway_ip if is_gratuitous else attacker_ip,
                    "arp_sender_mac": attacker_mac,  # 攻击者MAC
                    "arp_target_ip": target_ip if is_gratuitous else gateway_ip,
                    "gratuitous_arp": is_gratuitous,
                    "arp_reply_without_request": is_gratuitous
                }
                packets.append(packet)
            
            flows[flow_id] = {"packets": packets, "metadata": {"type": "arp_spoofing"}}
        
        logger.info(f"生成了{flow_count}个ARP欺骗攻击流量")
        return flows
    
    def generate_data_exfiltration_traffic(self, flow_count=5, packets_per_flow=100):
        """
        生成数据泄露流量
        
        Args:
            flow_count (int): 流的数量
            packets_per_flow (int): 每个流的数据包数量
            
        Returns:
            dict: 生成的流量数据
        """
        flows = {}
        
        for i in range(flow_count):
            flow_id = f"data_exfiltration_flow_{i}"
            src_ip = self._generate_ip(is_local=True)  # 内部主机
            dst_ip = self._generate_ip(is_local=False)  # 外部目标
            src_port = random.randint(50000, 60000)
            dst_port = random.choice([443, 80, 8080, 53])  # 常见出站端口
            
            packets = []
            start_time = time.time()
            
            # 设置为非工作时间
            current_hour = datetime.fromtimestamp(start_time).hour
            if 9 <= current_hour <= 17:  # 工作时间
                start_time = start_time + (24 - current_hour + 1) * 3600  # 调整到非工作时间
            
            # 数据泄露特点：大量出站数据，非常规时间，持续时间长
            for j in range(packets_per_flow):
                packet = {
                    "timestamp": start_time + j * random.uniform(0.1, 0.5),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": random.choice(["TCP", "UDP"]),
                    "size": random.randint(1000, 10000),  # 大包
                    "flags": {"ack": True}
                }
                packets.append(packet)
            
            flows[flow_id] = {
                "packets": packets, 
                "metadata": {
                    "type": "data_exfiltration",
                    "local_networks": self.local_networks,
                    "normal_hours": list(range(9, 18))  # 9am-6pm
                }
            }
        
        logger.info(f"生成了{flow_count}个数据泄露流量")
        return flows
    
    def generate_mixed_traffic(self, normal_ratio=0.6):
        """
        生成混合流量，包含正常流量和各种攻击流量
        
        Args:
            normal_ratio (float): 正常流量的比例
            
        Returns:
            tuple: (生成的流量数据, 真实标签)
        """
        # 确定各类型流量的数量
        total_flows = 100
        normal_flows = int(total_flows * normal_ratio)
        attack_flows_per_type = int((total_flows - normal_flows) / 5)  # 5种攻击类型
        
        # 生成各类型流量
        flows = {}
        flows.update(self.generate_normal_traffic(flow_count=normal_flows))
        flows.update(self.generate_port_scan_traffic(flow_count=attack_flows_per_type))
        flows.update(self.generate_ddos_traffic(flow_count=attack_flows_per_type))
        flows.update(self.generate_brute_force_traffic(flow_count=attack_flows_per_type))
        flows.update(self.generate_arp_spoofing_traffic(flow_count=attack_flows_per_type))
        flows.update(self.generate_data_exfiltration_traffic(flow_count=attack_flows_per_type))
        
        # 提取真实标签
        true_labels = {}
        for flow_id, flow_data in flows.items():
            if "metadata" in flow_data and "type" in flow_data["metadata"]:
                true_labels[flow_id] = flow_data["metadata"]["type"]
            else:
                true_labels[flow_id] = "unknown"
        
        logger.info(f"生成了混合流量: 总计{len(flows)}个流, 正常流{normal_flows}个, 每种攻击类型{attack_flows_per_type}个")
        return flows, true_labels


def evaluate_classifier(analyzer, flows, true_labels):
    """
    评估分类器性能
    
    Args:
        analyzer (TrafficAnalyzer): 流量分析器实例
        flows (dict): 流量数据
        true_labels (dict): 真实标签
        
    Returns:
        dict: 评估结果
    """
    # 分析流量
    results = analyzer.analyze_traffic(flows)
    
    # 提取预测标签
    predicted_labels = {}
    for flow_id, result in results.items():
        predicted_labels[flow_id] = result["classification"]["type"]
    
    # 计算混淆矩阵
    labels = set(true_labels.values()) | set(predicted_labels.values())
    confusion_matrix = {true: {pred: 0 for pred in labels} for true in labels}
    
    for flow_id in true_labels:
        true = true_labels[flow_id]
        pred = predicted_labels.get(flow_id, "unknown")
        confusion_matrix[true][pred] += 1
    
    # 计算评估指标
    correct = sum(1 for flow_id in true_labels if true_labels[flow_id] == predicted_labels.get(flow_id, "unknown"))
    total = len(true_labels)
    accuracy = correct / total if total > 0 else 0
    
    # 计算每种类型的精确率和召回率
    precision = {}
    recall = {}
    f1_score = {}
    
    for label in labels:
        # 精确率 = 正确预测为该类的样本数 / 预测为该类的样本总数
        pred_as_label = sum(confusion_matrix[true][label] for true in labels)
        precision[label] = confusion_matrix[label][label] / pred_as_label if pred_as_label > 0 else 0
        
        # 召回率 = 正确预测为该类的样本数 / 该类的样本总数
        true_label = sum(confusion_matrix[label][pred] for pred in labels)
        recall[label] = confusion_matrix[label][label] / true_label if true_label > 0 else 0
        
        # F1分数 = 2 * 精确率 * 召回率 / (精确率 + 召回率)
        if precision[label] + recall[label] > 0:
            f1_score[label] = 2 * precision[label] * recall[label] / (precision[label] + recall[label])
        else:
            f1_score[label] = 0
    
    # 计算宏平均F1分数
    macro_f1 = sum(f1_score.values()) / len(f1_score) if f1_score else 0
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "macro_f1": macro_f1,
        "confusion_matrix": confusion_matrix
    }


def main():
    """
    主函数
    """
    # 创建流量生成器
    generator = TrafficGenerator()
    
    # 生成混合流量
    logger.info("生成测试流量...")
    flows, true_labels = generator.generate_mixed_traffic(normal_ratio=0.6)
    
    # 创建流量分析器
    logger.info("初始化流量分析器...")
    analyzer = TrafficAnalyzer()
    
    # 评估分类器性能
    logger.info("评估分类器性能...")
    results = evaluate_classifier(analyzer, flows, true_labels)
    
    # 打印评估结果
    print("\n分类器评估结果:")
    print("-" * 80)
    print(f"准确率: {results['accuracy']:.4f}")
    print(f"宏平均F1分数: {results['macro_f1']:.4f}")
    print("-" * 80)
    
    print("\n各类型评估指标:")
    print("-" * 80)
    print(f"{'类型':<20} {'精确率':<10} {'召回率':<10} {'F1分数':<10}")
    print("-" * 80)
    
    for label in sorted(results["precision"]):
        precision = results["precision"][label]
        recall = results["recall"][label]
        f1 = results["f1_score"][label]
        print(f"{label:<20} {precision:.4f}    {recall:.4f}    {f1:.4f}")
    
    print("-" * 80)
    
    # 打印混淆矩阵
    print("\n混淆矩阵:")
    labels = sorted(results["confusion_matrix"].keys())
    
    # 打印表头
    header = "真实\预测".ljust(15)
    for label in labels:
        header += label.ljust(15)
    print(header)
    print("-" * (15 + 15 * len(labels)))
    
    # 打印每一行
    for true in labels:
        row = true.ljust(15)
        for pred in labels:
            row += str(results["confusion_matrix"][true][pred]).ljust(15)
        print(row)
    
    # 检查是否达到目标
    if results["accuracy"] >= 0.6:
        print("\n恭喜！流量分析模块达到了60%以上的分类准确率目标。")
    else:
        print("\n警告：流量分析模块未达到60%的分类准确率目标，需要进一步优化。")


if __name__ == "__main__":
    main()