#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
流量分析模块

该模块实现了自动化的流量模式识别与分类功能，用于识别网络流量中的潜在威胁。
目标是达到60%的分类准确率。
"""

import os
import sys
import logging
import numpy as np
import pandas as pd
from collections import defaultdict
import time
import json
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """
    流量分析器类
    
    实现了自动化的流量模式识别与分类功能，用于分析网络流量并识别潜在威胁。
    """
    
    def __init__(self, attack_patterns_file=None):
        """
        初始化流量分析器
        
        Args:
            attack_patterns_file (str): 攻击模式库文件路径
        """
        self.attack_patterns = {}
        self.flow_features = defaultdict(dict)
        self.classified_flows = {}
        
        # 加载攻击模式库
        if attack_patterns_file and os.path.exists(attack_patterns_file):
            self.load_attack_patterns(attack_patterns_file)
        else:
            # 使用默认的攻击模式
            self._initialize_default_patterns()
        
        logger.info(f"初始化流量分析器: 已加载{len(self.attack_patterns)}种攻击模式")
    
    def _initialize_default_patterns(self):
        """
        初始化默认的攻击模式
        """
        self.attack_patterns = {
            "port_scan": {
                "description": "端口扫描攻击",
                "features": {
                    "unique_ports": {"min": 10, "weight": 0.4},
                    "packets_per_second": {"min": 5, "weight": 0.3},
                    "avg_packet_size": {"max": 100, "weight": 0.2},
                    "syn_ratio": {"min": 0.8, "weight": 0.1}
                }
            },
            "ddos": {
                "description": "DDoS攻击",
                "features": {
                    "packets_per_second": {"min": 100, "weight": 0.4},
                    "unique_sources": {"min": 5, "weight": 0.3},
                    "syn_ratio": {"min": 0.7, "weight": 0.2},
                    "avg_packet_size": {"max": 200, "weight": 0.1}
                }
            },
            "brute_force": {
                "description": "暴力破解攻击",
                "features": {
                    "failed_login_ratio": {"min": 0.6, "weight": 0.4},
                    "login_attempts_per_minute": {"min": 10, "weight": 0.3},
                    "unique_usernames": {"min": 3, "weight": 0.2},
                    "avg_request_interval": {"max": 5, "weight": 0.1}
                }
            },
            "arp_spoofing": {
                "description": "ARP欺骗攻击",
                "features": {
                    "arp_requests_per_second": {"min": 5, "weight": 0.4},
                    "ip_mac_pairs": {"min": 2, "weight": 0.3},
                    "gratuitous_arp_ratio": {"min": 0.5, "weight": 0.2},
                    "arp_reply_without_request": {"min": 3, "weight": 0.1}
                }
            },
            "data_exfiltration": {
                "description": "数据泄露",
                "features": {
                    "outbound_data_volume": {"min": 1000000, "weight": 0.4},  # 1MB
                    "unusual_destination": {"min": 0.7, "weight": 0.3},
                    "unusual_protocol": {"min": 0.7, "weight": 0.2},
                    "unusual_time": {"min": 0.7, "weight": 0.1}
                }
            }
        }
    
    def load_attack_patterns(self, file_path):
        """
        从文件加载攻击模式库
        
        Args:
            file_path (str): 攻击模式库文件路径
            
        Returns:
            bool: 加载是否成功
        """
        try:
            with open(file_path, 'r') as f:
                self.attack_patterns = json.load(f)
            logger.info(f"从{file_path}加载了{len(self.attack_patterns)}种攻击模式")
            return True
        except Exception as e:
            logger.error(f"加载攻击模式库失败: {e}")
            self._initialize_default_patterns()
            return False
    
    def save_attack_patterns(self, file_path):
        """
        保存攻击模式库到文件
        
        Args:
            file_path (str): 攻击模式库文件路径
            
        Returns:
            bool: 保存是否成功
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(self.attack_patterns, f, indent=4)
            logger.info(f"攻击模式库已保存到{file_path}")
            return True
        except Exception as e:
            logger.error(f"保存攻击模式库失败: {e}")
            return False
    
    def extract_features(self, flow_id, packets, metadata=None):
        """
        从数据包中提取特征
        
        Args:
            flow_id (str): 流标识符
            packets (list): 数据包列表
            metadata (dict): 元数据信息
            
        Returns:
            dict: 提取的特征
        """
        if not packets:
            return {}
        
        # 初始化特征字典
        features = {
            "timestamp": time.time(),
            "packet_count": len(packets),
            "unique_ports": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "avg_packet_size": 0,
            "packets_per_second": 0,
            "syn_ratio": 0,
            "failed_login_ratio": 0,
            "login_attempts_per_minute": 0,
            "unique_usernames": 0,
            "avg_request_interval": 0,
            "arp_requests_per_second": 0,
            "ip_mac_pairs": 0,
            "gratuitous_arp_ratio": 0,
            "arp_reply_without_request": 0,
            "outbound_data_volume": 0,
            "unusual_destination": 0,
            "unusual_protocol": 0,
            "unusual_time": 0
        }
        
        # 提取基本特征
        ports = set()
        sources = set()
        destinations = set()
        total_size = 0
        syn_count = 0
        arp_request_count = 0
        arp_reply_count = 0
        arp_reply_without_request_count = 0
        gratuitous_arp_count = 0
        ip_mac_map = {}
        outbound_data = 0
        
        # 计算时间相关特征
        start_time = packets[0].get('timestamp', time.time())
        end_time = packets[-1].get('timestamp', time.time())
        duration = max(end_time - start_time, 0.001)  # 避免除零错误
        
        # 分析每个数据包
        for packet in packets:
            # 提取基本信息
            src_ip = packet.get('src_ip', '')
            dst_ip = packet.get('dst_ip', '')
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            protocol = packet.get('protocol', '')
            size = packet.get('size', 0)
            flags = packet.get('flags', {})
            
            # 更新集合
            if src_port > 0:
                ports.add(src_port)
            if dst_port > 0:
                ports.add(dst_port)
            if src_ip:
                sources.add(src_ip)
            if dst_ip:
                destinations.add(dst_ip)
            
            # 累计大小
            total_size += size
            
            # 检查SYN标志
            if flags.get('syn', False) and not flags.get('ack', False):
                syn_count += 1
            
            # 检查ARP包
            if protocol.lower() == 'arp':
                if packet.get('arp_operation', 0) == 1:  # ARP请求
                    arp_request_count += 1
                elif packet.get('arp_operation', 0) == 2:  # ARP响应
                    arp_reply_count += 1
                    
                    # 检查是否有对应的请求
                    if packet.get('arp_reply_without_request', False):
                        arp_reply_without_request_count += 1
                    
                    # 检查是否是无故ARP（Gratuitous ARP）
                    if packet.get('gratuitous_arp', False):
                        gratuitous_arp_count += 1
                
                # 记录IP-MAC对应关系
                sender_ip = packet.get('arp_sender_ip', '')
                sender_mac = packet.get('arp_sender_mac', '')
                if sender_ip and sender_mac:
                    if sender_ip in ip_mac_map and ip_mac_map[sender_ip] != sender_mac:
                        # 发现IP-MAC映射变化
                        features["ip_mac_pairs"] += 1
                    ip_mac_map[sender_ip] = sender_mac
            
            # 计算出站数据量
            if metadata and 'local_networks' in metadata:
                local_networks = metadata['local_networks']
                is_outbound = any(src_ip.startswith(net) for net in local_networks) and \
                              not any(dst_ip.startswith(net) for net in local_networks)
                if is_outbound:
                    outbound_data += size
        
        # 计算特征值
        features["unique_ports"] = len(ports)
        features["unique_sources"] = len(sources)
        features["unique_destinations"] = len(destinations)
        features["avg_packet_size"] = total_size / len(packets) if packets else 0
        features["packets_per_second"] = len(packets) / duration
        features["syn_ratio"] = syn_count / len(packets) if packets else 0
        features["arp_requests_per_second"] = arp_request_count / duration
        features["gratuitous_arp_ratio"] = gratuitous_arp_count / arp_reply_count if arp_reply_count else 0
        features["arp_reply_without_request"] = arp_reply_without_request_count
        features["outbound_data_volume"] = outbound_data
        
        # 如果有元数据，可以计算更多特征
        if metadata:
            # 计算登录相关特征（如果有）
            if 'login_attempts' in metadata:
                login_attempts = metadata['login_attempts']
                failed_logins = sum(1 for attempt in login_attempts if not attempt.get('success', False))
                features["failed_login_ratio"] = failed_logins / len(login_attempts) if login_attempts else 0
                features["login_attempts_per_minute"] = len(login_attempts) / (duration / 60)
                features["unique_usernames"] = len(set(attempt.get('username', '') for attempt in login_attempts))
            
            # 计算时间间隔
            if len(packets) > 1:
                intervals = [packets[i+1].get('timestamp', 0) - packets[i].get('timestamp', 0) 
                             for i in range(len(packets)-1)]
                features["avg_request_interval"] = sum(intervals) / len(intervals)
            
            # 计算异常特征
            if 'normal_destinations' in metadata:
                normal_dests = set(metadata['normal_destinations'])
                unusual_dests = len(destinations - normal_dests)
                features["unusual_destination"] = unusual_dests / len(destinations) if destinations else 0
            
            if 'normal_protocols' in metadata:
                normal_protocols = set(metadata['normal_protocols'])
                protocols_used = set(p.get('protocol', '') for p in packets)
                unusual_protocols = len(protocols_used - normal_protocols)
                features["unusual_protocol"] = unusual_protocols / len(protocols_used) if protocols_used else 0
            
            if 'normal_hours' in metadata:
                normal_hours = set(metadata['normal_hours'])
                current_hour = datetime.fromtimestamp(start_time).hour
                features["unusual_time"] = 0 if current_hour in normal_hours else 1
        
        # 保存特征
        self.flow_features[flow_id] = features
        
        return features
    
    def classify_flow(self, flow_id, features=None):
        """
        对流量进行分类
        
        Args:
            flow_id (str): 流标识符
            features (dict): 流量特征，如果为None则使用之前提取的特征
            
        Returns:
            dict: 分类结果，包含攻击类型和置信度
        """
        if features is None:
            if flow_id not in self.flow_features:
                logger.warning(f"流 {flow_id} 的特征不存在")
                return {"type": "normal", "confidence": 1.0, "details": {}}
            features = self.flow_features[flow_id]
        
        # 初始化结果
        result = {
            "type": "normal",
            "confidence": 0.0,
            "details": {}
        }
        
        # 对每种攻击模式计算匹配度
        max_score = 0.0
        for attack_type, pattern in self.attack_patterns.items():
            score = 0.0
            matched_features = {}
            
            # 计算每个特征的匹配度
            for feature_name, criteria in pattern["features"].items():
                if feature_name not in features:
                    continue
                
                feature_value = features[feature_name]
                weight = criteria.get("weight", 1.0)
                
                # 根据条件类型计算匹配度
                if "min" in criteria and feature_value >= criteria["min"]:
                    matched_features[feature_name] = {
                        "value": feature_value,
                        "threshold": criteria["min"],
                        "match": True
                    }
                    score += weight
                elif "max" in criteria and feature_value <= criteria["max"]:
                    matched_features[feature_name] = {
                        "value": feature_value,
                        "threshold": criteria["max"],
                        "match": True
                    }
                    score += weight
                else:
                    matched_features[feature_name] = {
                        "value": feature_value,
                        "threshold": criteria.get("min", criteria.get("max", 0)),
                        "match": False
                    }
            
            # 归一化得分
            total_weight = sum(criteria.get("weight", 1.0) for criteria in pattern["features"].values())
            normalized_score = score / total_weight if total_weight > 0 else 0
            
            # 更新结果
            if normalized_score > max_score:
                max_score = normalized_score
                result["type"] = attack_type
                result["confidence"] = normalized_score
                result["details"] = {
                    "description": pattern.get("description", ""),
                    "matched_features": matched_features
                }
        
        # 如果得分低于阈值，认为是正常流量
        if max_score < 0.6:  # 可配置的阈值
            result["type"] = "normal"
            result["confidence"] = 1.0 - max_score
        
        # 保存分类结果
        self.classified_flows[flow_id] = result
        
        return result
    
    def analyze_traffic(self, flows):
        """
        分析多个流量
        
        Args:
            flows (dict): 流量数据，格式为 {flow_id: {"packets": [...], "metadata": {...}}}
            
        Returns:
            dict: 分析结果，格式为 {flow_id: {"classification": {...}, "features": {...}}}
        """
        results = {}
        
        for flow_id, flow_data in flows.items():
            # 提取特征
            features = self.extract_features(
                flow_id, 
                flow_data.get("packets", []), 
                flow_data.get("metadata", None)
            )
            
            # 分类
            classification = self.classify_flow(flow_id, features)
            
            # 保存结果
            results[flow_id] = {
                "classification": classification,
                "features": features
            }
        
        return results
    
    def get_statistics(self):
        """
        获取分析统计信息
        
        Returns:
            dict: 统计信息
        """
        # 计算各类型流量的数量
        type_counts = defaultdict(int)
        for result in self.classified_flows.values():
            flow_type = result.get("type", "unknown")
            type_counts[flow_type] += 1
        
        # 计算总体统计信息
        total_flows = len(self.classified_flows)
        attack_flows = sum(count for flow_type, count in type_counts.items() if flow_type != "normal")
        
        return {
            "total_flows": total_flows,
            "attack_flows": attack_flows,
            "normal_flows": type_counts.get("normal", 0),
            "attack_types": {k: v for k, v in type_counts.items() if k != "normal"},
            "attack_ratio": attack_flows / total_flows if total_flows > 0 else 0
        }
    
    def generate_report(self, output_file=None):
        """
        生成分析报告
        
        Args:
            output_file (str): 输出文件路径，如果为None则返回报告内容
            
        Returns:
            str or bool: 如果output_file为None，返回报告内容；否则返回是否成功写入文件
        """
        # 获取统计信息
        stats = self.get_statistics()
        
        # 生成报告内容
        report = {
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "statistics": stats,
            "detected_attacks": []
        }
        
        # 添加检测到的攻击
        for flow_id, result in self.classified_flows.items():
            if result.get("type", "normal") != "normal":
                attack_info = {
                    "flow_id": flow_id,
                    "attack_type": result.get("type", "unknown"),
                    "confidence": result.get("confidence", 0),
                    "details": result.get("details", {})
                }
                report["detected_attacks"].append(attack_info)
        
        # 如果指定了输出文件，写入文件
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=4)
                logger.info(f"分析报告已保存到{output_file}")
                return True
            except Exception as e:
                logger.error(f"保存分析报告失败: {e}")
                return False
        
        # 否则返回报告内容
        return json.dumps(report, indent=4)

    def analyze_flow(self, flow_data):
        """兼容性方法，处理单条流数据"""
        if not isinstance(flow_data, dict) or 'packets' not in flow_data:
            logger.error("Invalid flow data format")
            return {
                "type": "unknown",
                "confidence": 0,
                "details": {"error": "Invalid data format"}
            }
        
        # 生成临时flow_id
        first_packet = flow_data.get('packets', [{}])[0]
        flow_id = f"temp_{first_packet.get('src_ip','unknown')}_{first_packet.get('dst_ip','unknown')}_{time.time()}"
        
        # 分析单条流
        result = self.analyze_traffic({flow_id: flow_data})
        return result[flow_id]['classification']

# 测试代码
if __name__ == "__main__":
    # 创建流量分析器实例
    analyzer = TrafficAnalyzer()
    
    # 模拟端口扫描流量
    port_scan_packets = []
    for i in range(100):
        packet = {
            "timestamp": time.time() + i * 0.1,
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "src_port": 12345,
            "dst_port": 1000 + i,  # 不同的目标端口
            "protocol": "TCP",
            "size": 60,
            "flags": {"syn": True, "ack": False}
        }
        port_scan_packets.append(packet)
    
    # 模拟正常流量
    normal_packets = []
    for i in range(100):
        packet = {
            "timestamp": time.time() + i * 1.0,
            "src_ip": "192.168.1.101",
            "dst_ip": "192.168.1.2",
            "src_port": 54321,
            "dst_port": 80,  # 固定的目标端口
            "protocol": "TCP",
            "size": 1024,
            "flags": {"syn": i < 1, "ack": i >= 1}
        }
        normal_packets.append(packet)
    
    # 分析流量
    flows = {
        "port_scan_flow": {"packets": port_scan_packets},
        "normal_flow": {"packets": normal_packets}
    }
    
    results = analyzer.analyze_traffic(flows)
    
    # 打印结果
    for flow_id, result in results.items():
        print(f"\n流 {flow_id} 的分类结果:")
        classification = result["classification"]
        print(f"类型: {classification['type']}")
        print(f"置信度: {classification['confidence']:.2f}")
        
        if "details" in classification and "description" in classification["details"]:
            print(f"描述: {classification['details']['description']}")
    
    # 打印统计信息
    stats = analyzer.get_statistics()
    print("\n统计信息:")
    print(f"总流量数: {stats['total_flows']}")
    print(f"攻击流量数: {stats['attack_flows']}")
    print(f"正常流量数: {stats['normal_flows']}")
    print(f"攻击类型分布: {stats['attack_types']}")
    print(f"攻击比例: {stats['attack_ratio']:.2%}")
    
    # 生成报告
    report = analyzer.generate_report()
    print("\n分析报告:")
    print(report)