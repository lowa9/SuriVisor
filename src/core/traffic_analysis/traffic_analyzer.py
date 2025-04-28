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
import subprocess
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from src.core.suricata_monitor.process_manager import SuricataProcessManager
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
            dict: 统计信息，符合统一的结果数据结构
        """
        # 导入ResultStructure，确保只在需要时导入
        from src.utils.result_utils import ResultStructure
        
        # 创建基础结果数据结构
        result = ResultStructure.create_base_result()
        result["success"] = True
        
        # 计算各类型流量的数量
        type_counts = defaultdict(int)
        for flow_result in self.classified_flows.values():
            flow_type = flow_result.get("type", "unknown")
            type_counts[flow_type] += 1
        
        # 计算总体统计信息
        total_flows = len(self.classified_flows)
        attack_flows = sum(count for flow_type, count in type_counts.items() if flow_type != "normal")
        
        # 填充流量统计信息
        result["traffic_stats"] = {
            "total_packets": getattr(self, 'total_packets', 0),
            "total_bytes": getattr(self, 'total_bytes', 0),
            "packet_rate": getattr(self, 'packet_rate', 0.0),
            "byte_rate": getattr(self, 'byte_rate', 0.0),
            "flow_count": total_flows,
            "protocol_distribution": getattr(self, 'protocol_distribution', {}),
            "port_distribution": getattr(self, 'port_distribution', {}),
            "attack_flows": attack_flows,
            "normal_flows": type_counts.get("normal", 0),
            "attack_types": {k: v for k, v in type_counts.items() if k != "normal"},
            "attack_ratio": attack_flows / total_flows if total_flows > 0 else 0
        }
        
        # 填充网络性能指标（如果有）
        if hasattr(self, 'network_metrics') and self.network_metrics:
            result["network_metrics"] = self.network_metrics
        
        # 填充TCP健康度指标（如果有）
        if hasattr(self, 'tcp_health_metrics') and self.tcp_health_metrics:
            result["tcp_health"] = self.tcp_health_metrics
        
        # 填充告警信息（如果有）
        if hasattr(self, 'detected_alerts') and self.detected_alerts:
            result["alerts"] = self.detected_alerts
            result["alert_count"] = len(self.detected_alerts)
        
        # 添加结果摘要
        result["summary"] = f"流量分析完成，共分析{total_flows}个流，其中攻击流{attack_flows}个，正常流{type_counts.get('normal', 0)}个"
        
        return result
    
    def analyze_pcap(self, pcap_file: str, suricata_manager: SuricataProcessManager, log_dir: str = None, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        离线分析PCAP文件（非实时模式）
        
        Args:
            pcap_file: PCAP文件路径
            suricata_manager: Suricata进程管理器实例
            log_dir: 日志输出目录，如果为None则使用默认日志目录
            callback: 回调函数，接收告警事件作为参数
            
        Returns:
            Dict[str, Any]: 分析结果，包含成功状态和分析摘要
        """
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP文件不存在: {pcap_file}")
            return {"success": False, "error": f"PCAP文件不存在: {pcap_file}"}
        
        # 使用当前配置的日志目录或指定的日志目录
        output_log_dir = log_dir if log_dir else suricata_manager.log_dir
        os.makedirs(output_log_dir, exist_ok=True)
        
        try:
            # 构建Suricata离线分析命令
            cmd = [
                suricata_manager.binary_path,
                '-c', suricata_manager.config_path,
                '-r', pcap_file,
                '--set', f'default-rule-path={suricata_manager.rule_dir}',
                '-l', output_log_dir
            ]
            
            logger.info(f"开始离线分析PCAP文件: {pcap_file}")
            logger.debug(f"执行命令: {' '.join(cmd)}")
            
            # 启动独立的Suricata进程进行分析
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # 分析结果处理
            eve_json = os.path.join(output_log_dir, "eve.json")
            # result = {"success": True, "alerts": [], "alert_count": 0}
            from src.utils.result_utils import ResultStructure
            result = ResultStructure.create_base_result()

            # 检查eve.json文件是否存在，如果存在则记录当前行数
            initial_line_count = 0
            if os.path.exists(eve_json):
                with open(eve_json, 'r') as f:
                    initial_line_count = sum(1 for _ in f)
                logger.info(f"分析前eve.json已有{initial_line_count}行")
            
            logger.info(f"等待Suricata完成PCAP分析...")
            
            # 等待分析完成
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Suricata分析失败: {stderr}")
                return {"success": False, "error": stderr}
            
            # 等待eve.json文件创建
            max_wait = 30  # 最大等待时间（秒）
            wait_time = 0
            while not os.path.exists(eve_json) and wait_time < max_wait:
                time.sleep(1)
                wait_time += 1
            
            if not os.path.exists(eve_json):
                logger.warning(f"等待{max_wait}秒后eve.json文件仍未创建")
                return {"success": False, "error": "未能创建分析结果文件"}
            
            # 分析完成后处理结果
            try:
                # 读取eve.json文件，只处理新增的行
                with open(eve_json, 'r') as f:
                    # 跳过已有的行
                    for _ in range(initial_line_count):
                        next(f, None)
                    
                    # 处理新增的行
                    for line in f:
                        if not line.strip():
                            continue
                            
                        try:
                            event = json.loads(line)
                            
                            # 处理告警事件
                            if event.get('event_type') == 'alert':
                                # 导入告警工具模块
                                from src.utils.alert_utils import AlertStructure
                                
                                # 将Suricata告警转换为标准格式
                                alert_data = AlertStructure.from_suricata_alert(event)
                                
                                # 添加到告警列表
                                result["alerts"].append(alert_data)
                                result["alert_count"] += 1
                                
                                # 如果提供了回调函数，调用它
                                if callback and callable(callback):
                                    callback(alert_data)
                                    
                                logger.info(f"检测到告警: {alert_data['signature']}")
                            
                            # 处理统计事件，提取数据包信息
                            elif event.get('event_type') == 'stats':
                                stats = event.get('stats', {})
                                stats_decoder = stats.get('decoder', {})
                                stats_flow = stats.get('flow', {})
                                
                                # 提取总数据包数
                                if 'pkts' in stats_decoder:
                                    result["traffic_stats"]["total_packets"] = stats_decoder['pkts']
                                
                                # 提取总字节数
                                if 'bytes' in stats_decoder:
                                    result["traffic_stats"]["total_bytes"] = stats_decoder['bytes']

                                # 提取所有的流量数
                                if 'total' in stats_flow:
                                    result["traffic_stats"]["flow_count"] = stats_flow['total']

                                # 提取分析的tcp流量数
                                if 'tcp' in stats_flow:
                                    result["traffic_stats"]["tcp_flow_count"] = stats_flow['tcp']

                                # 提取分析的udp流量数
                                if 'udp' in stats_flow:
                                    result["traffic_stats"]["udp_flow_count"] = stats_flow['udp']                    
                                
                                logger.info(f"提取到数据包统计信息: 总数据包={result['traffic_stats']['total_packets']}")
                        except json.JSONDecodeError:
                            logger.warning(f"无法解析JSON行: {line}")
                            continue
            except Exception as e:
                logger.error(f"处理分析结果时发生错误: {e}")
                return {"success": False, "error": str(e)}
            
            # 如果从eve.json中没有获取到数据包统计信息，尝试从suricata.log中获取
            if result["traffic_stats"]["total_packets"] == 0:
                suricata_log = os.path.join(output_log_dir, "suricata.log")
                if os.path.exists(suricata_log):
                    try:
                        with open(suricata_log, 'r') as f:
                            for line in f:
                                # 查找包含数据包统计信息的行
                                if "pcap: read" in line and "packets" in line:
                                    # 例如: [536457 - RX#01] 2025-04-21 23:07:45 Notice: pcap: read 1 file, 1577 packets, 223252 bytes
                                    parts = line.split()
                                    for i, part in enumerate(parts):
                                        if part == "packets,":
                                            result["traffic_stats"]["total_packets"] = int(parts[i-1])
                                            logger.info(f"从suricata.log中提取到总数据包数: {result['traffic_stats']['total_packets']}")
                                            break
                    except Exception as e:
                        logger.warning(f"从suricata.log提取数据包统计信息时出错: {e}")
            
            logger.info("PCAP文件分析完成")
            result["log_file"] = eve_json
            
            # 确保数据包统计信息存在于结果中
            if "total_packets" not in result['traffic_stats'] or result["traffic_stats"]["total_packets"] == 0:
                # 如果无法从日志中获取，尝试从pcap文件名中提取（如果文件名中包含数据包数量信息）
                logger.warning("无法从日志中获取数据包统计信息，使用默认值")
            result["success"] = True

            return result
            
        except Exception as e:
            logger.error(f"离线分析过程中发生错误: {e}")
            return {"success": False, "error": str(e)}
    
    def generate_report(self, suricata_result, eve_json_path, output_file=None):
        """
        生成统一格式的分析报告
        
        Args:
            suricata_result (dict): 从Suricata获取的统计信息和事件数据摘要。
                                    预期包含 'stats' 和 'flow' 事件中的相关字段。
            eve_json_path (str): EVE JSON 日志文件的路径。
            output_file (str): 输出文件路径，如果为None则返回报告字典。
            
        Returns:
            dict or bool: 如果output_file为None，返回包含分析结果的字典；否则返回是否成功写入文件。
        """
        # 初始化结果字典
        result = {
            # 基础状态
            "success": True,  
            "alerts": [],      # 告警列表
            "alert_count": 0,  # 告警数量

            # 流量统计
            "total_packets": suricata_result.get("total_packets", 0),
            "total_bytes": suricata_result.get("total_bytes", 0),
            "tcp_flows": suricata_result.get("tcp_flows", 0),
            "udp_flows": suricata_result.get("udp_flows", 0),
            "analyzed_flows": suricata_result.get("analyzed_flows", len(self.classified_flows)), # 使用分类器分析的流数量
            "reassembled_packets": suricata_result.get("reassembled_packets", 0),

            # 网络性能指标
            "lost_packets": suricata_result.get("lost_packets", 0),
            "lost_packets_ratio": round(
                (suricata_result.get("kernel_drops", 0) + suricata_result.get("decoder_drops", 0))
                / max(1, suricata_result.get("received_packets", 1)),
                4
            ),
            "kernel_drops": suricata_result.get("kernel_drops", 0),
            "decoder_drops": suricata_result.get("decoder_drops", 0),

            # TCP流健康度指标
            "tcp_out_of_order_ratio": round(
                suricata_result.get("tcp_out_of_order", 0)
                / max(1, suricata_result.get("tcp_packets", 1)),
                4
            ),
            "tcp_retransmission_ratio": round(
                suricata_result.get("tcp_retransmissions", 0)
                / max(1, suricata_result.get("tcp_packets", 1)),
                4
            ),
            "tcp_reassembly_failures": suricata_result.get("tcp_reassembly_failures", 0),

            # 其他补充指标
            "active_flows": suricata_result.get("active_flows", 0),
            "flow_timeouts": suricata_result.get("flow_timeouts", 0),

            # 日志路径
            "log_file": eve_json_path
        }

        try:
            # 填充告警信息 (从已分类的流量中提取)
            detected_attacks = []
            for flow_id, classification_result in self.classified_flows.items():
                if classification_result.get("type", "normal") != "normal":
                    attack_info = {
                        "flow_id": flow_id,
                        "attack_type": classification_result.get("type", "unknown"),
                        "confidence": classification_result.get("confidence", 0),
                        "description": classification_result.get("details", {}).get("description", ""),
                        # 可以根据需要添加更多告警细节，例如匹配的特征
                        "matched_features": classification_result.get("details", {}).get("matched_features", {})
                    }
                    detected_attacks.append(attack_info)
            
            result["alerts"] = detected_attacks
            result["alert_count"] = len(detected_attacks)

            # 如果指定了输出文件，写入文件
            if output_file:
                try:
                    with open(output_file, 'w') as f:
                        json.dump(result, f, indent=4)
                    logger.info(f"统一格式的分析报告已保存到{output_file}")
                    return True
                except Exception as e:
                    logger.error(f"保存统一格式的分析报告失败: {e}")
                    result["success"] = False
                    result["error_message"] = f"Failed to save report: {e}"
                    return False # 保存失败
            
            # 否则返回报告字典
            return result

        except Exception as e:
            logger.error(f"生成统一格式的分析报告时出错: {e}")
            result["success"] = False
            result["error_message"] = f"Error generating report: {e}"
            # 即使出错，也尝试返回部分结果
            if output_file:
                # 尝试保存包含错误信息的文件
                try:
                    with open(output_file, 'w') as f:
                        json.dump(result, f, indent=4)
                    logger.warning(f"已保存包含错误的分析报告到 {output_file}")
                except Exception as write_err:
                    logger.error(f"保存错误报告也失败了: {write_err}")
                return False # 生成或保存失败
            return result # 返回包含错误信息的字典

