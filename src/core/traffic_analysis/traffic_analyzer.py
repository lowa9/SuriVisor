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

# 创建 Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # 全局最低级别（DEBUG）

# --- 文件处理器（记录所有 DEBUG 及以上日志）---
file_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__),'../../../data/logs/surivisor.log'), mode='a')
file_handler.setLevel(logging.DEBUG)  # 文件记录 DEBUG+
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# # --- 控制台处理器（只显示 INFO 及以上日志）---
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.INFO)  # 控制台只显示 INFO+
# console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

# 添加处理器
logger.addHandler(file_handler)
# logger.addHandler(console_handler)


class TrafficAnalyzer:
    """
    流量分析器类
    
    该类提供了流量分析的核心功能，包括实时流量分析和离线分析。
    该类检测分析了一些关键的网络指标
    """
    
    def __init__(self):
        """
        初始化流量分析器

        """
        # # 初始化流量分析器的状态和配置
        # self.total_packets = 0      # 总数据包数
        # self.total_bytes = 0         # 总字节数
        # self.packet_rate = 0.0       # 数据包速率
        # self.byte_rate = 0.0         # 字节速率
        # self.protocol_distribution = {}  # 协议分布
        # self.port_distribution = {}      # 端口分布
        
        # # 网络性能指标
        # self.network_metrics = {
        #     "avg_rtt": 0.0,                  # 平均往返时间(ms)
        #     "bandwidth_utilization": 0.0,    # 带宽利用率(%)
        #     "connection_failure_rate": 0.0   # 连接失败率(%)
        # }
        
        # # TCP健康度指标
        # self.tcp_health_metrics = {
        #     "retransmission_ratio": 0.0,     # 重传比例(%)
        #     "out_of_order_ratio": 0.0       # 乱序比例(%)
        # }
        
        # # 告警信息
        # self.detected_alerts = []
        
        logger.info(f"初始化流量分析器") 
    
    def analyze_realtime_metrics(self, output_log_dir: str = None) -> Dict[str, Any]:
        """
        实时分析网络性能指标和TCP健康度指标
        
        从eve.json文件中提取网络性能指标和TCP健康度指标，用于实时监控
        
        Args:
            eve_json_path: eve.json文件路径
            
        Returns:
            Dict[str, Any]: 分析结果，包含网络性能指标和TCP健康度指标
        """
        eve_json_path = os.path.join(output_log_dir, "eve.json")
        if not os.path.exists(eve_json_path):
            logger.error(f"eve.json文件不存在: {eve_json_path}")
            return {"success": False, "error": f"eve.json文件不存在: {eve_json_path}"}
        
        try:
            # 用于计算网络性能指标的临时数据结构
            tcp_sessions = {}  # 存储TCP会话信息，用于计算RTT
            stream_stats = {   # 流事件统计信息
                "total_flows": 0,
                "retransmissions": 0,  # 重传事件数
                "out_of_order": 0      # 乱序事件数
            }
            flow_stats = {     # 流量统计信息
                "total_flows": 0,
                "failed_connections": 0,
                "total_packets": 0
            }
            
            # 导入ResultStructure，确保只在需要时导入
            from src.utils.result_utils import ResultStructure
            
            # 创建基础结果数据结构
            result = ResultStructure.create_base_result()
            result["success"] = True
            
            # 获取文件大小，用于限制读取量
            file_size = os.path.getsize(eve_json_path)
            max_read_size = 10 * 1024 * 1024  # 最多读取10MB数据
            
            # 从文件末尾开始读取最新的事件
            with open(eve_json_path, 'r') as f:
                # 如果文件过大，只读取最后部分
                if file_size > max_read_size:
                    f.seek(file_size - max_read_size)
                    # 跳过当前行，确保从完整的一行开始读取
                    f.readline()
                
                # 读取并处理事件
                for line in f:
                    if not line.strip():
                        continue
                        
                    try:
                        event = json.loads(line)
                        
                        # 处理统计事件，提取数据包信息
                        if event.get('event_type') == 'stats':
                            stats = event.get('stats', {})
                            stats_decoder = stats.get('decoder', {})
                            stats_flow = stats.get('flow', {})
                            stats_capture = stats.get('capture', {})

                            # 提取总数据包数
                            if 'pkts' in stats_decoder:
                                result["traffic_stats"] = result.get("traffic_stats", {}) or {}
                                result["traffic_stats"]["total_packets"] = stats_decoder['pkts']
                                flow_stats["total_packets"] = stats_decoder['pkts']
                            
                            # 提取总字节数
                            if 'bytes' in stats_decoder:
                                result["traffic_stats"] = result.get("traffic_stats", {}) or {}
                                result["traffic_stats"]["total_bytes"] = stats_decoder['bytes']

                            # 提取所有的流量数
                            if 'total' in stats_flow:
                                result["traffic_stats"] = result.get("traffic_stats", {}) or {}
                                result["traffic_stats"]["flow_count"] = stats_flow['total']
                                flow_stats["total_flows"] = stats_flow['total']
                                stream_stats["total_flows"] = stats_flow['total']

                            # 提取分析的tcp流量数
                            if 'tcp' in stats_flow:
                                result["traffic_stats"] = result.get("traffic_stats", {}) or {}
                                result["traffic_stats"]["tcp_flow_count"] = stats_flow['tcp']

                            # 提取分析的udp流量数
                            if 'udp' in stats_flow:
                                result["traffic_stats"] = result.get("traffic_stats", {}) or {}
                                result["traffic_stats"]["udp_flow_count"] = stats_flow['udp']                    

                            # 
                            if 'kernel_drop' in stats_capture:
                                result['traffic_stats'] = result.get('traffic_stats',{}) or {}
                                result['traffic_stats']['kernel_drop'] = stats_capture['kernel_drop']
                                
                        # 处理流事件，用于计算网络性能指标
                        elif event.get('event_type') == 'flow':
                            
                            # 提取流信息
                            flow = event.get('flow', {})
                            proto = flow.get('proto', '')
                            start_time = flow.get('start', '')
                            end_time = flow.get('end', '')
                            
                            # 检查是否为失败的连接（短连接或重置连接）
                            if flow.get('state', '') in ['failed', 'reset']:
                                flow_stats["failed_connections"] += 1
                            
                            # 计算TCP会话的RTT（如果有开始和结束时间）
                            if proto == 'TCP' and start_time and end_time:
                                try:
                                    # 解析时间字符串为datetime对象
                                    start_dt = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S.%f%z")
                                    end_dt = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S.%f%z")
                                    
                                    # 计算会话持续时间（毫秒）
                                    duration_ms = (end_dt - start_dt).total_seconds() * 1000
                                    
                                    # 存储会话信息，用于后续计算平均RTT
                                    session_id = f"{flow.get('src_ip')}:{flow.get('src_port')}-{flow.get('dest_ip')}:{flow.get('dest_port')}"
                                    tcp_sessions[session_id] = duration_ms
                                except (ValueError, TypeError) as e:
                                    logger.debug(f"无法解析流时间: {e}")
                        
                        # 处理stream事件，用于计算TCP健康度指标
                        elif event.get('event_type') == 'stream':
                            stream = event.get('stream', {})
                            event_type = stream.get('event', '')
                            
                            # 检查是否为乱序包事件
                            if event_type == 'out-of-order-packet':
                                stream_stats["out_of_order"] += 1
                            
                            # 检查是否为重传事件
                            elif event_type == 'retransmission':
                                stream_stats["retransmissions"] += 1
                            
                    except json.JSONDecodeError:
                        logger.warning(f"无法解析JSON行: {line}")
                        continue
            
            # 计算网络性能指标
            # 1. 平均往返时间 (RTT)
            if tcp_sessions:
                avg_rtt = sum(tcp_sessions.values()) / len(tcp_sessions)
                result["network_metrics"] = result.get("network_metrics", {}) or {}
                result["network_metrics"]["avg_rtt"] = round(avg_rtt, 2)
            
            # 2. 连接失败率
            if flow_stats["total_flows"] > 0:
                connection_failure_rate = (flow_stats["failed_connections"] / flow_stats["total_flows"]) * 100
                result["network_metrics"] = result.get("network_metrics", {}) or {}
                result["network_metrics"]["connection_failure_rate"] = round(connection_failure_rate, 2)
            
            # 3. 带宽利用率（这需要额外信息，这里使用一个估计值）
            # 假设带宽利用率与数据包数量和字节数有关
            if result.get("traffic_stats", {}).get("total_bytes", 0) > 0:
                # 这里使用一个简化的计算方法，实际应用中可能需要更复杂的算法
                bandwidth_utilization = min(100, (result["traffic_stats"]["total_bytes"] / (1024 * 1024)) * 5)  # 简化计算
                result["network_metrics"] = result.get("network_metrics", {}) or {}
                result["network_metrics"]["bandwidth_utilization"] = round(bandwidth_utilization, 2)
            
            # 计算TCP健康度指标（基于stream事件）
            if stream_stats["total_flows"] > 0:
                # 1. 重传比例（粗略计算）
                retransmission_ratio = (stream_stats["retransmissions"] / stream_stats["total_flows"]) * 100
                result["tcp_health"] = result.get("tcp_health", {}) or {}
                result["tcp_health"]["retransmission_ratio"] = round(retransmission_ratio, 2)
                
                # 2. 乱序比例（粗略计算）
                out_of_order_ratio = (stream_stats["out_of_order"] / stream_stats["total_flows"]) * 100
                result["tcp_health"] = result.get("tcp_health", {}) or {}
                result["tcp_health"]["out_of_order_ratio"] = round(out_of_order_ratio, 2)
            
            # 更新类的其他属性
            self.total_packets = result.get("traffic_stats", {}).get("total_packets", 0)
            self.total_bytes = result.get("traffic_stats", {}).get("total_bytes", 0)
            
            return result
            
        except Exception as e:
            logger.error(f"实时分析过程中发生错误: {e}")
            return {"success": False, "error": str(e)}
    
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
                # 用于计算网络性能指标的临时数据结构
                tcp_sessions = {}  # 存储TCP会话信息，用于计算RTT
                tcp_stats = {      # TCP统计信息
                    "total_packets": 0,
                    "retransmissions": 0,
                    "out_of_order": 0,
                    "duplicate_acks": 0,
                    "window_sizes": [],
                    "reassembly_times": []
                }
                flow_stats = {     # 流量统计信息
                    "total_flows": 0,
                    "failed_connections": 0,
                    "total_packets": 0
                }
                
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
                                    flow_stats["total_packets"] = stats_decoder['pkts']
                                
                                # 提取总字节数
                                if 'bytes' in stats_decoder:
                                    result["traffic_stats"]["total_bytes"] = stats_decoder['bytes']

                                # 提取所有的流量数
                                if 'total' in stats_flow:
                                    result["traffic_stats"]["flow_count"] = stats_flow['total']
                                    flow_stats["total_flows"] = stats_flow['total']

                                # 提取分析的tcp流量数
                                if 'tcp' in stats_flow:
                                    result["traffic_stats"]["tcp_flow_count"] = stats_flow['tcp']

                                # 提取分析的udp流量数
                                if 'udp' in stats_flow:
                                    result["traffic_stats"]["udp_flow_count"] = stats_flow['udp']                    
                                
                                logger.info(f"提取到数据包统计信息: 总数据包={result['traffic_stats']['total_packets']}")
                            
                            # 处理流事件，用于计算网络性能指标
                            elif event.get('event_type') == 'flow':
                                # flow_stats["total_flows"] += 1
                                
                                # 提取流信息
                                flow = event.get('flow', {})
                                proto = flow.get('proto', '')
                                start_time = flow.get('start', '')
                                end_time = flow.get('end', '')
                                
                                # 检查是否为失败的连接（短连接或重置连接）
                                if flow.get('state', '') in ['failed', 'reset']:
                                    flow_stats["failed_connections"] += 1
                                
                                # 计算TCP会话的RTT（如果有开始和结束时间）
                                if proto == 'TCP' and start_time and end_time:
                                    try:
                                        # 解析时间字符串为datetime对象
                                        start_dt = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%S.%f%z")
                                        end_dt = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%S.%f%z")
                                        
                                        # 计算会话持续时间（毫秒）
                                        duration_ms = (end_dt - start_dt).total_seconds() * 1000
                                        
                                        # 存储会话信息，用于后续计算平均RTT
                                        session_id = f"{flow.get('src_ip')}:{flow.get('src_port')}-{flow.get('dest_ip')}:{flow.get('dest_port')}"
                                        tcp_sessions[session_id] = duration_ms
                                    except (ValueError, TypeError) as e:
                                        logger.debug(f"无法解析流时间: {e}")

                        except json.JSONDecodeError:
                            logger.warning(f"无法解析JSON行: {line}")
                            continue
                
                # 计算网络性能指标
                # 1. 平均往返时间 (RTT)
                if tcp_sessions:
                    avg_rtt = sum(tcp_sessions.values()) / len(tcp_sessions)
                    result["network_metrics"] = result.get("network_metrics", {}) or {}
                    result["network_metrics"]["avg_rtt"] = round(avg_rtt, 2)
                
                # 2. 连接失败率
                if flow_stats["total_flows"] > 0:
                    connection_failure_rate = (flow_stats["failed_connections"] / flow_stats["total_flows"]) * 100
                    result["network_metrics"] = result.get("network_metrics", {}) or {}
                    result["network_metrics"]["connection_failure_rate"] = round(connection_failure_rate, 2)
                
                # 4. 带宽利用率（这需要额外信息，这里使用一个估计值）
                # 假设带宽利用率与数据包数量和字节数有关
                if result["traffic_stats"]["total_bytes"] > 0:
                    # 这里使用一个简化的计算方法，实际应用中可能需要更复杂的算法
                    bandwidth_utilization = min(100, (result["traffic_stats"]["total_bytes"] / (1024 * 1024)) * 5)  # 简化计算
                    result["network_metrics"] = result.get("network_metrics", {}) or {}
                    result["network_metrics"]["bandwidth_utilization"] = round(bandwidth_utilization, 2)
                
                # 计算TCP健康度指标
                if tcp_stats["total_packets"] > 0:
                    # 1. 重传比例
                    retransmission_ratio = (tcp_stats["retransmissions"] / tcp_stats["total_packets"]) * 100
                    result["tcp_health"] = result.get("tcp_health", {}) or {}
                    result["tcp_health"]["retransmission_ratio"] = round(retransmission_ratio, 2)
                    
                    # 2. 乱序比例
                    out_of_order_ratio = (tcp_stats["out_of_order"] / tcp_stats["total_packets"]) * 100
                    result["tcp_health"]["out_of_order_ratio"] = round(out_of_order_ratio, 2)
                    
                    # 3. 重复ACK比例
                    duplicate_ack_ratio = (tcp_stats["duplicate_acks"] / tcp_stats["total_packets"]) * 100
                    result["tcp_health"]["duplicate_ack_ratio"] = round(duplicate_ack_ratio, 2)
                
                # 5. 平均窗口大小
                if tcp_stats["window_sizes"]:
                    avg_window_size = sum(tcp_stats["window_sizes"]) / len(tcp_stats["window_sizes"])
                    result["tcp_health"]["avg_window_size"] = int(avg_window_size)
                
                # 6. 平均重组时间
                if tcp_stats["reassembly_times"]:
                    avg_reassembly_time = sum(tcp_stats["reassembly_times"]) / len(tcp_stats["reassembly_times"])
                    result["tcp_health"]["avg_reassembly_time"] = round(avg_reassembly_time, 2)
                
                # 更新类的其他属性
                self.total_packets = result["traffic_stats"].get("total_packets", 0)
                self.total_bytes = result["traffic_stats"].get("total_bytes", 0)
                # 存储检测到的告警
                self.detected_alerts = result.get("alerts", [])
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
