#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
结果数据结构工具模块

提供统一的结果数据结构定义和处理函数，包括：
- 分析结果(result)数据结构定义
- 报告结果(report_result)数据结构定义
- 数据结构转换和处理函数
"""

import os
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

# 配置日志
logger = logging.getLogger(__name__)


class ResultStructure:
    """
    结果数据结构类
    
    提供统一的结果数据结构定义和处理函数
    """
    
    @staticmethod
    def create_base_result() -> Dict[str, Any]:
        """
        创建基础结果数据结构
        
        Returns:
            Dict[str, Any]: 基础结果数据结构
        """
        return {
            # 基础状态
            "success": "False",                # 分析是否成功
            "timestamp": time.time(),       # 时间戳
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # 格式化时间
            
            # 告警信息
            "alerts": [],                   # 告警列表
            "alert_count": 0,               # 告警数量
            
            # 流量统计
            "traffic_stats": {
                "total_packets": 0,       # 网口捕获数据包数
                "kernel_drop": 0,           # 内核丢弃数量
                "decoder_packets": 0,       # 解码器解码包数
                "total_bytes": 0,           # 总字节数
                "flow_count": 0,            # 流数量
                "tcp_flow_count": 0,         # TCP流数量
                "udp_flow_count": 0,         # UDP流数量      
                "protocol_distribution": {}, # 协议分布
            },
            
            # 网络性能指标
            "network_metrics": {
                "avg_rtt": 0.0,                 # 平均往返时间(ms)
                "connection_failure_rate": 0.0, # 连接失败率
                "kernel_drop_ratio": 0.0,       # 内核丢包率(%)
                "bandwidth_utilization": 0.0,   # 带宽利用率
            },
            
            # TCP流健康度指标
            "tcp_health": {
                "session_reuse_ratio": 0.0,
                "abnormal_ack_ratio": 0.0,
                "reassembly_fail_rate": 0.0,
            },

            # 实时分析事件管理
            "event_logs": {
                "events_received": 0,
                "events_processed": 0,
                "events_dropped": 0,
                "events_by_type": {},
                "events_by_source": {},
                "events_by_priority": {},
                "processing_time": 0,
                "avg_processing_time": 0,
                "queue_size": 0,
                "queue_full_percentage":0
            },
            # 日志路径
            "log_paths": {
                "suricata_log": "",        # Suricata日志路径
                "alert_log": "",           # 告警日志路径
                "traffic_log": "",         # 流量日志路径
                "event_log": "",           # 事件日志路径
            },
            
            # 分析结果摘要
            "summary": "",                  # 结果摘要
        }
    
    @staticmethod
    def create_report_result(result: Dict[str, Any], metadata: {}) -> Dict[str, Any]:
        """
        基于分析结果创建报告结果数据结构
        
        Args:
            result (Dict[str, Any]): 分析结果数据
            
        Returns:
            Dict[str, Any]: 报告结果数据结构
        """
        
        # 创建报告数据结构
        report_result = {
            "metadata": metadata,
            "data": {
                "timestamp": result.get("timestamp", time.time()),
                "datetime": result.get("datetime", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                "system_status": "running",  # 默认为运行中
                
                # 告警统计
                "alert_stats": {
                    "total": result.get("alert_count", 0),
                    "by_severity": _count_alerts_by_severity(result.get("alerts", [])),
                    "by_category": _count_alerts_by_category(result.get("alerts", [])),
                },
                
                # 流量统计
                "traffic_stats": result.get("traffic_stats", {}),
                
                # 网络性能指标
                "network_metrics": result.get("network_metrics", {}),
                
                # TCP流健康度指标
                "tcp_health": result.get("tcp_health", {}),

                # 实时分析事件管理
                "event_logs": result.get("event_logs", {}),
                
                # 告警详情
                "alerts": _format_alerts_for_report(result.get("alerts", [])),
                
                # 分析结果摘要
                "summary": result.get("summary", ""),
            }
        }
        
        return report_result


def _count_alerts_by_severity(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    按严重程度统计告警数量
    
    Args:
        alerts (List[Dict[str, Any]]): 告警列表
        
    Returns:
        Dict[str, int]: 按严重程度统计的告警数量
    """
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for alert in alerts:
        severity = alert.get("severity", "medium")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    return severity_counts


def _count_alerts_by_category(alerts: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    按类别统计告警数量
    
    Args:
        alerts (List[Dict[str, Any]]): 告警列表
        
    Returns:
        Dict[str, int]: 按类别统计的告警数量
    """
    category_counts = {}
    
    for alert in alerts:
        category = alert.get("category", "未分类")
        if category not in category_counts:
            category_counts[category] = 0
        category_counts[category] += 1
    
    return category_counts


def _format_alerts_for_report(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    格式化告警数据用于报告显示
    
    Args:
        alerts (List[Dict[str, Any]]): 原始告警列表
        
    Returns:
        List[Dict[str, Any]]: 格式化后的告警列表
    """
    formatted_alerts = []
    
    for alert in alerts:
        formatted_alert = {
            "id": alert.get("id", ""),
            "timestamp": alert.get("timestamp", 0),
            "datetime": datetime.fromtimestamp(alert.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S") \
                        if "timestamp" in alert else "",
            "severity": alert.get("severity", "medium"),
            "category": alert.get("category", "未分类"),
            "signature": alert.get("signature", ""),
            "description": alert.get("description", ""),
            "src_ip": alert.get("src_ip", ""),
            "src_port": alert.get("src_port", ""),
            "dest_ip": alert.get("dest_ip", ""),
            "dest_port": alert.get("dest_port", ""),
            "protocol": alert.get("protocol", ""),
            "action": alert.get("action", ""),
            "details": alert.get("details", {}),
        }
        
        formatted_alerts.append(formatted_alert)
    
    return formatted_alerts