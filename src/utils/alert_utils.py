#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
告警数据结构工具模块

提供统一的告警数据结构定义和处理函数，包括：
- 标准告警(alert)数据结构定义
- 告警数据结构转换和处理函数
- 与Suricata告警格式的转换函数
"""

import os
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union

# 配置日志
logger = logging.getLogger(__name__)


class AlertStructure:
    """
    告警数据结构类
    
    提供统一的告警数据结构定义和处理函数
    """
    
    @staticmethod
    def create_alert(signature: str, severity: str = "medium", category: str = "未分类",
                    src_ip: str = "", src_port: str = "", 
                    dest_ip: str = "", dest_port: str = "",
                    protocol: str = "", action: str = "alert", 
                    description: str = "", details: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        创建标准告警数据结构
        
        Args:
            signature (str): 告警签名/名称
            severity (str): 严重程度，可选值: "critical", "high", "medium", "low", "info"
            category (str): 告警类别
            src_ip (str): 源IP地址
            src_port (str): 源端口
            dest_ip (str): 目标IP地址
            dest_port (str): 目标端口
            protocol (str): 协议
            action (str): 动作，如"alert"、"block"等
            description (str): 告警描述
            details (Dict[str, Any]): 其他详细信息
            
        Returns:
            Dict[str, Any]: 标准告警数据结构
        """
        current_time = time.time()
        formatted_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 生成唯一ID
        alert_id = f"alert_{int(current_time * 1000)}_{hash(signature + src_ip + dest_ip)}"
        
        # 创建标准告警结构
        alert = {
            "id": alert_id,                      # 告警唯一ID
            "timestamp": current_time,           # 时间戳
            "datetime": formatted_time,          # 格式化时间
            "severity": severity,                # 严重程度
            "category": category,                # 告警类别
            "signature": signature,              # 告警签名/名称
            "description": description,          # 告警描述
            "src_ip": src_ip,              # 源IP地址
            "src_port": src_port,          # 源端口
            "dest_ip": dest_ip,    # 目标IP地址
            "dest_port": dest_port, # 目标端口
            "protocol": protocol,                # 协议
            "action": action,                    # 动作
            "details": details or {},            # 其他详细信息
        }
        
        return alert
    
    @staticmethod
    def from_suricata_alert(suricata_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        从Suricata告警格式转换为标准告警格式
        
        Args:
            suricata_alert (Dict[str, Any]): Suricata告警数据
            
        Returns:
            Dict[str, Any]: 标准告警数据结构
        """
        try:
            # 提取Suricata告警中的基本信息

            # 提取告警信息
            alert_data = suricata_alert.get("alert", {})
            
            # 映射严重程度
            severity_map = {
                1: "critical",
                2: "high",
                3: "medium",
                4: "low",
                5: "info"
            }
            severity_value = alert_data.get("severity", 3)  # 默认为medium
            severity = severity_map.get(severity_value, "medium")
            
            # 创建标准告警
            return AlertStructure.create_alert(
                signature=alert_data.get("signature", "未知告警"),
                severity=severity,
                category=alert_data.get("category", "未分类"),
                src_ip=suricata_alert.get("src_ip", ""),
                src_port=str(suricata_alert.get("src_port", "")),
                dest_ip=suricata_alert.get("dest_ip", ""),
                dest_port=str(suricata_alert.get("dest_port", "")),
                protocol=suricata_alert.get("proto", ""),
                action=alert_data.get("action", "alert"),
                description=f"{alert_data.get('signature', '未知告警')} ({alert_data.get('category', '未分类')})",
                details={
                    "original": suricata_alert,
                    "metadata": alert_data.get("metadata", {}),
                    "gid": alert_data.get("gid", ""),
                    "signature_id": alert_data.get("signature_id", ""),
                    "rev": alert_data.get("rev", ""),
                    "app_proto": suricata_alert.get("app_proto", ""),
                    "flow": suricata_alert.get("flow", {})
                }
            )
        except Exception as e:
            logger.error(f"从Suricata告警转换失败: {e}")
            # 返回一个基本的告警结构
            return AlertStructure.create_alert(
                signature="告警转换失败",
                description=f"无法解析Suricata告警: {str(e)}",
                details={"original": suricata_alert}
            )
    
    @staticmethod
    def from_anomaly_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        从异常事件数据转换为标准告警格式
        
        Args:
            event_data (Dict[str, Any]): 事件数据
            
        Returns:
            Dict[str, Any]: 标准告警数据结构
        """
        try:
            # 提取异常信息
            anomaly_data = event_data.get("anomaly", {})
            anomaly_type = anomaly_data.get("type", "未知异常")
            # 创建标准告警
            return AlertStructure.create_alert(
                signature=f"异常检测: {anomaly_type}",
                severity="medium",
                category="异常检测",
                src_ip=event_data.get("src_ip", ""),
                dest_ip=event_data.get("dest_ip", ""),
                protocol=event_data.get("proto", ""),
                description=f"检测到异常行为: {anomaly_type} ",
                details={
                    "original": event_data
                }
            )
        except Exception as e:
            logger.error(f"从异常事件转换失败: {e}")
            # 返回一个基本的告警结构
            return AlertStructure.create_alert(
                signature="异常事件转换失败",
                category="异常检测",
                description=f"无法解析异常事件: {str(e)}",
                details={"original": anomaly_data}
            )
    
    @staticmethod
    def get_severity_level(severity: str) -> int:
        """
        获取严重程度的数值级别
        
        Args:
            severity (str): 严重程度字符串
            
        Returns:
            int: 严重程度数值，数值越小严重程度越高
        """
        severity_levels = {
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 4,
            "info": 5
        }
        return severity_levels.get(severity.lower(), 3)  # 默认为medium (3)
    
    @staticmethod
    def save_alert_to_file(alert: Dict[str, Any], directory: str = None) -> str:
        """
        将告警保存到文件
        
        Args:
            alert (Dict[str, Any]): 告警数据
            directory (str): 保存目录，如果为None则使用默认目录
            
        Returns:
            str: 保存的文件路径
        """
        try:
            # 确定保存目录
            if directory is None:
                directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/alerts'))
            
            # 确保目录存在
            os.makedirs(directory, exist_ok=True)
            
            # 生成文件名
            alert_id = alert.get("id", f"alert_{int(time.time() * 1000)}")
            file_path = os.path.join(directory, f"{alert_id}.json")
            
            # 保存到文件
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(alert, f, indent=2, ensure_ascii=False)
                
            logger.debug(f"告警已保存到文件: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"保存告警到文件失败: {e}")
            return ""