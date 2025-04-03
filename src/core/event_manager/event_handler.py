#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器模块

该模块实现了事件处理器，用于处理系统中的各类事件，
特别是将重要事件传递给报告生成器，确保事件能够被记录并包含在生成的报告中。
"""

import os
import sys
import time
import logging
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EventHandler:
    """
    事件处理器类
    
    负责处理系统中的各类事件，特别是将重要事件传递给报告生成器。
    """
    
    def __init__(self, report_generator=None):
        """
        初始化事件处理器
        
        Args:
            report_generator: 报告生成器实例，用于生成报告
        """
        self.report_generator = report_generator
        
        # 事件存储，按类型分类
        self.events = {
            "alert": [],
            "attack": [],
            "system": [],
            "anomaly": [],
            "other": []
        }
        
        # 事件统计信息
        self.stats = {
            "events_handled": 0,
            "events_by_type": {},
            "events_by_priority": {},
            "events_by_source": {}
        }
        
        logger.info("初始化事件处理器")
    
    def set_report_generator(self, report_generator):
        """
        设置报告生成器
        
        Args:
            report_generator: 报告生成器实例
        """
        self.report_generator = report_generator
        logger.info("设置报告生成器")
    
    def handle_event(self, event):
        """
        处理事件
        
        Args:
            event: 事件对象
        """
        # 记录事件
        self._record_event(event)
        
        # 更新统计信息
        self._update_stats(event)
        
        # 根据事件类型处理
        if event.event_type.startswith("alert"):
            self._handle_alert_event(event)
        elif event.event_type.startswith("attack"):
            self._handle_attack_event(event)
        elif event.event_type.startswith("system"):
            self._handle_system_event(event)
        elif event.event_type.startswith("anomaly"):
            self._handle_anomaly_event(event)
        else:
            self._handle_other_event(event)
        
        logger.debug(f"处理事件: {event.id}")
    
    def _record_event(self, event):
        """
        记录事件
        
        Args:
            event: 事件对象
        """
        # 确定事件类型分类
        if event.event_type.startswith("alert"):
            event_category = "alert"
        elif event.event_type.startswith("attack"):
            event_category = "attack"
        elif event.event_type.startswith("system"):
            event_category = "system"
        elif event.event_type.startswith("anomaly"):
            event_category = "anomaly"
        else:
            event_category = "other"
        
        # 记录事件
        self.events[event_category].append(event.to_dict())
        
        # 限制每类事件的最大数量，防止内存占用过大
        max_events_per_category = 1000
        if len(self.events[event_category]) > max_events_per_category:
            self.events[event_category] = self.events[event_category][-max_events_per_category:]
    
    def _update_stats(self, event):
        """
        更新统计信息
        
        Args:
            event: 事件对象
        """
        # 更新总事件数
        self.stats["events_handled"] += 1
        
        # 更新事件类型统计
        if event.event_type in self.stats["events_by_type"]:
            self.stats["events_by_type"][event.event_type] += 1
        else:
            self.stats["events_by_type"][event.event_type] = 1
        
        # 更新事件优先级统计
        if event.priority in self.stats["events_by_priority"]:
            self.stats["events_by_priority"][event.priority] += 1
        else:
            self.stats["events_by_priority"][event.priority] = 1
        
        # 更新事件来源统计
        if event.source in self.stats["events_by_source"]:
            self.stats["events_by_source"][event.source] += 1
        else:
            self.stats["events_by_source"][event.source] = 1
    
    def _handle_alert_event(self, event):
        """
        处理告警事件
        
        Args:
            event: 事件对象
        """
        # 如果有报告生成器，将告警事件传递给报告生成器
        if self.report_generator:
            # 可以在这里添加特定的报告生成逻辑
            pass
        
        # 记录告警事件
        logger.warning(f"告警事件: {event.data.get('description', '未知告警')} - 优先级: {event.priority}")
    
    def _handle_attack_event(self, event):
        """
        处理攻击事件
        
        Args:
            event: 事件对象
        """
        # 如果有报告生成器，将攻击事件传递给报告生成器
        if self.report_generator:
            # 可以在这里添加特定的报告生成逻辑
            pass
        
        # 记录攻击事件
        logger.warning(f"攻击事件: {event.data.get('type', '未知攻击')} - 来源: {event.data.get('source_ip', '未知')} - 目标: {event.data.get('target_ip', '未知')}")
    
    def _handle_system_event(self, event):
        """
        处理系统事件
        
        Args:
            event: 事件对象
        """
        # 如果有报告生成器，将系统事件传递给报告生成器
        if self.report_generator:
            # 可以在这里添加特定的报告生成逻辑
            pass
        
        # 记录系统事件
        logger.info(f"系统事件: {event.data.get('description', '未知系统事件')}")
    
    def _handle_anomaly_event(self, event):
        """
        处理异常事件
        
        Args:
            event: 事件对象
        """
        # 如果有报告生成器，将异常事件传递给报告生成器
        if self.report_generator:
            # 可以在这里添加特定的报告生成逻辑
            pass
        
        # 记录异常事件
        logger.warning(f"异常事件: {event.data.get('description', '未知异常')} - 值: {event.data.get('value', '未知')} - 阈值: {event.data.get('threshold', '未知')}")
    
    def _handle_other_event(self, event):
        """
        处理其他事件
        
        Args:
            event: 事件对象
        """
        # 如果有报告生成器，将其他事件传递给报告生成器
        if self.report_generator:
            # 可以在这里添加特定的报告生成逻辑
            pass
        
        # 记录其他事件
        logger.info(f"其他事件: {event.event_type} - {event.data}")
    
    def get_events_for_report(self, event_types=None, max_events=100, start_time=None, end_time=None):
        """
        获取用于报告的事件
        
        Args:
            event_types: 事件类型列表，如果为None则获取所有类型
            max_events: 每种类型的最大事件数
            start_time: 开始时间戳
            end_time: 结束时间戳
            
        Returns:
            Dict[str, List]: 按类型分类的事件列表
        """
        result = {}
        
        # 确定要获取的事件类型
        if event_types is None:
            event_types = list(self.events.keys())
        
        # 获取每种类型的事件
        for event_type in event_types:
            if event_type in self.events:
                # 过滤事件
                filtered_events = self.events[event_type]
                
                # 按时间过滤
                if start_time is not None:
                    filtered_events = [e for e in filtered_events if e["timestamp"] >= start_time]
                
                if end_time is not None:
                    filtered_events = [e for e in filtered_events if e["timestamp"] <= end_time]
                
                # 限制事件数量
                result[event_type] = filtered_events[-max_events:] if len(filtered_events) > max_events else filtered_events
        
        return result
    
    def get_statistics(self):
        """
        获取统计信息
        
        Returns:
            Dict: 统计信息字典
        """
        # 添加当前事件数量信息
        events_count = {}
        for event_type, events in self.events.items():
            events_count[event_type] = len(events)
        
        # 复制统计信息，避免返回可变对象
        stats_copy = self.stats.copy()
        stats_copy["current_events_count"] = events_count
        
        return stats_copy
    
    def clear_events(self, event_types=None):
        """
        清除事件
        
        Args:
            event_types: 要清除的事件类型列表，如果为None则清除所有类型
            
        Returns:
            int: 清除的事件数量
        """
        cleared_count = 0
        
        # 确定要清除的事件类型
        if event_types is None:
            event_types = list(self.events.keys())
        
        # 清除每种类型的事件
        for event_type in event_types:
            if event_type in self.events:
                cleared_count += len(self.events[event_type])
                self.events[event_type] = []
        
        logger.info(f"清除了{cleared_count}个事件")
        return cleared_count
    
    def clear_statistics(self):
        """
        清除统计信息
        """
        self.stats = {
            "events_handled": 0,
            "events_by_type": {},
            "events_by_priority": {},
            "events_by_source": {}
        }
        logger.info("清除了事件统计信息")