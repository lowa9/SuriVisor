#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络报文异常处理机制模块

该模块实现了对关键网络指标的监测机制，用于及时发现并报警网络异常。
目标是保证关键网络指标监测覆盖率达到80%，并确保报警响应时间不超过3分钟。
"""

import os
import sys
import time
import logging
import json
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from src.core.event_manager import EventManager

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

class EventDetector:
    """
    网络异常检测器类
    
    实现了对关键网络指标的监测机制，用于及时发现并报警网络异常。
    """
    
    def __init__(self, config_file=None, event_callback=None):
        """
        初始化网络异常检测器
        
        Args:
            config_file (str): 配置文件路径
            event_callback (callable): 告警回调函数，接收告警信息作为参数
        """
        # 默认配置
        self.config = {
            "metrics": {
                "packet_loss_ratio": {
                    "description": "丢包率",
                    "threshold": 0.05,  # 5%
                    "window_size": 1000,  # 样本窗口大小
                    "severity": "high",
                    "enabled": True
                },
                "out_of_order_ratio": {
                    "description": "乱序比例",
                    "threshold": 0.1,  # 10%
                    "window_size": 1000,
                    "severity": "medium",
                    "enabled": True
                },
                "retransmission_ratio": {
                    "description": "重传比例",
                    "threshold": 0.08,  # 8%
                    "window_size": 1000,
                    "severity": "medium",
                    "enabled": True
                },
                "duplicate_ack_ratio": {
                    "description": "重复ACK比例",
                    "threshold": 0.1,  # 10%
                    "window_size": 1000,
                    "severity": "low",
                    "enabled": True
                },
                "rtt_variation": {
                    "description": "RTT变化率",
                    "threshold": 0.5,  # 50%
                    "window_size": 100,
                    "severity": "medium",
                    "enabled": True
                },
                "connection_failure_rate": {
                    "description": "连接失败率",
                    "threshold": 0.2,  # 20%
                    "window_size": 100,
                    "severity": "high",
                    "enabled": True
                },
                "bandwidth_utilization": {
                    "description": "带宽利用率",
                    "threshold": 0.9,  # 90%
                    "window_size": 60,  # 60秒
                    "severity": "medium",
                    "enabled": True
                },
                "syn_flood_detection": {
                    "description": "SYN洪水检测",
                    "threshold": 100,  # 每秒SYN包数
                    "window_size": 10,  # 10秒
                    "severity": "critical",
                    "enabled": True
                },
                "icmp_flood_detection": {
                    "description": "ICMP洪水检测",
                    "threshold": 50,  # 每秒ICMP包数
                    "window_size": 10,  # 10秒
                    "severity": "high",
                    "enabled": True
                },
                "fragmentation_ratio": {
                    "description": "分片比例",
                    "threshold": 0.2,  # 20%
                    "window_size": 1000,
                    "severity": "low",
                    "enabled": True
                }
            },
            "alert": {
                "min_interval": 180,  # 最小告警间隔（秒）
                "max_alerts_per_hour": 20,  # 每小时最大告警数
                "alert_suppression": True,  # 是否启用告警抑制
                "alert_aggregation": True,  # 是否启用告警聚合
                "notification_channels": ["console", "log"]  # 告警通知渠道
            },
            "monitoring": {
                "sampling_interval": 1,  # 采样间隔（秒）
                "report_interval": 60,  # 报告间隔（秒）
                "auto_threshold_adjustment": True,  # 是否自动调整阈值
                "learning_period": 3600  # 学习期（秒）
            }
        }
        
        # 加载配置文件
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
        
        # 初始化指标数据结构
        self.metrics_data = {}
        for metric_name in self.config["metrics"]:
            metric_config = self.config["metrics"][metric_name]
            if metric_config["enabled"]:
                self.metrics_data[metric_name] = {
                    "values": deque(maxlen=metric_config["window_size"]),
                    "alerts": [],
                    "last_alert_time": 0,
                    "current_value": 0,
                    "status": "normal"
                }
        
        # 告警回调函数
        self.event_callback = event_callback
        
        # 告警历史
        self.alert_history = []
        
        # 事件管理器
        self.event_manager = None
        
        # 监控状态
        self.monitoring_active = False
        self.monitoring_thread = None
        self.running = False  # 控制监控循环的运行标志
        
        # 学习模式数据
        self.learning_mode = False
        self.learning_data = defaultdict(list)
        self.learning_start_time = 0
        
        logger.info(f"初始化网络异常检测器: 监测{len(self.metrics_data)}个指标")
    
    def load_config(self, config_file):
        """
        从文件加载配置
        
        Args:
            config_file (str): 配置文件路径
            
        Returns:
            bool: 加载是否成功
        """
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
            
            # 合并配置
            for section in user_config:
                if section in self.config:
                    if isinstance(self.config[section], dict):
                        self.config[section].update(user_config[section])
                    else:
                        self.config[section] = user_config[section]
            
            logger.info(f"从{config_file}加载配置成功")
            return True
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return False
    
    def save_config(self, config_file):
        """
        保存配置到文件
        
        Args:
            config_file (str): 配置文件路径
            
        Returns:
            bool: 保存是否成功
        """
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"配置已保存到{config_file}")
            return True
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
            return False
    
    def start_monitoring(self, event_manager):
        """
        启动监控

        Args:
            event_manager: EventManager实例
        
        Returns:
            bool: 启动是否成功
        """
        if self.monitoring_active:
            logger.warning("监控已经在运行")
            return False
        
        self.monitoring_active = True
        self.running = True  # 设置运行标志
        self.set_event_manager(event_manager)
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        logger.info("网络异常监控已启动")
        return True
    
    def stop_monitoring(self):
        """
        停止监控
        
        Returns:
            bool: 停止是否成功
        """
        if not self.monitoring_active:
            logger.warning("监控未在运行")
            return False
        
        self.monitoring_active = False
        self.running = False  # 设置运行标志为False，使监控循环退出
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        logger.info("网络异常监控已停止")
        return True
        
    def set_event_manager(self, event_manager):
        """
        设置事件管理器实例
        
        Args:
            event_manager: EventManager实例
            
        Returns:
            bool: 设置是否成功
        """
        if event_manager is None:
            logger.warning("提供的事件管理器为空")
            return False
            
        self.event_manager = event_manager
        logger.info("已设置事件管理器实例")
        return True
        
    def get_event_handlers(self):
        """
        获取事件类型及其处理优先级映射
        
        Returns:
            dict: 事件类型及其优先级的映射字典
        """
        # 如果事件管理器已设置，则使用其handlers属性中的事件类型
        if self.event_manager is not None:
            # 从事件管理器的handlers中提取事件类型
            # 注意：event_manager.handlers是defaultdict(list)，键为事件类型
            # 为每种事件类型分配优先级
            handlers_dict = {}
            for event_type in self.event_manager.handlers.keys():
                # 为不同事件类型设置默认优先级
                if event_type == 'alert':
                    handlers_dict[event_type] = 0  # 最高优先级
                elif event_type == 'anomaly':
                    handlers_dict[event_type] = 1
                else:
                    handlers_dict[event_type] = 2  # 其他事件类型默认优先级
            
            # 如果没有找到任何处理器，使用默认配置
            if not handlers_dict:
                handlers_dict = self._get_default_handlers()
            
            return handlers_dict
        
        # 如果配置中有自定义的事件处理器映射，则使用配置中的
        if hasattr(self, 'config') and 'event_handlers' in self.config:
            return self.config['event_handlers']
        
        # 如果没有事件管理器和自定义配置，则使用默认配置
        return self._get_default_handlers()
        
    def _get_default_handlers(self):
        """
        获取默认的事件处理器映射
        
        Returns:
            dict: 默认的事件类型及其优先级的映射字典
        """
        return {
            'alert': 0,      # 高优先级
            'anomaly': 1,    # 中高优先级
            'flow': 2,       # 中优先级
            'http': 3,       # 低优先级
            'dns': 3,        # 低优先级
            'tls': 3,        # 低优先级
            'ssh': 3         # 低优先级
        }
    
    def _monitoring_loop(self):
        """
        监控循环
        """
        from src.core.ElasticSearch import ESClient
        from src.core.event_manager import EventManager
        from src.core.event_manager.event_manager import Event
        
        # 初始化ES客户端
        es_client = ESClient()
        
        # 确保事件管理器实例存在
        if not self.event_manager:
            logger.warning("事件管理器未设置，创建默认实例")
            self.event_manager = EventManager()
            self.event_manager.start()  # 确保事件管理器已启动
        
        # 获取事件类型及其处理优先级映射
        # 这里使用get_event_handlers方法，该方法会优先使用event_manager中的handlers
        event_handlers = self.get_event_handlers()
        
        # 记录上次查询时间
        last_query_time = datetime.now() - timedelta(minutes=1)
        
        logger.info("事件检测循环已启动")
        
        while self.running:
            try:
                current_time = datetime.now()
                
                # 查询各类型事件
                for event_type, priority in event_handlers.items():
                    events = es_client.query_events(
                        event_type=event_type,
                        start_time=last_query_time,
                        end_time=current_time,
                        size=100
                    )
                    
                    # 处理事件
                    for event_data in events:
                        try:
                            # 使用事件管理器的create_and_emit_event方法创建并发送事件
                            # 这样可以确保事件格式与事件管理器期望的一致
                            success = self.event_manager.create_and_emit_event(
                                event_type=event_type,
                                source="es_client",
                                priority=priority,
                                data=event_data
                            )
                            
                            if success:
                                logger.debug(f"已将{event_type}事件添加到事件队列")
                            else:
                                logger.warning(f"添加{event_type}事件到队列失败，可能队列已满")
                            
                        except Exception as e:
                            logger.error(f"处理{event_type}事件失败: {e}")
                
                # 更新上次查询时间
                last_query_time = current_time
                
                # 避免过于频繁查询
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"事件检测循环异常: {e}")
                time.sleep(5)  # 发生异常时，暂停一段时间后重试