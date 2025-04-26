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
# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


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
        # 默认的事件处理器映射
        default_handlers = {
            'alert': 0,  # 高优先级
            'anomaly': 1,
            'flow': 2,
            'http': 3,
            'dns': 3,
            'tls': 3,
            'ssh': 3
        }
        
        # 如果配置中有自定义的事件处理器映射，则使用配置中的
        if hasattr(self, 'config') and 'event_handlers' in self.config:
            return self.config['event_handlers']
        
        return default_handlers
    
    def _monitoring_loop(self):
        """
        监控循环
        """
        from src.core.ElasticSearch import ESClient
        from src.core.event_manager import EventManager
        from src.core.event_manager.event_manager import Event
        
        # 初始化ES客户端
        es_client = ESClient()
        
        # 使用事件管理器实例
        event_manager = self.event_manager if hasattr(self, 'event_manager') and self.event_manager else EventManager()
        
        # 事件类型及其处理优先级映射
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
                            # 创建事件对象
                            event = Event(
                                event_type=event_type,
                                # TODO: 确定事件的来源,先写es
                                source="es_client",
                                priority=priority,
                                data=event_data
                            )
                            
                            # 将事件发送到事件管理器的事件队列
                            event_manager.emit_event(event)
                            
                            logger.debug(f"已将{event_type}事件添加到事件队列: {event.id}")
                            
                        except Exception as e:
                            logger.error(f"处理{event_type}事件失败: {e}")
                
                # 更新上次查询时间
                last_query_time = current_time
                
                # 避免过于频繁查询
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"事件检测循环异常: {e}")
                time.sleep(5)  # 发生异常时，暂停一段时间后重试
    
    
    def _generate_report(self):
        """
        生成监控报告
        """
        report = {
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "metrics": {}
        }
        
        # 收集各指标的当前状态
        for metric_name, metric_data in self.metrics_data.items():
            if not metric_data["values"]:
                continue
            
            # 计算统计信息
            values = list(metric_data["values"])
            avg_value = sum(values) / len(values)
            max_value = max(values)
            min_value = min(values)
            
            report["metrics"][metric_name] = {
                "current": metric_data["current_value"],
                "average": avg_value,
                "max": max_value,
                "min": min_value,
                "status": metric_data["status"],
                "threshold": self.config["metrics"][metric_name]["threshold"]
            }
        
        # 计算监测覆盖率
        total_metrics = len(self.config["metrics"])
        active_metrics = sum(1 for m in self.config["metrics"] if self.config["metrics"][m]["enabled"])
        coverage_ratio = active_metrics / total_metrics if total_metrics > 0 else 0
        
        report["coverage"] = {
            "total_metrics": total_metrics,
            "active_metrics": active_metrics,
            "coverage_ratio": coverage_ratio
        }
        
        # 记录报告
        logger.info(f"监控报告: 覆盖率 {coverage_ratio:.2%}, 活跃指标 {active_metrics}/{total_metrics}")
        
        # 如果覆盖率低于目标，记录警告
        if coverage_ratio < 0.8:  # 80%的目标覆盖率
            logger.warning(f"监测覆盖率 {coverage_ratio:.2%} 低于目标 80%")
        
        return report
    

    def get_active_alerts(self):
        """
        获取当前活跃的告警
        
        Returns:
            list: 活跃告警列表
        """
        active_alerts = []
        
        for metric_name, metric_data in self.metrics_data.items():
            for alert in metric_data["alerts"]:
                if alert["status"] == "active":
                    active_alerts.append(alert)
        
        return active_alerts
    
    def get_alert_history(self, start_time=None, end_time=None, metric_name=None, severity=None):
        """
        获取告警历史
        
        Args:
            start_time (float): 开始时间戳
            end_time (float): 结束时间戳
            metric_name (str): 指标名称过滤
            severity (str): 严重程度过滤
            
        Returns:
            list: 告警历史列表
        """
        filtered_alerts = self.alert_history
        
        # 时间过滤
        if start_time is not None:
            filtered_alerts = [a for a in filtered_alerts if a["time"] >= start_time]
        if end_time is not None:
            filtered_alerts = [a for a in filtered_alerts if a["time"] <= end_time]
        
        # 指标名称过滤
        if metric_name is not None:
            filtered_alerts = [a for a in filtered_alerts if a["metric"] == metric_name]
        
        # 严重程度过滤
        if severity is not None:
            filtered_alerts = [a for a in filtered_alerts if a["severity"] == severity]
        
        return filtered_alerts
    
    def get_metric_status(self, metric_name=None):
        """
        获取指标状态
        
        Args:
            metric_name (str): 指标名称，如果为None则返回所有指标
            
        Returns:
            dict: 指标状态信息
        """
        if metric_name is not None:
            if metric_name not in self.metrics_data:
                return {}
            
            metric_data = self.metrics_data[metric_name]
            metric_config = self.config["metrics"][metric_name]
            
            return {
                "name": metric_name,
                "description": metric_config["description"],
                "current_value": metric_data["current_value"],
                "threshold": metric_config["threshold"],
                "status": metric_data["status"],
                "severity": metric_config["severity"],
                "enabled": metric_config["enabled"]
            }
        else:
            # 返回所有指标状态
            result = {}
            for name in self.metrics_data:
                result[name] = self.get_metric_status(name)
            return result
    
    def generate_anomaly_report(self, output_file=None):
        """
        生成异常报告
        
        Args:
            output_file (str): 输出文件路径，如果为None则返回报告内容
            
        Returns:
            str or bool: 如果output_file为None，返回报告内容；否则返回是否成功写入文件
        """
        # 获取当前状态
        metric_status = self.get_metric_status()
        active_alerts = self.get_active_alerts()
        
        # 计算监测覆盖率
        total_metrics = len(self.config["metrics"])
        active_metrics = sum(1 for m in self.config["metrics"] if self.config["metrics"][m]["enabled"])
        coverage_ratio = active_metrics / total_metrics if total_metrics > 0 else 0
        
        # 生成报告内容
        report = {
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "coverage": {
                "total_metrics": total_metrics,
                "active_metrics": active_metrics,
                "coverage_ratio": coverage_ratio,
                "target_achieved": coverage_ratio >= 0.8  # 80%的目标覆盖率
            },
            "metrics": metric_status,
            "active_alerts": active_alerts,
            "alert_history": self.alert_history[-20:],  # 最近20条告警历史
            "summary": {
                "total_alerts": len(self.alert_history),
                "active_alerts": len(active_alerts),
                "metrics_in_alert": sum(1 for m in metric_status.values() if m["status"] == "alert"),
                "metrics_normal": sum(1 for m in metric_status.values() if m["status"] == "normal")
            }
        }
        
        # 如果指定了输出文件，写入文件
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=4)
                logger.info(f"异常报告已保存到{output_file}")
                return True
            except Exception as e:
                logger.error(f"保存异常报告失败: {e}")
                return False
        
        # 否则返回报告内容
        return json.dumps(report, indent=4)
