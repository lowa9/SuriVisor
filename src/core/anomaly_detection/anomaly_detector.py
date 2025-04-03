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
from datetime import datetime

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    网络异常检测器类
    
    实现了对关键网络指标的监测机制，用于及时发现并报警网络异常。
    """
    
    def __init__(self, config_file=None, alert_callback=None):
        """
        初始化网络异常检测器
        
        Args:
            config_file (str): 配置文件路径
            alert_callback (callable): 告警回调函数，接收告警信息作为参数
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
        self.alert_callback = alert_callback
        
        # 告警历史
        self.alert_history = []
        
        # 监控状态
        self.monitoring_active = False
        self.monitoring_thread = None
        
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
    
    def update_metric(self, metric_name, value):
        """
        更新指标值
        
        Args:
            metric_name (str): 指标名称
            value (float): 指标值
            
        Returns:
            bool: 更新是否成功
        """
        if metric_name not in self.metrics_data:
            logger.warning(f"未知指标: {metric_name}")
            return False
        
        # 更新指标值
        self.metrics_data[metric_name]["values"].append(value)
        self.metrics_data[metric_name]["current_value"] = value
        
        # 如果在学习模式，记录数据
        if self.learning_mode:
            self.learning_data[metric_name].append(value)
        
        # 检查是否超过阈值
        self._check_threshold(metric_name)
        
        return True
    
    def _check_threshold(self, metric_name):
        """
        检查指标是否超过阈值
        
        Args:
            metric_name (str): 指标名称
        """
        if metric_name not in self.metrics_data or metric_name not in self.config["metrics"]:
            return
        
        metric_data = self.metrics_data[metric_name]
        metric_config = self.config["metrics"][metric_name]
        
        current_value = metric_data["current_value"]
        threshold = metric_config["threshold"]
        
        # 检查是否超过阈值
        if current_value > threshold:
            # 更新状态
            old_status = metric_data["status"]
            metric_data["status"] = "alert"
            
            # 如果状态从正常变为告警，触发告警
            if old_status == "normal":
                self._trigger_alert(metric_name)
        else:
            # 恢复正常
            if metric_data["status"] == "alert":
                metric_data["status"] = "normal"
                self._trigger_recovery(metric_name)
    
    def _trigger_alert(self, metric_name):
        """
        触发告警
        
        Args:
            metric_name (str): 指标名称
        """
        current_time = time.time()
        metric_data = self.metrics_data[metric_name]
        metric_config = self.config["metrics"][metric_name]
        
        # 检查告警间隔
        min_interval = self.config["alert"]["min_interval"]
        if current_time - metric_data["last_alert_time"] < min_interval:
            logger.debug(f"告警抑制: {metric_name} 在最小间隔内")
            return
        
        # 检查每小时最大告警数
        hour_start = current_time - 3600
        recent_alerts = [a for a in self.alert_history if a["time"] > hour_start]
        if len(recent_alerts) >= self.config["alert"]["max_alerts_per_hour"]:
            logger.warning(f"告警限制: 已达到每小时最大告警数 {self.config['alert']['max_alerts_per_hour']}")
            return
        
        # 创建告警信息
        alert_info = {
            "metric": metric_name,
            "description": metric_config["description"],
            "value": metric_data["current_value"],
            "threshold": metric_config["threshold"],
            "severity": metric_config["severity"],
            "time": current_time,
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "active"
        }
        
        # 记录告警
        metric_data["alerts"].append(alert_info)
        metric_data["last_alert_time"] = current_time
        self.alert_history.append(alert_info)
        
        # 调用告警回调函数
        if self.alert_callback:
            try:
                self.alert_callback(alert_info)
            except Exception as e:
                logger.error(f"调用告警回调函数失败: {e}")
        
        # 记录告警日志
        logger.warning(f"告警: {metric_config['description']}超过阈值 - 当前值: {metric_data['current_value']:.4f}, 阈值: {metric_config['threshold']:.4f}, 严重程度: {metric_config['severity']}")
    
    def _trigger_recovery(self, metric_name):
        """
        触发恢复通知
        
        Args:
            metric_name (str): 指标名称
        """
        metric_data = self.metrics_data[metric_name]
        metric_config = self.config["metrics"][metric_name]
        
        # 更新最近的告警状态
        if metric_data["alerts"]:
            metric_data["alerts"][-1]["status"] = "resolved"
            metric_data["alerts"][-1]["resolve_time"] = time.time()
        
        # 记录恢复日志
        logger.info(f"恢复: {metric_config['description']}已恢复正常 - 当前值: {metric_data['current_value']:.4f}, 阈值: {metric_config['threshold']:.4f}")
    
    def start_monitoring(self):
        """
        启动监控
        
        Returns:
            bool: 启动是否成功
        """
        if self.monitoring_active:
            logger.warning("监控已经在运行")
            return False
        
        self.monitoring_active = True
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
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        logger.info("网络异常监控已停止")
        return True
    
    def _monitoring_loop(self):
        """
        监控循环
        """
        last_report_time = time.time()
        
        while self.monitoring_active:
            current_time = time.time()
            
            # 检查是否需要生成报告
            if current_time - last_report_time >= self.config["monitoring"]["report_interval"]:
                self._generate_report()
                last_report_time = current_time
            
            # 检查学习模式是否结束
            if self.learning_mode and current_time - self.learning_start_time >= self.config["monitoring"]["learning_period"]:
                self._finish_learning()
            
            # 休眠一段时间
            time.sleep(self.config["monitoring"]["sampling_interval"])
    
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
    
    def start_learning_mode(self, duration=None):
        """
        启动学习模式，自动调整阈值
        
        Args:
            duration (int): 学习时长（秒），如果为None则使用配置中的值
            
        Returns:
            bool: 启动是否成功
        """
        if self.learning_mode:
            logger.warning("学习模式已经在运行")
            return False
        
        self.learning_mode = True
        self.learning_data = defaultdict(list)
        self.learning_start_time = time.time()
        
        # 设置学习时长
        if duration is not None:
            self.config["monitoring"]["learning_period"] = duration
        
        logger.info(f"学习模式已启动，持续时间: {self.config['monitoring']['learning_period']}秒")
        return True
    
    def _finish_learning(self):
        """
        完成学习模式，调整阈值
        """
        if not self.learning_mode:
            return
        
        logger.info("学习模式完成，调整阈值")
        
        # 遍历所有指标
        for metric_name, values in self.learning_data.items():
            if not values:
                continue
            
            # 计算统计信息
            avg_value = sum(values) / len(values)
            std_dev = (sum((x - avg_value) ** 2 for x in values) / len(values)) ** 0.5
            
            # 根据统计信息调整阈值
            if metric_name in self.config["metrics"]:
                # 设置新阈值为平均值加上3倍标准差（可配置）
                new_threshold = avg_value + 3 * std_dev
                old_threshold = self.config["metrics"][metric_name]["threshold"]
                
                # 更新阈值
                self.config["metrics"][metric_name]["threshold"] = new_threshold
                
                logger.info(f"指标 {metric_name} 阈值已调整: {old_threshold:.4f} -> {new_threshold:.4f}")
        
        # 重置学习模式
        self.learning_mode = False
        self.learning_data = defaultdict(list)
    
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


# 测试代码
if __name__ == "__main__":
    # 定义告警回调函数
    def alert_handler(alert_info):
        print(f"\n收到告警: {alert_info['description']}")
        print(f"当前值: {alert_info['value']:.4f}, 阈值: {alert_info['threshold']:.4f}")
        print(f"严重程度: {alert_info['severity']}, 时间: {alert_info['datetime']}")
    
    # 创建异常检测器实例
    detector = AnomalyDetector(alert_callback=alert_handler)
    
    # 启动监控
    detector.start_monitoring()
    
    try:
        # 模拟更新指标
        print("模拟正常网络流量...")
        for i in range(50):
            # 正常值
            detector.update_metric("packet_loss_ratio", 0.01)  # 1%丢包率
            detector.update_metric("out_of_order_ratio", 0.05)  # 5%乱序比例
            detector.update_metric("syn_flood_detection", 10)  # 每秒10个SYN包
            time.sleep(0.1)
        
        print("\n模拟网络异常...")
        # 模拟丢包率异常
        for i in range(20):
            detector.update_metric("packet_loss_ratio", 0.08)  # 8%丢包率，超过阈值
            time.sleep(0.1)
        
        # 恢复正常
        print("\n恢复正常网络状态...")
        for i in range(20):
            detector.update_metric("packet_loss_ratio", 0.01)  # 恢复正常
            time.sleep(0.1)
        
        # 模拟SYN洪水攻击
        print("\n模拟SYN洪水攻击...")
        for i in range(20):
            detector.update_metric("syn_flood_detection", 150)  # 每秒150个SYN包，超过阈值
            time.sleep(0.1)
        
        # 生成报告
        print("\n生成异常报告...")
        report = detector.generate_anomaly_report()
        print(report)
        
    except KeyboardInterrupt:
        print("\n测试中断")
    finally:
        # 停止监控
        detector.stop_monitoring()