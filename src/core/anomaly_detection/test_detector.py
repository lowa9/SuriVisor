#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络异常检测模块测试脚本

该脚本用于测试网络异常检测模块的性能，模拟不同类型的网络异常场景，
并评估监测覆盖率是否达到80%以上，报警响应时间是否在3分钟内。
"""

import os
import sys
import time
import random
import logging
import json
import threading
from datetime import datetime
from collections import defaultdict

# 导入异常检测器
from anomaly_detector import AnomalyDetector

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AnomalySimulator:
    """
    网络异常模拟器类
    
    用于模拟各种网络异常场景，测试异常检测器的性能。
    """
    
    def __init__(self):
        """
        初始化网络异常模拟器
        """
        # 定义异常场景
        self.scenarios = {
            "packet_loss": self._simulate_packet_loss,
            "out_of_order": self._simulate_out_of_order,
            "syn_flood": self._simulate_syn_flood,
            "icmp_flood": self._simulate_icmp_flood,
            "bandwidth_saturation": self._simulate_bandwidth_saturation
        }
        
        # 告警记录
        self.alerts = []
        self.alert_times = {}
        
        logger.info("初始化网络异常模拟器")
    
    def _alert_callback(self, alert_info):
        """
        告警回调函数
        
        Args:
            alert_info (dict): 告警信息
        """
        metric = alert_info["metric"]
        self.alerts.append(alert_info)
        
        # 记录告警时间
        if metric not in self.alert_times:
            self.alert_times[metric] = time.time()
        
        logger.info(f"收到告警: {alert_info['description']} - 值: {alert_info['value']:.4f}, 阈值: {alert_info['threshold']:.4f}")
    
    def _simulate_packet_loss(self, detector, duration=60, severity="medium"):
        """
        模拟丢包场景
        
        Args:
            detector (AnomalyDetector): 异常检测器实例
            duration (int): 持续时间（秒）
            severity (str): 严重程度（low, medium, high）
            
        Returns:
            dict: 测试结果
        """
        logger.info(f"开始模拟丢包场景 (持续{duration}秒, 严重程度:{severity})")
        
        # 根据严重程度设置丢包率
        if severity == "low":
            loss_ratio = 0.03  # 3%
        elif severity == "medium":
            loss_ratio = 0.08  # 8%
        else:  # high
            loss_ratio = 0.15  # 15%
        
        # 记录开始时间
        start_time = time.time()
        anomaly_start_time = None
        
        # 先模拟正常流量
        for i in range(10):
            detector.update_metric("packet_loss_ratio", 0.01)  # 1%丢包率
            time.sleep(0.5)
        
        # 模拟丢包异常
        anomaly_start_time = time.time()
        for i in range(int(duration / 0.5)):
            # 添加一些随机波动
            current_loss = loss_ratio + random.uniform(-0.01, 0.01)
            detector.update_metric("packet_loss_ratio", max(0, current_loss))
            time.sleep(0.5)
        
        # 恢复正常
        for i in range(10):
            detector.update_metric("packet_loss_ratio", 0.01)  # 恢复正常
            time.sleep(0.5)
        
        # 计算响应时间
        response_time = None
        if "packet_loss_ratio" in self.alert_times:
            response_time = self.alert_times["packet_loss_ratio"] - anomaly_start_time
        
        return {
            "scenario": "packet_loss",
            "severity": severity,
            "anomaly_value": loss_ratio,
            "duration": duration,
            "response_time": response_time,
            "detected": "packet_loss_ratio" in self.alert_times
        }
    
    def _simulate_out_of_order(self, detector, duration=60, severity="medium"):
        """
        模拟乱序场景
        
        Args:
            detector (AnomalyDetector): 异常检测器实例
            duration (int): 持续时间（秒）
            severity (str): 严重程度（low, medium, high）
            
        Returns:
            dict: 测试结果
        """
        logger.info(f"开始模拟乱序场景 (持续{duration}秒, 严重程度:{severity})")
        
        # 根据严重程度设置乱序比例
        if severity == "low":
            out_of_order_ratio = 0.05  # 5%
        elif severity == "medium":
            out_of_order_ratio = 0.15  # 15%
        else:  # high
            out_of_order_ratio = 0.25  # 25%
        
        # 记录开始时间
        start_time = time.time()
        anomaly_start_time = None
        
        # 先模拟正常流量
        for i in range(10):
            detector.update_metric("out_of_order_ratio", 0.02)  # 2%乱序比例
            time.sleep(0.5)
        
        # 模拟乱序异常
        anomaly_start_time = time.time()
        for i in range(int(duration / 0.5)):
            # 添加一些随机波动
            current_ratio = out_of_order_ratio + random.uniform(-0.02, 0.02)
            detector.update_metric("out_of_order_ratio", max(0, current_ratio))
            time.sleep(0.5)
        
        # 恢复正常
        for i in range(10):
            detector.update_metric("out_of_order_ratio", 0.02)  # 恢复正常
            time.sleep(0.5)
        
        # 计算响应时间
        response_time = None
        if "out_of_order_ratio" in self.alert_times:
            response_time = self.alert_times["out_of_order_ratio"] - anomaly_start_time
        
        return {
            "scenario": "out_of_order",
            "severity": severity,
            "anomaly_value": out_of_order_ratio,
            "duration": duration,
            "response_time": response_time,
            "detected": "out_of_order_ratio" in self.alert_times
        }
    
    def _simulate_syn_flood(self, detector, duration=60, severity="medium"):
        """
        模拟SYN洪水攻击场景
        
        Args:
            detector (AnomalyDetector): 异常检测器实例
            duration (int): 持续时间（秒）
            severity (str): 严重程度（low, medium, high）
            
        Returns:
            dict: 测试结果
        """
        logger.info(f"开始模拟SYN洪水攻击场景 (持续{duration}秒, 严重程度:{severity})")
        
        # 根据严重程度设置SYN包数量
        if severity == "low":
            syn_count = 120  # 每秒120个SYN包
        elif severity == "medium":
            syn_count = 200  # 每秒200个SYN包
        else:  # high
            syn_count = 500  # 每秒500个SYN包
        
        # 记录开始时间
        start_time = time.time()
        anomaly_start_time = None
        
        # 先模拟正常流量
        for i in range(10):
            detector.update_metric("syn_flood_detection", 20)  # 每秒20个SYN包
            time.sleep(0.5)
        
        # 模拟SYN洪水攻击
        anomaly_start_time = time.time()
        for i in range(int(duration / 0.5)):
            # 添加一些随机波动
            current_count = syn_count + random.randint(-20, 20)
            detector.update_metric("syn_flood_detection", max(0, current_count))
            time.sleep(0.5)
        
        # 恢复正常
        for i in range(10):
            detector.update_metric("syn_flood_detection", 20)  # 恢复正常
            time.sleep(0.5)
        
        # 计算响应时间
        response_time = None
        if "syn_flood_detection" in self.alert_times:
            response_time = self.alert_times["syn_flood_detection"] - anomaly_start_time
        
        return {
            "scenario": "syn_flood",
            "severity": severity,
            "anomaly_value": syn_count,
            "duration": duration,
            "response_time": response_time,
            "detected": "syn_flood_detection" in self.alert_times
        }
    
    def _simulate_icmp_flood(self, detector, duration=60, severity="medium"):
        """
        模拟ICMP洪水攻击场景
        
        Args:
            detector (AnomalyDetector): 异常检测器实例
            duration (int): 持续时间（秒）
            severity (str): 严重程度（low, medium, high）
            
        Returns:
            dict: 测试结果
        """
        logger.info(f"开始模拟ICMP洪水攻击场景 (持续{duration}秒, 严重程度:{severity})")
        
        # 根据严重程度设置ICMP包数量
        if severity == "low":
            icmp_count = 60  # 每秒60个ICMP包
        elif severity == "medium":
            icmp_count = 100  # 每秒100个ICMP包
        else:  # high
            icmp_count = 200  # 每秒200个ICMP包
        
        # 记录开始时间
        start_time = time.time()
        anomaly_start_time = None
        
        # 先模拟正常流量
        for i in range(10):
            detector.update_metric("icmp_flood_detection", 10)  # 每秒10个ICMP包
            time.sleep(0.5)
        
        # 模拟ICMP洪水攻击
        anomaly_start_time = time.time()
        for i in range(int(duration / 0.5)):
            # 添加一些随机波动
            current_count = icmp_count + random.randint(-10, 10)
            detector.update_metric("icmp_flood_detection", max(0, current_count))
            time.sleep(0.5)
        
        # 恢复正常
        for i in range(10):
            detector.update_metric("icmp_flood_detection", 10)  # 恢复正常
            time.sleep(0.5)
        
        # 计算响应时间
        response_time = None
        if "icmp_flood_detection" in self.alert_times:
            response_time = self.alert_times["icmp_flood_detection"] - anomaly_start_time
        
        return {
            "scenario": "icmp_flood",
            "severity": severity,
            "anomaly_value": icmp_count,
            "duration": duration,
            "response_time": response_time,
            "detected": "icmp_flood_detection" in self.alert_times
        }
    
    def _simulate_bandwidth_saturation(self, detector, duration=60, severity="medium"):
        """
        模拟带宽饱和场景
        
        Args:
            detector (AnomalyDetector): 异常检测器实例
            duration (int): 持续时间（秒）
            severity (str): 严重程度（low, medium, high）
            
        Returns:
            dict: 测试结果
        """
        logger.info(f"开始模拟带宽饱和场景 (持续{duration}秒, 严重程度:{severity})")
        
        # 根据严重程度设置带宽利用率
        if severity == "low":
            bandwidth_util = 0.85  # 85%
        elif severity == "medium":
            bandwidth_util = 0.95  # 95%
        else:  # high
            bandwidth_util = 0.99  # 99%
        
        # 记录开始时间
        start_time = time.time()
        anomaly_start_time = None
        
        # 先模拟正常流量
        for i in range(10):
            detector.update_metric("bandwidth_utilization", 0.6)  # 60%带宽利用率
            time.sleep(0.5)
        
        # 模拟带宽饱和
        anomaly_start_time = time.time()
        for i in range(int(duration / 0.5)):
            # 添加一些随机波动
            current_util = bandwidth_util + random.uniform(-0.05, 0)
            detector.update_metric("bandwidth_utilization", min(1.0, max(0, current_util)))
            time.sleep(0.5)
        
        # 恢复正常
        for i in range(10):
            detector.update_metric("bandwidth_utilization", 0.6)  # 恢复正常
            time.sleep(0.5)
        
        # 计算响应时间
        response_time = None
        if "bandwidth_utilization" in self.alert_times:
            response_time = self.alert_times["bandwidth_utilization"] - anomaly_start_time
        
        return {
            "scenario": "bandwidth_saturation",
            "severity": severity,
            "anomaly_value": bandwidth_util,
            "duration": duration,
            "response_time": response_time,
            "detected": "bandwidth_utilization" in self.alert_times
        }
    
    def run_scenario(self, scenario_name, detector, duration=30, severity="medium"):
        """
        运行指定的异常场景
        
        Args:
            scenario_name (str): 场景名称
            detector (AnomalyDetector): 异常检测器实例
            duration (int): 持续时间（秒）
            severity (str): 严重程度（low, medium, high）
            
        Returns:
            dict: 测试结果
        """
        if scenario_name not in self.scenarios:
            logger.error(f"未知场景: {scenario_name}")
            return {"error": f"未知场景: {scenario_name}"}
        
        # 重置告警记录
        self.alerts = []
        self.alert_times = {}
        
        # 运行场景
        return self.scenarios[scenario_name](detector, duration, severity)
    
    def run_all_scenarios(self, detector, duration=30):
        """
        运行所有异常场景
        
        Args:
            detector (AnomalyDetector): 异常检测器实例
            duration (int): 每个场景的持续时间（秒）
            
        Returns:
            list: 所有测试结果
        """
        results = []
        severities = ["low", "medium", "high"]
        
        for scenario_name in self.scenarios:
            for severity in severities:
                # 重置告警记录
                self.alerts = []
                self.alert_times = {}
                
                # 运行场景
                result = self.run_scenario(scenario_name, detector, duration, severity)
                results.append(result)
        
        return results


def evaluate_detector_performance(results):
    """
    评估异常检测器性能
    
    Args:
        results (list): 测试结果列表
        
    Returns:
        dict: 评估结果
    """
    # 计算检测率
    total_scenarios = len(results)
    detected_scenarios = sum(1 for r in results if r.get("detected", False))
    detection_rate = detected_scenarios / total_scenarios if total_scenarios > 0 else 0
    
    # 计算响应时间统计
    response_times = [r["response_time"] for r in results if r.get("response_time") is not None]
    avg_response_time = sum(response_times) / len(response_times) if response_times else None
    max_response_time = max(response_times) if response_times else None
    min_response_time = min(response_times) if response_times else None
    
    # 计算达标率
    target_response_time = 180  # 3分钟 = 180秒
    qualified_responses = sum(1 for t in response_times if t <= target_response_time)
    response_time_qualification_rate = qualified_responses / len(response_times) if response_times else 0
    
    # 按严重程度分组
    by_severity = defaultdict(list)
    for result in results:
        severity = result.get("severity")
        if severity:
            by_severity[severity].append(result)
    
    # 计算每个严重程度的检测率
    severity_detection_rates = {}
    for severity, severity_results in by_severity.items():
        total = len(severity_results)
        detected = sum(1 for r in severity_results if r.get("detected", False))
        severity_detection_rates[severity] = detected / total if total > 0 else 0
    
    return {
        "total_scenarios": total_scenarios,
        "detected_scenarios": detected_scenarios,
        "detection_rate": detection_rate,
        "avg_response_time": avg_response_time,
        "max_response_time": max_response_time,
        "min_response_time": min_response_time,
        "response_time_qualification_rate": response_time_qualification_rate,
        "severity_detection_rates": severity_detection_rates
    }


def main():
    """
    主函数
    """
    # 创建异常模拟器
    simulator = AnomalySimulator()
    
    # 创建异常检测器
    detector = AnomalyDetector(alert_callback=simulator._alert_callback)
    
    # 启动监控
    detector.start_monitoring()
    
    try:
        # 运行测试场景
        logger.info("开始运行测试场景...")
        results = simulator.run_all_scenarios(detector, duration=20)  # 缩短测试时间
        
        # 评估性能
        logger.info("评估异常检测器性能...")
        performance = evaluate_detector_performance(results)
        
        # 获取监测覆盖率
        report = detector.generate_anomaly_report()
        report_dict = json.loads(report)
        coverage_ratio = report_dict["coverage"]["coverage_ratio"]
        
        # 打印评估结果
        print("\n异常检测器评估结果:")
        print("-" * 80)
        print(f"总场景数: {performance['total_scenarios']}")
        print(f"检测到的场景数: {performance['detected_scenarios']}")
        print(f"检测率: {performance['detection_rate']:.2%}")
        print(f"监测覆盖率: {coverage_ratio:.2%}")
        print("-" * 80)
        
        print("\n响应时间统计:")
        print("-" * 80)
        if performance["avg_response_time"] is not None:
            print(f"平均响应时间: {performance['avg_response_time']:.2f}秒")
            print(f"最大响应时间: {performance['max_response_time']:.2f}秒")
            print(f"最小响应时间: {performance['min_response_time']:.2f}秒")
            print(f"响应时间达标率: {performance['response_time_qualification_rate']:.2%}")
        else:
            print("无响应时间数据")
        print("-" * 80)
        
        print("\n按严重程度的检测率:")
        print("-" * 80)
        for severity, rate in performance["severity_detection_rates"].items():
            print(f"{severity}: {rate:.2%}")
        print("-" * 80)
        
        # 检查是否达到目标
        coverage_target_achieved = coverage_ratio >= 0.8  # 80%的目标覆盖率
        response_time_target_achieved = performance["response_time_qualification_rate"] == 1.0  # 所有响应时间都在3分钟内
        
        if coverage_target_achieved and response_time_target_achieved:
            print("\n恭喜！网络异常检测模块达到了所有性能目标：")
            print(f"- 监测覆盖率: {coverage_ratio:.2%} (目标: 80%)")
            print(f"- 报警响应时间: 所有场景都在3分钟内响应")
        else:
            print("\n警告：网络异常检测模块未达到所有性能目标：")
            if not coverage_target_achieved:
                print(f"- 监测覆盖率: {coverage_ratio:.2%} (目标: 80%)")
            if not response_time_target_achieved:
                print(f"- 报警响应时间: {performance['response_time_qualification_rate']:.2%}的场景在3分钟内响应 (目标: 100%)")
        
    except KeyboardInterrupt:
        print("\n测试中断")
    finally:
        # 停止监控
        detector.stop_monitoring()


if __name__ == "__main__":
    main()