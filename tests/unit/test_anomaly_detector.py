#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
import os
import json
import time
import tempfile
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
from collections import deque

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), '../../src'))

from core.anomaly_detection.anomaly_detector import AnomalyDetector

class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        """每个测试用例前的设置"""
        self.alert_callback = MagicMock()
        self.detector = AnomalyDetector(alert_callback=self.alert_callback)
    
    def test_initialization(self):
        """测试异常检测器初始化"""
        # 验证默认配置是否正确加载
        self.assertIn("metrics", self.detector.config)
        self.assertIn("alert", self.detector.config)
        self.assertIn("monitoring", self.detector.config)
        
        # 验证指标数据结构是否正确初始化
        for metric_name in self.detector.config["metrics"]:
            if self.detector.config["metrics"][metric_name]["enabled"]:
                self.assertIn(metric_name, self.detector.metrics_data)
                self.assertIn("values", self.detector.metrics_data[metric_name])
                self.assertIn("alerts", self.detector.metrics_data[metric_name])
                self.assertIn("status", self.detector.metrics_data[metric_name])
    
    def test_load_config(self):
        """测试配置加载功能"""
        # 创建临时配置文件
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            test_config = {
                "metrics": {
                    "test_metric": {
                        "description": "测试指标",
                        "threshold": 0.1,
                        "window_size": 100,
                        "severity": "high",
                        "enabled": True
                    }
                },
                "alert": {
                    "min_interval": 60
                }
            }
            json.dump(test_config, temp_file)
            temp_file_path = temp_file.name
        
        try:
            # 加载配置
            result = self.detector.load_config(temp_file_path)
            self.assertTrue(result)
            
            # 验证配置是否正确加载
            self.assertIn("test_metric", self.detector.config["metrics"])
            self.assertEqual(self.detector.config["metrics"]["test_metric"]["threshold"], 0.1)
            self.assertEqual(self.detector.config["alert"]["min_interval"], 60)
        finally:
            # 清理临时文件
            os.unlink(temp_file_path)
    
    def test_save_config(self):
        """测试配置保存功能"""
        # 创建临时文件路径
        temp_file_path = tempfile.mktemp()
        
        try:
            # 保存配置
            result = self.detector.save_config(temp_file_path)
            self.assertTrue(result)
            
            # 验证文件是否创建
            self.assertTrue(os.path.exists(temp_file_path))
            
            # 验证内容是否正确
            with open(temp_file_path, 'r') as f:
                saved_config = json.load(f)
            
            self.assertEqual(saved_config, self.detector.config)
        finally:
            # 清理临时文件
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    def test_update_metric(self):
        """测试指标更新功能"""
        # 测试更新有效指标
        metric_name = "packet_loss_ratio"
        result = self.detector.update_metric(metric_name, 0.03)
        self.assertTrue(result)
        self.assertEqual(self.detector.metrics_data[metric_name]["current_value"], 0.03)
        self.assertEqual(list(self.detector.metrics_data[metric_name]["values"])[-1], 0.03)
        
        # 测试更新无效指标
        result = self.detector.update_metric("invalid_metric", 0.5)
        self.assertFalse(result)
    
    def test_threshold_check(self):
        """测试阈值检测功能"""
        metric_name = "packet_loss_ratio"
        threshold = self.detector.config["metrics"][metric_name]["threshold"]
        
        # 测试低于阈值的情况
        self.detector.update_metric(metric_name, threshold - 0.01)
        self.assertEqual(self.detector.metrics_data[metric_name]["status"], "normal")
        
        # 测试超过阈值的情况
        self.detector.update_metric(metric_name, threshold + 0.01)
        self.assertEqual(self.detector.metrics_data[metric_name]["status"], "alert")
    
    def test_alert_trigger(self):
        """测试告警触发功能"""
        metric_name = "packet_loss_ratio"
        threshold = self.detector.config["metrics"][metric_name]["threshold"]
        
        # 触发告警
        self.detector.update_metric(metric_name, threshold + 0.1)
        
        # 验证告警回调是否被调用
        self.alert_callback.assert_called_once()
        
        # 验证告警历史是否记录
        self.assertEqual(len(self.detector.alert_history), 1)
        self.assertEqual(self.detector.alert_history[0]["metric"], metric_name)
        self.assertEqual(self.detector.alert_history[0]["status"], "active")
    
    def test_alert_recovery(self):
        """测试告警恢复功能"""
        metric_name = "packet_loss_ratio"
        threshold = self.detector.config["metrics"][metric_name]["threshold"]
        
        # 先触发告警
        self.detector.update_metric(metric_name, threshold + 0.1)
        self.assertEqual(self.detector.metrics_data[metric_name]["status"], "alert")
        
        # 然后恢复正常
        self.detector.update_metric(metric_name, threshold - 0.1)
        self.assertEqual(self.detector.metrics_data[metric_name]["status"], "normal")
        
        # 验证告警状态是否更新
        self.assertEqual(self.detector.alert_history[0]["status"], "resolved")
    
    def test_alert_suppression(self):
        """测试告警抑制功能"""
        metric_name = "packet_loss_ratio"
        threshold = self.detector.config["metrics"][metric_name]["threshold"]
        
        # 设置最小告警间隔
        self.detector.config["alert"]["min_interval"] = 10
        
        # 第一次触发告警
        self.detector.update_metric(metric_name, threshold + 0.1)
        self.alert_callback.reset_mock()
        
        # 立即再次触发告警，应该被抑制
        self.detector.update_metric(metric_name, threshold + 0.2)
        self.alert_callback.assert_not_called()
    
    @patch('time.time')
    def test_monitoring_report(self, mock_time):
        """测试监控报告生成"""
        # 模拟时间
        mock_time.return_value = 1000
        
        # 更新一些指标
        self.detector.update_metric("packet_loss_ratio", 0.03)
        self.detector.update_metric("rtt_variation", 0.2)
        
        # 生成报告
        report = self.detector._generate_report()
        
        # 验证报告内容
        self.assertIn("metrics", report)
        self.assertIn("packet_loss_ratio", report["metrics"])
        self.assertIn("rtt_variation", report["metrics"])
        self.assertIn("coverage", report)
        self.assertIn("coverage_ratio", report["coverage"])
    
    def test_learning_mode(self):
        """测试学习模式"""
        # 启动学习模式
        result = self.detector.start_learning_mode(duration=1)
        self.assertTrue(result)
        self.assertTrue(self.detector.learning_mode)
        
        # 添加一些测试数据
        metric_name = "packet_loss_ratio"
        self.detector.update_metric(metric_name, 0.01)
        self.detector.update_metric(metric_name, 0.02)
        self.detector.update_metric(metric_name, 0.03)
        
        # 验证学习数据是否记录
        self.assertEqual(len(self.detector.learning_data[metric_name]), 3)
        
        # 模拟学习完成
        old_threshold = self.detector.config["metrics"][metric_name]["threshold"]
        self.detector._finish_learning()
        
        # 验证阈值是否调整
        self.assertFalse(self.detector.learning_mode)
        self.assertNotEqual(self.detector.config["metrics"][metric_name]["threshold"], old_threshold)
    
    def test_get_active_alerts(self):
        """测试获取活跃告警"""
        # 触发两个不同指标的告警
        self.detector.update_metric("packet_loss_ratio", 0.1)
        self.detector.update_metric("connection_failure_rate", 0.3)
        
        # 获取活跃告警
        active_alerts = self.detector.get_active_alerts()
        
        # 验证活跃告警数量
        self.assertEqual(len(active_alerts), 2)
    
    def test_get_metric_status(self):
        """测试获取指标状态"""
        # 更新指标
        metric_name = "packet_loss_ratio"
        self.detector.update_metric(metric_name, 0.03)
        
        # 获取单个指标状态
        status = self.detector.get_metric_status(metric_name)
        self.assertEqual(status["name"], metric_name)
        self.assertEqual(status["current_value"], 0.03)
        
        # 获取所有指标状态
        all_status = self.detector.get_metric_status()
        self.assertIsInstance(all_status, dict)
        self.assertIn(metric_name, all_status)

if __name__ == '__main__':
    unittest.main()