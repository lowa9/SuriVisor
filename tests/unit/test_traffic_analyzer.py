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
from collections import defaultdict

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), '../../src'))

from core.traffic_analysis.traffic_analyzer import TrafficAnalyzer

class TestTrafficAnalyzer(unittest.TestCase):
    def setUp(self):
        """每个测试用例前的设置"""
        self.analyzer = TrafficAnalyzer()
    
    def test_initialization(self):
        """测试流量分析器初始化"""
        # 验证默认攻击模式是否正确加载
        self.assertIn("port_scan", self.analyzer.attack_patterns)
        self.assertIn("ddos", self.analyzer.attack_patterns)
        self.assertIn("brute_force", self.analyzer.attack_patterns)
        self.assertIn("arp_spoofing", self.analyzer.attack_patterns)
        self.assertIn("data_exfiltration", self.analyzer.attack_patterns)
        
        # 验证数据结构是否正确初始化
        self.assertIsInstance(self.analyzer.flow_features, defaultdict)
        self.assertIsInstance(self.analyzer.classified_flows, dict)
    
    def test_load_save_attack_patterns(self):
        """测试攻击模式库的加载和保存"""
        # 创建临时文件路径
        temp_file_path = tempfile.mktemp()
        
        try:
            # 保存当前攻击模式库
            result = self.analyzer.save_attack_patterns(temp_file_path)
            self.assertTrue(result)
            
            # 验证文件是否创建
            self.assertTrue(os.path.exists(temp_file_path))
            
            # 创建新的分析器实例并加载保存的模式库
            new_analyzer = TrafficAnalyzer(attack_patterns_file=temp_file_path)
            
            # 验证加载的模式库是否与原始模式库一致
            self.assertEqual(len(new_analyzer.attack_patterns), len(self.analyzer.attack_patterns))
            for attack_type in self.analyzer.attack_patterns:
                self.assertIn(attack_type, new_analyzer.attack_patterns)
        finally:
            # 清理临时文件
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    def test_extract_features_port_scan(self):
        """测试端口扫描流量的特征提取"""
        # 模拟端口扫描流量
        port_scan_packets = []
        base_time = time.time()
        for i in range(100):
            packet = {
                "timestamp": base_time + i * 0.1,
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "src_port": 12345,
                "dst_port": 1000 + i,  # 不同的目标端口
                "protocol": "TCP",
                "size": 60,
                "flags": {"syn": True, "ack": False}
            }
            port_scan_packets.append(packet)
        
        # 提取特征
        flow_id = "port_scan_flow"
        features = self.analyzer.extract_features(flow_id, port_scan_packets)
        
        # 验证特征值
        self.assertEqual(features["packet_count"], 100)
        self.assertEqual(features["unique_ports"], 101)  # 源端口 + 100个目标端口
        self.assertEqual(features["unique_sources"], 1)
        self.assertEqual(features["unique_destinations"], 1)
        self.assertAlmostEqual(features["avg_packet_size"], 60.0)
        self.assertGreaterEqual(features["packets_per_second"], 5)  # 100个包在10秒内
        self.assertAlmostEqual(features["syn_ratio"], 1.0)  # 所有包都是SYN
        
        # 验证特征是否保存到分析器中
        self.assertIn(flow_id, self.analyzer.flow_features)
        self.assertEqual(self.analyzer.flow_features[flow_id], features)
    
    def test_extract_features_ddos(self):
        """测试DDoS流量的特征提取"""
        # 模拟DDoS流量
        ddos_packets = []
        base_time = time.time()
        for i in range(1000):  # 大量数据包
            src_ip = f"192.168.1.{i % 50 + 10}"  # 多个源IP
            packet = {
                "timestamp": base_time + i * 0.01,  # 高频率
                "src_ip": src_ip,
                "dst_ip": "192.168.1.1",
                "src_port": 12345 + (i % 10),
                "dst_port": 80,
                "protocol": "TCP",
                "size": 60,
                "flags": {"syn": True, "ack": False}
            }
            ddos_packets.append(packet)
        
        # 提取特征
        flow_id = "ddos_flow"
        features = self.analyzer.extract_features(flow_id, ddos_packets)
        
        # 验证特征值
        self.assertEqual(features["packet_count"], 1000)
        self.assertGreaterEqual(features["unique_sources"], 50)  # 至少50个不同的源IP
        self.assertGreaterEqual(features["packets_per_second"], 100)  # 1000个包在10秒内
        self.assertAlmostEqual(features["syn_ratio"], 1.0)  # 所有包都是SYN
    
    def test_extract_features_brute_force(self):
        """测试暴力破解流量的特征提取"""
        # 模拟暴力破解流量
        brute_force_packets = []
        base_time = time.time()
        for i in range(100):
            packet = {
                "timestamp": base_time + i * 0.5,  # 每0.5秒一个请求
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "src_port": 12345,
                "dst_port": 22,  # SSH端口
                "protocol": "TCP",
                "size": 200,
                "flags": {"syn": i % 10 == 0, "ack": i % 10 != 0}
            }
            brute_force_packets.append(packet)
        
        # 创建登录尝试元数据
        metadata = {
            "login_attempts": [
                {"timestamp": base_time + i * 0.5, "username": f"user{i % 5}", "success": i % 10 == 0}
                for i in range(100)
            ]
        }
        
        # 提取特征
        flow_id = "brute_force_flow"
        features = self.analyzer.extract_features(flow_id, brute_force_packets, metadata)
        
        # 验证特征值
        self.assertEqual(features["packet_count"], 100)
        self.assertAlmostEqual(features["failed_login_ratio"], 0.9, delta=0.1)  # 90%的登录失败
        self.assertGreaterEqual(features["login_attempts_per_minute"], 10)  # 每分钟至少10次尝试
        self.assertEqual(features["unique_usernames"], 5)  # 5个不同的用户名
        self.assertLessEqual(features["avg_request_interval"], 5)  # 平均请求间隔小于5秒
    
    def test_classify_flow_port_scan(self):
        """测试端口扫描流量的分类"""
        # 模拟端口扫描特征
        features = {
            "unique_ports": 100,
            "packets_per_second": 10,
            "avg_packet_size": 60,
            "syn_ratio": 0.9
        }
        
        # 分类流量
        flow_id = "port_scan_test"
        result = self.analyzer.classify_flow(flow_id, features)
        
        # 验证分类结果
        self.assertEqual(result["type"], "port_scan")
        self.assertGreaterEqual(result["confidence"], 0.6)  # 置信度至少60%
        self.assertIn("details", result)
        self.assertIn("description", result["details"])
        self.assertIn("matched_features", result["details"])
        
        # 验证分类结果是否保存到分析器中
        self.assertIn(flow_id, self.analyzer.classified_flows)
        self.assertEqual(self.analyzer.classified_flows[flow_id], result)
    
    def test_classify_flow_ddos(self):
        """测试DDoS流量的分类"""
        # 模拟DDoS特征
        features = {
            "packets_per_second": 200,
            "unique_sources": 50,
            "syn_ratio": 0.8,
            "avg_packet_size": 60
        }
        
        # 分类流量
        flow_id = "ddos_test"
        result = self.analyzer.classify_flow(flow_id, features)
        
        # 验证分类结果
        self.assertEqual(result["type"], "ddos")
        self.assertGreaterEqual(result["confidence"], 0.6)  # 置信度至少60%
    
    def test_classify_flow_brute_force(self):
        """测试暴力破解流量的分类"""
        # 模拟暴力破解特征
        features = {
            "failed_login_ratio": 0.8,
            "login_attempts_per_minute": 20,
            "unique_usernames": 5,
            "avg_request_interval": 3
        }
        
        # 分类流量
        flow_id = "brute_force_test"
        result = self.analyzer.classify_flow(flow_id, features)
        
        # 验证分类结果
        self.assertEqual(result["type"], "brute_force")
        self.assertGreaterEqual(result["confidence"], 0.6)  # 置信度至少60%
    
    def test_classify_flow_normal(self):
        """测试正常流量的分类"""
        # 模拟正常流量特征（所有特征值都低于攻击阈值）
        features = {
            "unique_ports": 2,
            "packets_per_second": 1,
            "avg_packet_size": 1024,
            "syn_ratio": 0.1,
            "failed_login_ratio": 0.1,
            "login_attempts_per_minute": 1,
            "unique_usernames": 1,
            "avg_request_interval": 10,
            "arp_requests_per_second": 0.1,
            "ip_mac_pairs": 0,
            "gratuitous_arp_ratio": 0,
            "arp_reply_without_request": 0,
            "outbound_data_volume": 1000,
            "unusual_destination": 0,
            "unusual_protocol": 0,
            "unusual_time": 0
        }
        
        # 分类流量
        flow_id = "normal_test"
        result = self.analyzer.classify_flow(flow_id, features)
        
        # 验证分类结果
        self.assertEqual(result["type"], "normal")
        self.assertGreaterEqual(result["confidence"], 0.6)  # 置信度至少60%
    
    def test_analyze_traffic(self):
        """测试流量分析功能"""
        # 模拟多种流量
        flows = {
            "port_scan_flow": {
                "packets": [
                    {
                        "timestamp": time.time() + i * 0.1,
                        "src_ip": "192.168.1.100",
                        "dst_ip": "192.168.1.1",
                        "src_port": 12345,
                        "dst_port": 1000 + i,
                        "protocol": "TCP",
                        "size": 60,
                        "flags": {"syn": True, "ack": False}
                    } for i in range(100)
                ]
            },
            "normal_flow": {
                "packets": [
                    {
                        "timestamp": time.time() + i * 1.0,
                        "src_ip": "192.168.1.101",
                        "dst_ip": "192.168.1.2",
                        "src_port": 54321,
                        "dst_port": 80,
                        "protocol": "TCP",
                        "size": 1024,
                        "flags": {"syn": i < 1, "ack": i >= 1}
                    } for i in range(10)
                ]
            }
        }
        
        # 分析流量
        results = self.analyzer.analyze_traffic(flows)
        
        # 验证结果
        self.assertEqual(len(results), 2)  # 两个流
        self.assertIn("port_scan_flow", results)
        self.assertIn("normal_flow", results)
        
        # 验证端口扫描流的分类结果
        port_scan_result = results["port_scan_flow"]
        self.assertIn("classification", port_scan_result)
        self.assertIn("features", port_scan_result)
        self.assertEqual(port_scan_result["classification"]["type"], "port_scan")
        
        # 验证正常流的分类结果
        normal_result = results["normal_flow"]
        self.assertIn("classification", normal_result)
        self.assertIn("features", normal_result)
        self.assertEqual(normal_result["classification"]["type"], "normal")
    
    def test_get_statistics(self):
        """测试统计信息获取功能"""
        # 添加一些分类结果
        self.analyzer.classified_flows = {
            "flow1": {"type": "port_scan", "confidence": 0.8},
            "flow2": {"type": "ddos", "confidence": 0.9},
            "flow3": {"type": "normal", "confidence": 0.7},
            "flow4": {"type": "normal", "confidence": 0.8},
            "flow5": {"type": "brute_force", "confidence": 0.7}
        }
        
        # 获取统计信息
        stats = self.analyzer.get_statistics()
        
        # 验证统计信息
        self.assertEqual(stats["total_flows"], 5)
        self.assertEqual(stats["attack_flows"], 3)  # 3个攻击流
        self.assertEqual(stats["normal_flows"], 2)  # 2个正常流
        self.assertEqual(len(stats["attack_types"]), 3)  # 3种攻击类型
        self.assertEqual(stats["attack_types"]["port_scan"], 1)
        self.assertEqual(stats["attack_types"]["ddos"], 1)
        self.assertEqual(stats["attack_types"]["brute_force"], 1)
        self.assertAlmostEqual(stats["attack_ratio"], 0.6)  # 攻击比例为60%
    
    def test_generate_report(self):
        """测试报告生成功能"""
        # 添加一些分类结果
        self.analyzer.classified_flows = {
            "flow1": {"type": "port_scan", "confidence": 0.8, "details": {"description": "端口扫描攻击"}},
            "flow2": {"type": "normal", "confidence": 0.7}
        }
        
        # 生成报告（不保存到文件）
        report_str = self.analyzer.generate_report()
        
        # 验证报告内容
        # 确保report_str是字符串类型
        if isinstance(report_str, str):
            report = json.loads(report_str)
        else:
            raise TypeError("report_str必须是字符串类型")
        self.assertIn("timestamp", report)
        self.assertIn("datetime", report)
        self.assertIn("statistics", report)
        self.assertIn("detected_attacks", report)
        self.assertEqual(len(report["detected_attacks"]), 1)  # 1个检测到的攻击
        self.assertEqual(report["detected_attacks"][0]["attack_type"], "port_scan")
        
        # 测试保存到文件
        temp_file_path = tempfile.mktemp()
        try:
            # 保存报告
            result = self.analyzer.generate_report(output_file=temp_file_path)
            self.assertTrue(result)
            
            # 验证文件是否创建
            self.assertTrue(os.path.exists(temp_file_path))
            
            # 验证文件内容
            with open(temp_file_path, 'r') as f:
                saved_report = json.load(f)
            
            self.assertIn("statistics", saved_report)
            self.assertIn("detected_attacks", saved_report)
        finally:
            # 清理临时文件
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
    
    def test_classification_accuracy(self):
        """测试分类准确率是否达到60%以上"""
        # 创建各种类型的流量样本
        flow_samples = {
            # 端口扫描样本 (应该被正确分类为port_scan)
            "port_scan_1": {"unique_ports": 100, "packets_per_second": 10, "avg_packet_size": 60, "syn_ratio": 0.9},
            "port_scan_2": {"unique_ports": 50, "packets_per_second": 8, "avg_packet_size": 70, "syn_ratio": 0.85},
            
            # DDoS样本 (应该被正确分类为ddos)
            "ddos_1": {"packets_per_second": 200, "unique_sources": 50, "syn_ratio": 0.8, "avg_packet_size": 60},
            "ddos_2": {"packets_per_second": 150, "unique_sources": 30, "syn_ratio": 0.75, "avg_packet_size": 80},
            
            # 暴力破解样本 (应该被正确分类为brute_force)
            "brute_force_1": {"failed_login_ratio": 0.8, "login_attempts_per_minute": 20, "unique_usernames": 5, "avg_request_interval": 3},
            "brute_force_2": {"failed_login_ratio": 0.7, "login_attempts_per_minute": 15, "unique_usernames": 4, "avg_request_interval": 4},
            
            # ARP欺骗样本 (应该被正确分类为arp_spoofing)
            "arp_spoofing_1": {"arp_requests_per_second": 10, "ip_mac_pairs": 5, "gratuitous_arp_ratio": 0.6, "arp_reply_without_request": 5},
            "arp_spoofing_2": {"arp_requests_per_second": 8, "ip_mac_pairs": 3, "gratuitous_arp_ratio": 0.55, "arp_reply_without_request": 4},
            
            # 数据泄露样本 (应该被正确分类为data_exfiltration)
            "data_exfiltration_1": {"outbound_data_volume": 2000000, "unusual_destination": 0.8, "unusual_protocol": 0.8, "unusual_time": 1},
            "data_exfiltration_2": {"outbound_data_volume": 1500000, "unusual_destination": 0.75, "unusual_protocol": 0.75, "unusual_time": 1},
            
            # 正常流量样本 (应该被正确分类为normal)
            "normal_1": {"unique_ports": 2, "packets_per_second": 1, "avg_packet_size": 1024, "syn_ratio": 0.1},
            "normal_2": {"unique_ports": 3, "packets_per_second": 2, "avg_packet_size": 1500, "syn_ratio": 0.05},
            
            # 边界情况 (可能被错误分类)
            "borderline_1": {"unique_ports": 9, "packets_per_second": 4, "avg_packet_size": 110, "syn_ratio": 0.75},
            "borderline_2": {"packets_per_second": 90, "unique_sources": 4, "syn_ratio": 0.65, "avg_packet_size": 210}
        }
        
        # 预期的分类结果
        expected_classifications = {
            "port_scan_1": "port_scan",
            "port_scan_2": "port_scan",
            "ddos_1": "ddos",
            "ddos_2": "ddos",
            "brute_force_1": "brute_force",
            "brute_force_2": "brute_force",
            "arp_spoofing_1": "arp_spoofing",
            "arp_spoofing_2": "arp_spoofing",
            "data_exfiltration_1": "data_exfiltration",
            "data_exfiltration_2": "data_exfiltration",
            "normal_1": "normal",
            "normal_2": "normal",
            # 边界情况不计入准确率计算
        }
        
        # 分类所有样本
        correct_count = 0
        total_count = len(expected_classifications)
        
        for flow_id, features in flow_samples.items():
            result = self.analyzer.classify_flow(flow_id, features)
            
            # 如果是预期分类的样本，检查分类是否正确
            if flow_id in expected_classifications:
                expected_type = expected_classifications[flow_id]
                if result["type"] == expected_type:
                    correct_count += 1
        
        # 计算准确率
        accuracy = correct_count / total_count
        print(f"分类准确率: {accuracy:.2%}")
        
        # 验证准确率是否达到60%以上
        self.assertGreaterEqual(accuracy, 0.6, "分类准确率未达到60%")


if __name__ == '__main__':
    unittest.main()