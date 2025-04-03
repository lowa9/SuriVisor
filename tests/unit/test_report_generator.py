#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ReportGenerator单元测试

测试报告生成器的核心功能，包括多种格式报告的生成和图表生成。
"""

import os
import sys
import unittest
import json
import tempfile
import shutil
from datetime import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.core.report_generator.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """
    ReportGenerator单元测试类
    """
    
    def setUp(self):
        """
        测试前准备
        """
        # 创建临时目录用于测试输出
        self.test_output_dir = tempfile.mkdtemp()
        self.test_template_dir = tempfile.mkdtemp()
        
        # 创建报告生成器实例
        self.report_generator = ReportGenerator(
            output_dir=self.test_output_dir,
            template_dir=self.test_template_dir
        )
        
        # 创建测试数据
        self.test_data = {
            "timestamp": datetime.now().timestamp(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_status": "running",
            "packet_reassembly": {
                "total_packets": 1000,
                "reassembled_packets": 950,
                "lost_packets": 50,
                "out_of_order_packets": 30,
                "reassembly_success_rate": 95.0,
                "avg_reassembly_time": 0.5
            },
            "traffic_analysis": {
                "analyzed_flows": 100,
                "total_traffic": 10.5,
                "avg_flow_size": 105.0,
                "max_flow_size": 500.0,
                "detected_attacks": 2,
                "attacks": [
                    {
                        "type": "port_scan",
                        "confidence": 85,
                        "source_ip": "192.168.1.100",
                        "target_ip": "192.168.1.1",
                        "timestamp": "2023-01-01 12:00:00"
                    },
                    {
                        "type": "brute_force",
                        "confidence": 90,
                        "source_ip": "192.168.1.101",
                        "target_ip": "192.168.1.2",
                        "timestamp": "2023-01-01 12:30:00"
                    }
                ]
            },
            "anomaly_detection": {
                "total_anomalies": 3,
                "anomalies": [
                    {
                        "description": "丢包率",
                        "value": 0.06,
                        "threshold": 0.05,
                        "severity": "medium",
                        "datetime": "2023-01-01 12:05:00"
                    },
                    {
                        "description": "连接失败率",
                        "value": 0.25,
                        "threshold": 0.2,
                        "severity": "high",
                        "datetime": "2023-01-01 12:10:00"
                    },
                    {
                        "description": "SYN洪水检测",
                        "value": 120,
                        "threshold": 100,
                        "severity": "critical",
                        "datetime": "2023-01-01 12:15:00"
                    }
                ]
            },
            "event_manager": {
                "events_received": 500,
                "events_processed": 495,
                "events_dropped": 5,
                "avg_processing_time": 0.002,
                "queue_size": 0,
                "queue_full_percentage": 0.0,
                "events_by_type": {
                    "packet_event": 300,
                    "anomaly_event": 150,
                    "attack_event": 50
                }
            }
        }
        
        # 创建简单的HTML模板用于测试
        self.test_template = """<!DOCTYPE html>
<html>
<head>
    <title>Test Report</title>
</head>
<body>
    <h1>Test Report</h1>
    <p>Generated at: {{ metadata.generated_at }}</p>
    <p>System Status: {{ data.system_status }}</p>
</body>
</html>"""
        
        with open(os.path.join(self.test_template_dir, "report.html"), "w") as f:
            f.write(self.test_template)
    
    def tearDown(self):
        """
        测试后清理
        """
        # 删除临时目录
        shutil.rmtree(self.test_output_dir)
        shutil.rmtree(self.test_template_dir)
    
    def test_generate_json_report(self):
        """
        测试生成JSON格式报告
        """
        # 生成报告
        output_file = os.path.join(self.test_output_dir, "test_report.json")
        result = self.report_generator.generate_report(
            data=self.test_data,
            report_type="json",
            output_file=output_file
        )
        
        # 验证报告文件已创建
        self.assertTrue(os.path.exists(output_file))
        self.assertEqual(result, output_file)
        
        # 验证报告内容
        with open(output_file, "r") as f:
            report_data = json.load(f)
        
        self.assertTrue("metadata" in report_data)
        self.assertTrue("data" in report_data)
        self.assertEqual(report_data["data"]["system_status"], "running")
        self.assertEqual(report_data["data"]["packet_reassembly"]["total_packets"], 1000)
    
    def test_generate_html_report(self):
        """
        测试生成HTML格式报告
        """
        # 生成报告
        output_file = os.path.join(self.test_output_dir, "test_report.html")
        result = self.report_generator.generate_report(
            data=self.test_data,
            report_type="html",
            output_file=output_file
        )
        
        # 验证报告文件已创建
        self.assertTrue(os.path.exists(output_file))
        self.assertEqual(result, output_file)
        
        # 验证报告内容
        with open(output_file, "r") as f:
            html_content = f.read()
        
        self.assertIn("<!DOCTYPE html>", html_content)
        self.assertIn("Test Report", html_content)
        self.assertIn("System Status: running", html_content)
    
    def test_generate_csv_report(self):
        """
        测试生成CSV格式报告
        """
        # 生成报告
        output_file = os.path.join(self.test_output_dir, "test_report.csv")
        result = self.report_generator.generate_report(
            data=self.test_data,
            report_type="csv",
            output_file=output_file,
            options={"data_path": "traffic_analysis.attacks"}
        )
        
        # 验证报告文件已创建
        self.assertTrue(os.path.exists(output_file))
        self.assertEqual(result, output_file)
        
        # 验证报告内容
        with open(output_file, "r") as f:
            csv_content = f.read()
        
        self.assertIn("type,confidence,source_ip,target_ip,timestamp", csv_content)
        self.assertIn("port_scan,85,192.168.1.100,192.168.1.1,2023-01-01 12:00:00", csv_content)
    
    def test_generate_pdf_report(self):
        """
        测试生成PDF格式报告
        """
        # 尝试生成PDF报告，如果没有安装weasyprint，应该生成HTML报告
        output_file = os.path.join(self.test_output_dir, "test_report.pdf")
        result = self.report_generator.generate_report(
            data=self.test_data,
            report_type="pdf",
            output_file=output_file
        )
        
        # 验证报告文件已创建（可能是PDF或HTML）
        self.assertTrue(os.path.exists(result))
    
    def test_generate_bar_chart(self):
        """
        测试生成柱状图
        """
        # 准备图表数据
        chart_data = {
            "TCP": 500,
            "UDP": 300,
            "ICMP": 100,
            "Other": 50
        }
        
        # 生成图表
        output_file = os.path.join(self.test_output_dir, "test_chart.png")
        result = self.report_generator.generate_charts(
            data=chart_data,
            chart_type="bar",
            output_file=output_file,
            options={
                "title": "协议分布",
                "xlabel": "协议",
                "ylabel": "数据包数"
            }
        )
        
        # 验证图表文件已创建
        self.assertTrue(os.path.exists(output_file))
        self.assertEqual(result, output_file)
    
    def test_generate_pie_chart(self):
        """
        测试生成饼图
        """
        # 准备图表数据
        chart_data = {
            "正常流量": 800,
            "可疑流量": 150,
            "恶意流量": 50
        }
        
        # 生成图表
        output_file = os.path.join(self.test_output_dir, "test_pie.png")
        result = self.report_generator.generate_charts(
            data=chart_data,
            chart_type="pie",
            output_file=output_file,
            options={"title": "流量分类"}
        )
        
        # 验证图表文件已创建
        self.assertTrue(os.path.exists(output_file))
        self.assertEqual(result, output_file)
    
    def test_get_statistics(self):
        """
        测试获取统计信息
        """
        # 生成一些报告
        self.report_generator.generate_report(
            data=self.test_data,
            report_type="json"
        )
        self.report_generator.generate_report(
            data=self.test_data,
            report_type="html"
        )
        
        # 获取统计信息
        stats = self.report_generator.get_statistics()
        
        # 验证统计信息
        self.assertEqual(stats["reports_generated"], 2)
        self.assertEqual(stats["reports_by_type"]["json"], 1)
        self.assertEqual(stats["reports_by_type"]["html"], 1)
        self.assertTrue("avg_generation_time" in stats)
    
    def test_clear_statistics(self):
        """
        测试清除统计信息
        """
        # 生成一些报告
        self.report_generator.generate_report(
            data=self.test_data,
            report_type="json"
        )
        
        # 清除统计信息
        self.report_generator.clear_statistics()
        
        # 验证统计信息已清除
        stats = self.report_generator.get_statistics()
        self.assertEqual(stats["reports_generated"], 0)
        self.assertEqual(len(stats["reports_by_type"]), 0)


if __name__ == "__main__":
    unittest.main()