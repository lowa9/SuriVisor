#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SuriVisor - 基于Suricata的威胁分析系统

该文件是系统的主入口，负责初始化各个组件并协调它们之间的交互。
"""

import os
import sys
import time
import logging
import argparse
import json
import threading
from datetime import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入核心模块
from src.core.packet_reassembly.packet_reassembler import PacketReassembler
from src.core.traffic_analysis.traffic_analyzer import TrafficAnalyzer
from src.core.anomaly_detection.anomaly_detector import AnomalyDetector

# 配置日志
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   handlers=[
                       logging.FileHandler(os.path.join(os.path.dirname(__file__), '../logs/surivisor.log')),
                       logging.StreamHandler()
                   ])
logger = logging.getLogger("SuriVisor")


class SuriVisor:
    """
    SuriVisor系统主类
    
    负责初始化各个组件并协调它们之间的交互。
    """
    
    def __init__(self, config_file=None):
        """
        初始化SuriVisor系统
        
        Args:
            config_file (str): 配置文件路径
        """
        # 默认配置
        self.config = {
            "general": {
                "debug": False,
                "log_level": "INFO",
                "data_dir": os.path.join(os.path.dirname(__file__), '../data')
            },
            "suricata": {
                "binary_path": "/usr/bin/suricata",
                "config_path": os.path.join(os.path.dirname(__file__), '../config/suricata.yaml'),
                "rule_path": "/etc/suricata/rules"
            },
            "analysis": {
                "packet_reassembly_enabled": True,
                "anomaly_detection_enabled": True,
                "traffic_analysis_enabled": True
            },
            "ui": {
                "web_server_port": 8080,
                "dashboard_enabled": True,
                "report_generation_enabled": True
            }
        }
        
        # 加载配置文件
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
        
        # 确保日志目录存在
        os.makedirs(os.path.join(os.path.dirname(__file__), '../logs'), exist_ok=True)
        
        # 设置日志级别
        log_level = getattr(logging, self.config["general"]["log_level"].upper(), logging.INFO)
        logging.getLogger().setLevel(log_level)
        
        # 初始化组件
        self.packet_reassembler = None
        self.traffic_analyzer = None
        self.anomaly_detector = None
        
        # 系统状态
        self.running = False
        self.processing_thread = None
        
        logger.info("SuriVisor系统初始化完成")
    
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
    
    def initialize_components(self):
        """
        初始化系统组件
        
        Returns:
            bool: 初始化是否成功
        """
        try:
            # 初始化数据包重组器
            if self.config["analysis"]["packet_reassembly_enabled"]:
                logger.info("初始化数据包重组器...")
                self.packet_reassembler = PacketReassembler(
                    timeout=30,
                    max_fragments=1000,
                    buffer_size=10485760
                )
            
            # 初始化流量分析器
            if self.config["analysis"]["traffic_analysis_enabled"]:
                logger.info("初始化流量分析器...")
                attack_patterns_file = os.path.join(self.config["general"]["data_dir"], "attack_patterns.json")
                self.traffic_analyzer = TrafficAnalyzer(attack_patterns_file=attack_patterns_file)
            
            # 初始化异常检测器
            if self.config["analysis"]["anomaly_detection_enabled"]:
                logger.info("初始化异常检测器...")
                anomaly_config_file = os.path.join(os.path.dirname(__file__), '../config/anomaly_detection.json')
                self.anomaly_detector = AnomalyDetector(
                    config_file=anomaly_config_file,
                    alert_callback=self.handle_alert
                )
            
            logger.info("所有组件初始化完成")
            return True
        except Exception as e:
            logger.error(f"初始化组件失败: {e}")
            return False
    
    def handle_alert(self, alert_info):
        """
        处理告警信息
        
        Args:
            alert_info (dict): 告警信息
        """
        logger.warning(f"收到告警: {alert_info['description']} - 值: {alert_info['value']:.4f}, 阈值: {alert_info['threshold']:.4f}")
        
        # TODO: 实现更多告警处理逻辑，如发送邮件、短信等
        
        # 保存告警到文件
        alerts_dir = os.path.join(self.config["general"]["data_dir"], "alerts")
        os.makedirs(alerts_dir, exist_ok=True)
        
        alert_file = os.path.join(alerts_dir, f"alert_{int(time.time())}.json")
        try:
            with open(alert_file, 'w') as f:
                json.dump(alert_info, f, indent=4)
        except Exception as e:
            logger.error(f"保存告警信息失败: {e}")
    
    def start(self):
        """
        启动系统
        
        Returns:
            bool: 启动是否成功
        """
        if self.running:
            logger.warning("系统已经在运行")
            return False
        
        # 初始化组件
        if not self.initialize_components():
            return False
        
        # 启动异常检测
        if self.anomaly_detector:
            self.anomaly_detector.start_monitoring()
        
        # 设置运行状态
        self.running = True
        self.processing_thread = threading.Thread(target=self._processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
        logger.info("SuriVisor系统已启动")
        return True
    
    def stop(self):
        """
        停止系统
        
        Returns:
            bool: 停止是否成功
        """
        if not self.running:
            logger.warning("系统未在运行")
            return False
        
        # 设置停止标志
        self.running = False
        
        # 停止异常检测
        if self.anomaly_detector:
            self.anomaly_detector.stop_monitoring()
        
        # 等待处理线程结束
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
        
        logger.info("SuriVisor系统已停止")
        return True
    
    def _processing_loop(self):
        """
        主处理循环
        """
        while self.running:
            try:
                # TODO: 实现实时流量处理逻辑
                
                # 临时休眠，避免CPU占用过高
                time.sleep(1)
            except Exception as e:
                logger.error(f"处理循环异常: {e}")
    
    def process_pcap_file(self, pcap_file):
        """
        处理PCAP文件
        
        Args:
            pcap_file (str): PCAP文件路径
            
        Returns:
            dict: 处理结果
        """
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP文件不存在: {pcap_file}")
            return {"error": "文件不存在"}
        
        logger.info(f"开始处理PCAP文件: {pcap_file}")
        
        # TODO: 实现PCAP文件解析和处理逻辑
        # 这里需要使用pyshark或scapy等库解析PCAP文件，然后将数据包送入处理流程
        
        return {"status": "success", "message": "PCAP文件处理完成"}
    
    def generate_report(self, output_file=None):
        """
        生成系统报告
        
        Args:
            output_file (str): 输出文件路径，如果为None则返回报告内容
            
        Returns:
            str or bool: 如果output_file为None，返回报告内容；否则返回是否成功写入文件
        """
        # 收集各组件的报告
        report = {
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_status": "running" if self.running else "stopped"
        }
        
        # 添加数据包重组器报告
        if self.packet_reassembler:
            report["packet_reassembly"] = self.packet_reassembler.get_reassembly_statistics()
        
        # 添加流量分析器报告
        if self.traffic_analyzer:
            report["traffic_analysis"] = self.traffic_analyzer.get_statistics()
        
        # 添加异常检测器报告
        if self.anomaly_detector:
            anomaly_report = self.anomaly_detector.generate_anomaly_report()
            # 确保 anomaly_report 是字符串类型
            if isinstance(anomaly_report, str):
                report["anomaly_detection"] = json.loads(anomaly_report)
            else:
                report["anomaly_detection"] = anomaly_report
        
        # 如果指定了输出文件，写入文件
        if output_file:
            try:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=4)
                logger.info(f"系统报告已保存到{output_file}")
                return True
            except Exception as e:
                logger.error(f"保存系统报告失败: {e}")
                return False
        
        # 否则返回报告内容
        return json.dumps(report, indent=4)


def main():
    """
    主函数
    """
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="SuriVisor - 基于Suricata的威胁分析系统")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("-p", "--pcap", help="要处理的PCAP文件路径")
    parser.add_argument("-r", "--report", help="生成报告并保存到指定路径")
    parser.add_argument("-d", "--daemon", action="store_true", help="以守护进程模式运行")
    args = parser.parse_args()
    
    # 创建系统实例
    system = SuriVisor(config_file=args.config)
    
    try:
        # 启动系统
        if not system.start():
            logger.error("系统启动失败")
            return 1
        
        # 处理PCAP文件
        if args.pcap:
            result = system.process_pcap_file(args.pcap)
            print(json.dumps(result, indent=4))
        
        # 生成报告
        if args.report:
            system.generate_report(args.report)
        
        # 如果不是守护进程模式，运行一段时间后退出
        if not args.daemon:
            logger.info("系统将运行60秒后退出...")
            time.sleep(60)
        else:
            # 守护进程模式，持续运行
            logger.info("系统以守护进程模式运行，按Ctrl+C退出")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("接收到中断信号，系统将退出")
    finally:
        # 停止系统
        system.stop()
    
    return 0


if __name__ == "__main__":
    # 确保日志目录存在
    os.makedirs(os.path.join(os.path.dirname(__file__), '../logs'), exist_ok=True)
    
    # 运行主函数
    sys.exit(main())