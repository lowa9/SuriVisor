#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SuriVisor - 基于Suricata的威胁分析系统

该文件是系统的主入口，负责初始化各个组件并协调它们之间的交互。
"""

import os
import glob
import sys
import time
import logging
import argparse
import json
import threading
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入核心模块
from src.core.traffic_analysis.traffic_analyzer import TrafficAnalyzer
from src.core.event_detection.event_detector import EventDetector
from src.core.event_manager.event_manager import EventManager, Event
from src.core.report_generator.report_generator import ReportGenerator
from src.core.suricata_monitor.process_manager import SuricataProcessManager

# 导入工具模块
from src.utils.result_utils import ResultStructure

# 创建 Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # 全局最低级别（DEBUG）

# --- 文件处理器（记录所有 DEBUG 及以上日志）---
file_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__),'../data/logs/surivisor.log'), mode='a')
file_handler.setLevel(logging.DEBUG)  # 文件记录 DEBUG+
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# # --- 控制台处理器（只显示 INFO 及以上日志）---
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.INFO)  # 控制台只显示 INFO+
# console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

# 添加处理器
logger.addHandler(file_handler)
# logger.addHandler(console_handler)

class SuriVisor:
    """
    SuriVisor系统主类
    
    负责初始化各个组件并协调它们之间的交互。
    """
    
    def validate_suricata_config(self):
        """验证Suricata配置文件"""
        try:
            with open(self.config['suricata']['config_path'], 'r') as f:
                suricata_config = yaml.safe_load(f)
            
            # 验证必要的端口配置
            if 'vars' not in suricata_config or 'port-groups' not in suricata_config['vars']:
                raise ValueError("Suricata配置文件缺少端口组配置")
            
            port_groups = suricata_config['vars']['port-groups']
            required_ports = ['HTTP_PORTS', 'SSH_PORTS', 'DNS_PORTS', 'MODBUS_PORTS']
            
            for port in required_ports:
                if port not in port_groups:
                    logger.warning(f"Suricata配置缺少{port}配置")
            
            logger.info("Suricata配置验证完成")
            return True
            
        except Exception as e:
            logger.error(f"验证Suricata配置文件失败: {str(e)}")
            return False

    def __init__(self, config_file=None):
        """
        初始化SuriVisor系统
        
        Args:
            config_file (str): 配置文件路径
        """
        # 默认配置
        self.version = "1.1.0"

        self.config = {
            "general": {
                "debug": False,
                "log_level": "INFO",
                "data_dir": os.path.join(os.path.dirname(__file__), '../data')
            },
            "suricata": {
                "binary_path": "/usr/bin/suricata",
                "config_path": os.path.join(os.path.dirname(__file__), '../config/suricata.yaml'),
                "rule_dir": os.path.join(os.path.dirname(__file__), '../config/rules'),
                "monitor_interface": "any",
                "elasticsearch": {
                    "hosts": ["http://localhost:9200"],
                    "index": "suricata"
                }
            },
            "analysis": {
                "anomaly_detection_enabled": True,
                "traffic_analysis_enabled": True,
                "event_manager_enabled": True,
                "report_generator_enabled": True
            },
            "ui": {
                "web_server_port": 5000,
                "web_frontend_port": 8080,
                "dashboard_enabled": True,
                "report_generation_enabled": True
            }
        }
        
        # 加载配置文件
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
        
        # 确保日志目录存在
        os.makedirs(os.path.join(os.path.dirname(__file__), '../data/logs'), exist_ok=True)
        
        # 设置日志级别
        log_level = getattr(logging, self.config["general"]["log_level"].upper(), logging.INFO)
        logging.getLogger().setLevel(log_level)
        
        # 验证Suricata配置
        if not self.validate_suricata_config():
            logger.error("Suricata配置验证失败，系统启动终止")
            sys.exit(1)
        
        
        self.traffic_analyzer = None
        self.event_detector = None
        try:
            # 初始化Suricata进程管理器
            logger.info("初始化Suricata进程管理器...")
            self.suricata_manager = SuricataProcessManager(
                binary_path=self.config["suricata"]["binary_path"],
                config_path=self.config["suricata"]["config_path"],
                rule_dir=self.config["suricata"]["rule_dir"],
                log_dir=os.path.join(self.config["general"]["data_dir"], "logs/suricata")
            )

            # 初始化流量分析器
            if self.config["analysis"]["traffic_analysis_enabled"]:
                logger.info("初始化流量分析器...")
                attack_patterns_file = os.path.join(self.config["general"]["data_dir"], "attack_patterns.json")
                self.traffic_analyzer = TrafficAnalyzer(attack_patterns_file=attack_patterns_file)
            
            # 初始化事件管理器
            if self.config["analysis"]["event_manager_enabled"]:
                logger.info("初始化事件管理器...")
                self.event_manager = EventManager(
                    max_queue_size=1000,
                    worker_threads=2
                )

            # 初始化事件检测器
            if self.config["analysis"]["anomaly_detection_enabled"]:
                logger.info("初始化事件检测器...")
                self.event_detector = EventDetector(
                    self.event_manager
                )
                
            # 导入并初始化事件处理器
            from src.core.event_manager.event_handler import EventHandler
            self.event_handler = EventHandler()
            
            # 注册各类事件处理器
            logger.info("注册事件处理器...")
            # 注册告警事件处理器
            self.event_manager.register_handler(
                handler=self.event_handler.handle_alert_event,
                event_types=["alert"]
            )
            
            # 注册异常事件处理器
            self.event_manager.register_handler(
                handler=self.event_handler.handle_anomaly_event,
                event_types=["anomaly"]
            )
            
            # 注册流量事件处理器
            self.event_manager.register_handler(
                handler=self.event_handler.handle_flow_event,
                event_types=["flow"]
            )
            
            # 注册统计事件处理器
            self.event_manager.register_handler(
                handler=self.event_handler.handle_stats_event,
                event_types=["stats"]
            )
            
            # 初始化报告生成器
            logger.info("初始化报告生成器...")
            if self.config["analysis"]["report_generator_enabled"]:
                logger.info("初始化报告生成器...")
                reports_dir = os.path.join(self.config["general"]["data_dir"], "reports")
                templates_dir = os.path.join(os.path.dirname(__file__), '../templates')
                self.report_generator = ReportGenerator(
                    output_dir=reports_dir,
                    template_dir=templates_dir
                )
            
            # 系统状态
            self.running = False
            logger.info("SuriVisor系统初始化完成")

        except Exception as e:
            logger.error(f"初始化组件失败: {e}")

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
    
    def _generate_alert_report(self, event):
        """
        生成告警报告
        
        Args:
            event (Event): 告警事件对象
        """
        try:
            # 导入告警工具模块
            from src.utils.alert_utils import AlertStructure
            
            # 创建基础结果数据结构
            result = ResultStructure.create_base_result()
            result["success"] = True
            
            # 确保告警数据是标准格式
            if hasattr(event, 'data') and event.data:
                # 检查是否已经是标准格式
                if not ("id" in event.data and "severity" in event.data and isinstance(event.data.get("severity"), str)):
                    # 转换为标准格式
                    if "alert" in event.data:
                        # 可能是Suricata格式
                        event.data = AlertStructure.from_suricata_alert(event.data)
                    else:
                        # 其他格式，尝试创建标准告警
                        event.data = AlertStructure.create_alert(
                            signature=event.data.get('signature', '未知告警'),
                            severity=event.data.get('severity', 'medium') if isinstance(event.data.get('severity'), str) else 'medium',
                            category=event.data.get('category', '未分类'),
                            source_ip=event.data.get('source_ip', event.data.get('src_ip', '')),
                            source_port=str(event.data.get('source_port', event.data.get('src_port', ''))),
                            destination_ip=event.data.get('destination_ip', event.data.get('dest_ip', '')),
                            destination_port=str(event.data.get('destination_port', event.data.get('dest_port', ''))),
                            protocol=event.data.get('protocol', event.data.get('proto', '')),
                            description=event.data.get('description', ''),
                            details={"original": event.data}
                        )
            
            # 添加告警数据到结果
            result["alerts"] = [event.data] if hasattr(event, 'data') else []
            result["alert_count"] = len(result["alerts"])
            result["summary"] = f"检测到告警事件: {event.id}"
            
            # 转换为报告数据结构
            report_data = ResultStructure.create_report_result(result)
            report_data["data"]["system_status"] = "running" if self.running else "stopped"
            report_data["data"]["event"] = event.to_dict() if hasattr(event, 'to_dict') else {}
            
            # 生成报告文件名
            report_file = os.path.join(
                self.config["general"]["data_dir"],
                f"reports/alert_report_{event.id}.html"
            )
            
            # 确保报告目录存在
            os.makedirs(os.path.dirname(report_file), exist_ok=True)
            
            # 使用报告生成器生成HTML报告
            # 检查report_generator是否为None并且有generate_report方法
            if self.report_generator and hasattr(self.report_generator, 'generate_report'):
                self.report_generator.generate_report(
                data=report_data,
                report_type="html",
                output_file=report_file
            )
            else:
                logger.error("报告生成器未初始化或不支持generate_report方法")
                return False
                
            logger.info(f"告警报告已生成: {report_file}")
            return report_file
        except Exception as e:
            logger.error(f"生成告警报告失败: {e}")
            return None
    
    def _generate_anomaly_report(self, event):
        """
        生成异常报告
        
        Args:
            event (Event): 异常事件对象
        """
        try:
            # 创建基础结果数据结构
            result = ResultStructure.create_base_result()
            result["success"] = True
            
            # 添加异常事件数据
            if hasattr(event, 'data'):
                result["alerts"] = [event.data]
                result["alert_count"] = 1
            
            # 添加流量分析数据
            if self.traffic_analyzer and hasattr(self.traffic_analyzer, 'get_statistics'):
                traffic_stats = self.traffic_analyzer.get_statistics()
                if isinstance(traffic_stats, dict):
                    result["traffic_stats"] = traffic_stats
            
            # 添加异常检测数据
            if self.event_detector and hasattr(self.event_detector, 'generate_anomaly_report'):
                anomaly_data = self.event_detector.generate_anomaly_report()
                if isinstance(anomaly_data, dict):
                    # 将异常检测数据合并到结果中
                    if "network_metrics" in anomaly_data:
                        result["network_metrics"] = anomaly_data["network_metrics"]
                    if "tcp_health" in anomaly_data:
                        result["tcp_health"] = anomaly_data["tcp_health"]
            
            result["summary"] = f"检测到异常事件: {event.id}"
            
            # 转换为报告数据结构
            report_data = ResultStructure.create_report_result(result)
            report_data["data"]["system_status"] = "running" if self.running else "stopped"
            report_data["data"]["event"] = event.to_dict() if hasattr(event, 'to_dict') else {}
            
            # 生成报告文件名
            report_file = os.path.join(
                self.config["general"]["data_dir"],
                f"reports/anomaly_report_{event.id}.html"
            )
            
            # 使用报告生成器生成HTML报告
            # 检查report_generator是否为None并且有generate_report方法
            if self.report_generator and hasattr(self.report_generator, 'generate_report'):
                self.report_generator.generate_report(
                data=report_data,
                report_type="html",
                output_file=report_file
            )
            else:
                logger.error("报告生成器未初始化或不支持generate_report方法")
                return False
            
            logger.info(f"异常报告已生成: {report_file}")
        except Exception as e:
            logger.error(f"生成异常报告失败: {e}")
    
    def start(self, start_suricata=True):
        """
        启动实时流量分析告警系统
        
        Args:
            start_suricata (bool): 是否启动Suricata进程
            
        Returns:
            bool: 启动是否成功
        """
        if self.running:
            logger.warning("系统已经在运行")
            return False
        
        # 根据参数决定是否启动Suricata
        if start_suricata and self.suricata_manager:
            logger.info("正在启动Suricata进程...")
            if not self.suricata_manager.start():
                logger.error("启动Suricata失败")
                return False
            logger.info("Suricata进程启动成功")
            
        else:
            logger.info("跳过Suricata进程启动")
        
        # 启动事件管理器
        if self.event_manager:
            self.event_manager.start()

        # 启动事件检测
        if self.event_detector:
            self.event_detector.start_monitoring()
        
        # 设置运行状态
        self.running = True
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
        
        # 停止Suricata
        if self.suricata_manager:
            self.suricata_manager.stop()
        
        # 停止异常检测
        if self.event_detector:
            self.event_detector.stop_monitoring()
        
        # 停止事件管理器
        if self.event_manager:
            self.event_manager.stop()
        
        logger.info("SuriVisor系统已停止")
        return True

    def analyze_pcap_file(self, pcap_file):
        """离线分析PCAP文件
        
        Args:
            pcap_file (str): PCAP文件路径
            
        Returns:
            bool: 分析是否成功
        """
        if not os.path.exists(pcap_file):
            print(f"错误: PCAP文件 {pcap_file} 不存在")
            return False
        
        print(f"\n开始分析PCAP文件: {pcap_file}")
        
        # 使用Suricata进程管理器进行离线分析
        try:
            # 确保Suricata进程管理器已初始化
            if not hasattr(self, 'suricata_manager') or not self.suricata_manager:
                print("Suricata进程管理器未初始化，无法进行离线分析")
                return False
            
            # 设置日志目录
            log_dir = os.path.join(self.config["general"]["data_dir"], "logs/suricata")
            
            print("正在使用Suricata分析PCAP文件...")
            # 调用流量分析器的analyze_pcap方法进行分析
            result = self.traffic_analyzer.analyze_pcap(pcap_file, self.suricata_manager, log_dir)
            
            if not result["success"]:
                print(f"Suricata分析失败: {result.get('error', '未知错误')}")
                return False
            
            print("PCAP文件分析完成")
            
            # 显示分析结果摘要
            print("\n分析结果摘要:")
            print(f"检测到 {result['alert_count']} 个告警")
            
            # 显示新捕获的告警
            if result['alerts']:
                print("\n新捕获的告警:")
                for i, alert in enumerate(result['alerts']):
                    print(f"[{i+1}] {alert['signature']}")
                    print(f"    严重程度: {alert['severity']}")
                    print(f"    源IP: {alert['src_ip']} -> 目标IP: {alert['dest_ip']}")
                    print()
            
            # 生成分析报告
            if self.report_generator and self.config["analysis"]["report_generator_enabled"]:
                try:
                    
                    # 更新日志路径
                    result["log_paths"] = {
                        "suricata_log": os.path.join(log_dir, "suricata.log"),
                        "alert_log": os.path.join(log_dir, "alert.json"),
                        "traffic_log": os.path.join(log_dir, "stats.log"),
                        "event_log": os.path.join(log_dir, "eve.json"),
                    }
                    
                    # 更新分析结果摘要
                    result["summary"] = f"PCAP文件 {pcap_file} 分析完成，分析了{result['traffic_stats']['total_packets']}个数据包\
                        检测到 {result['alert_count']} 个告警"
                    
                    # 使用ResultStructure创建报告结果数据结构
                    metadata = {
                                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "generator": "SuriVisor",
                                "version": self.version,
                    }

                    report_data = ResultStructure.create_report_result(result,metadata)
                    
                    # 添加系统状态
                    report_data["data"]["system_status"] = "running" if self.running else "stopped"
                    
                    # 生成报告文件名
                    pcap_basename = os.path.basename(pcap_file)
                    report_filename = f"pcap_analysis_{os.path.splitext(pcap_basename)[0]}_{int(time.time())}.html"
                    report_path = os.path.join(self.config["general"]["data_dir"], "reports", report_filename)
                    
                    # 确保报告目录存在
                    os.makedirs(os.path.dirname(report_path), exist_ok=True)
                    
                    # 生成HTML报告
                    report_file = self.report_generator.generate_report(
                        data=report_data,
                        report_type="html",
                        output_file=report_path,
                    )
                    
                    print(f"\n分析报告已生成: {report_file}")
                except Exception as e:
                    logger.error(f"生成报告时发生错误: {e}")
            
            return True
        except Exception as e:
            logger.error(f"离线分析过程中发生错误: {e}")
            return False

    def generate_report(self, output_file=None, report_type="html"):
        """
        生成系统报告
        
        Args:
            output_file (str): 输出文件路径，如果为None则返回报告内容
            report_type (str): 报告类型，支持"json"、"html"、"pdf"、"csv"，默认为"json"
            
        Returns:
            str or bool: 如果output_file为None且report_type为"json"，返回报告内容；
                        否则返回生成的报告文件路径或操作是否成功
        """
        # 导入ResultStructure，确保只在需要时导入
        from src.utils.result_utils import ResultStructure
        
        # 创建基础结果数据结构
        report_result = ResultStructure.create_base_result()
        report_result["success"] = True
        report_result["system_status"] = "running" if self.running else "stopped"
        
        # 添加流量分析器报告（已经使用标准格式）
        if self.traffic_analyzer:
            traffic_stats = self.traffic_analyzer.get_statistics()
            # 整合流量分析数据
            report_result["traffic_stats"] = traffic_stats.get("traffic_stats", {})
            report_result["network_metrics"] = traffic_stats.get("network_metrics", {})
            report_result["tcp_health"] = traffic_stats.get("tcp_health", {})
        
        # 添加事件管理器报告
        if self.event_manager:
            # 获取检测到的alert信息
            alerts = self.event_manager.get_alerts()
            report_result["alerts"] = alerts
            report_result["alert_count"] = len(alerts)
            # 获取事件管理器报告
            report_result["event_logs"] = self.event_manager.get_statistics()
        
        # 如果有报告生成器且不是JSON格式或指定了输出文件，使用报告生成器
        if self.report_generator and (report_type != "json" or output_file):
            # 如果未指定输出文件，生成默认文件名
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = os.path.join(
                    self.config["general"]["data_dir"], 
                    f"reports/report_{timestamp}.{report_type}"
                )
            
            # 使用报告生成器生成报告
            return self.report_generator.generate_report(
                data=report_result,
                report_type=report_type,
                output_file=output_file
            )
        
        # 如果是JSON格式且未指定输出文件，返回JSON字符串
        if report_type == "json" and not output_file:
            return json.dumps(report_result, ensure_ascii=False, indent=2)
        
        # 否则，写入JSON文件
        try:
            # 确保输出文件的目录存在
            if output_file:
                output_dir = os.path.dirname(output_file)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report_result, f, ensure_ascii=False, indent=2)
                logger.info(f"系统报告已保存到{output_file}")
                return output_file
        except Exception as e:
            logger.error(f"保存系统报告失败: {e}")
            return False

    def start_online_detection(self):
        """启动在线检测模式
        
        Args:
            surivisor (self): SuriVisor实例
            
        Returns:
            bool: 启动是否成功
        """
        print("\n启动在线检测模式...")
        
        # 启动系统并启动Suricata进程
        if not self.start(start_suricata=True):
            print("启动在线检测模式失败")
            return False
        
        print("在线检测模式已启动")
        print("Suricata进程正在监控网络流量")
        print("按 Ctrl+C 停止检测")
        
        try:
            # 显示实时统计信息
            while True:
                # 获取Suricata状态
                if self.suricata_manager:
                    status = self.suricata_manager.status()
                    print(f"\r运行时间: {status.get('uptime', 0)}秒 | 内存使用: {status.get('memory_usage', 0)}KB\n", end="")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n正在停止在线检测...")
            self.stop()
            print("在线检测已停止")
        
        return True

def show_menu():
    """显示主菜单"""
    print("\n" + "=" * 50)
    print("SuriVisor - 基于Suricata的威胁分析系统")
    print("=" * 50)
    print("1. 离线分析模式 - 分析PCAP文件")
    print("2. 在线检测模式 - 实时监控网络流量")
    print("0. 退出系统")
    print("=" * 50)

def select_pcap_file(data_dir):
    """选择PCAP文件
    
    Args:
        data_dir (str): 数据目录
        
    Returns:
        str: 选择的PCAP文件路径，如果取消则返回None
    """
    pcap_dir = os.path.join(data_dir, "pcap")
    os.makedirs(pcap_dir, exist_ok=True)
    
    # 查找所有pcap文件
    pcap_files = glob.glob(os.path.join(pcap_dir, "*.pcap")) + \
                 glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    
    if not pcap_files:
        print(f"\n未找到PCAP文件。请将PCAP文件放置在 {pcap_dir} 目录下")
        return None
    
    print("\n可用的PCAP文件:")
    for i, pcap in enumerate(pcap_files):
        print(f"{i+1}. {os.path.basename(pcap)}")
    print("0. 返回主菜单")
    
    while True:
        try:
            choice = int(input("\n请选择要分析的PCAP文件 [0-{}]: ".format(len(pcap_files))))
            if choice == 0:
                return None
            elif 1 <= choice <= len(pcap_files):
                return pcap_files[choice-1]
            else:
                print("无效的选择，请重试")
        except ValueError:
            print("请输入有效的数字")

if __name__ == "__main__":
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="SuriVisor - 基于Suricata的威胁分析系统")
    parser.add_argument("-c", "--config", help="配置文件路径")
    parser.add_argument("-d", "--debug", action="store_true", help="启用调试模式")
    parser.add_argument("--offline", help="直接进入离线分析模式并分析指定的PCAP文件")
    parser.add_argument("--online", action="store_true", help="直接进入在线检测模式")
    args = parser.parse_args()
    
    # 创建SuriVisor实例
    surivisor = SuriVisor(config_file=args.config)
    
    # 交互式菜单
    while True:
        show_menu()
        choice = input("请选择操作 [0-2]: ")
        
        if choice == "1":
            # 离线分析模式
            pcap_file = select_pcap_file(surivisor.config["general"]["data_dir"])
            if pcap_file:
                surivisor.analyze_pcap_file(pcap_file)
        
        elif choice == "2":
            # 在线检测模式
            surivisor.start_online_detection()
        
        elif choice == "0":
            print("\n感谢使用SuriVisor系统，再见！")
            break
        
        else:
            print("\n无效的选择，请重试")