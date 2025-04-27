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

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入核心模块
from src.core.traffic_analysis.traffic_analyzer import TrafficAnalyzer
from src.core.event_detection.event_detector import EventDetector
from src.core.event_manager.event_manager import EventManager, Event
from src.core.report_generator.report_generator import ReportGenerator
from src.core.suricata_monitor.process_manager import SuricataProcessManager

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
            
            # 初始化事件检测器
            if self.config["analysis"]["anomaly_detection_enabled"]:
                logger.info("初始化事件检测器...")
                event_config_file = os.path.join(os.path.dirname(__file__), '../config/anomaly_detection.json')
                self.event_detector = EventDetector(
                    config_file=event_config_file,
                    event_callback=self.handle_event
                )

            # 初始化事件管理器
            if self.config["analysis"]["event_manager_enabled"]:
                logger.info("初始化事件管理器...")
                self.event_manager = EventManager(
                    max_queue_size=1000,
                    worker_threads=2
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
    
    def initialize_online_components(self):
        """
        初始化在线分析流量系统组件
        
        Returns:
            bool: 初始化是否成功
        """
        
    
    def _get_alert_priority(self, alert_info):
        """
        根据告警严重程度获取优先级
        
        Args:
            alert_info (dict): 告警信息
            
        Returns:
            int: 优先级，数字越小优先级越高
        """
        severity = alert_info.get("severity", "medium").lower()
        if severity == "critical":
            return 0
        elif severity == "high":
            return 1
        elif severity == "medium":
            return 2
        elif severity == "low":
            return 3
        else:
            return 2  # 默认为中等优先级
    
    def handle_event(self, event):
        """
        将event添加到队列中
        
        Args:
            event (Event): 事件对象
        """
        logger.info(f"处理事件: {event}")
        # 如果事件管理器已初始化，发送告警事件
        if self.event_manager:
            self.event_manager.create_and_emit_event(
                event_type=event.event_type,
                # TODO source
                source="",
                priority=self._get_alert_priority(alert_info),
                data=alert_info
            )
        
    def _handle_alert_event(self, event):
        """
        处理告警事件
        
        Args:
            event (Event): 告警事件对象
        """
        logger.info(f"处理告警事件: {event.id}")
        alert_data = event.data
        
        # 记录告警信息
        alert_file = os.path.join(
            self.config["general"]["data_dir"],
            f"alerts/alert_{event.id}.json"
        )
        os.makedirs(os.path.dirname(alert_file), exist_ok=True)
        
        try:
            with open(alert_file, 'w') as f:
                json.dump(event.to_dict(), f, indent=4)
            logger.info(f"告警信息已保存到{alert_file}")
        except Exception as e:
            logger.error(f"保存告警信息失败: {e}")
        
        # 根据告警严重程度采取不同措施
        severity = alert_data.get("severity", "medium").lower()
        if severity in ["critical", "high"]:
            # 对于高严重性告警，可以触发额外的响应措施
            # 例如发送邮件通知、短信通知等
            logger.warning(f"高严重性告警: {alert_data.get('description', '未知告警')}")
            
            # 如果配置了报告生成器，生成告警报告
            if self.report_generator:
                self._generate_alert_report(event)
    
    def _handle_attack_event(self, event):
        """
        处理攻击事件
        
        Args:
            event (Event): 攻击事件对象
        """
        logger.warning(f"检测到攻击: {event.id}")
        attack_data = event.data
        
        # 记录攻击信息
        attack_file = os.path.join(
            self.config["general"]["data_dir"],
            f"attacks/attack_{event.id}.json"
        )
        os.makedirs(os.path.dirname(attack_file), exist_ok=True)
        
        try:
            with open(attack_file, 'w') as f:
                json.dump(event.to_dict(), f, indent=4)
            logger.info(f"攻击信息已保存到{attack_file}")
        except Exception as e:
            logger.error(f"保存攻击信息失败: {e}")
        
        # 根据攻击类型和严重程度采取不同措施
        attack_type = attack_data.get("attack_type", "unknown")
        severity = attack_data.get("severity", "medium").lower()
        
        logger.warning(f"攻击类型: {attack_type}, 严重程度: {severity}")
        
        # 如果配置了报告生成器，生成攻击报告
        if self.report_generator:
            self._generate_attack_report(event)
    
    def _handle_system_event(self, event):
        """
        处理系统事件
        
        Args:
            event (Event): 系统事件对象
        """
        logger.info(f"处理系统事件: {event.id}")
        system_data = event.data
        
        # 根据系统事件类型处理
        event_subtype = system_data.get("subtype", "unknown")
        
        if event_subtype == "startup":
            logger.info("系统启动事件")
        elif event_subtype == "shutdown":
            logger.info("系统关闭事件")
        elif event_subtype == "config_change":
            logger.info(f"配置变更事件: {system_data.get('details', {})}")
        else:
            logger.info(f"未知系统事件子类型: {event_subtype}")
    
    def _generate_alert_report(self, event):
        """
        生成告警报告
        
        Args:
            event (Event): 告警事件对象
        """
        try:
            report_data = {
                "timestamp": time.time(),
                "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": event.to_dict(),
                "system_status": "running" if self.running else "stopped"
            }
            
            # 生成报告文件名
            report_file = os.path.join(
                self.config["general"]["data_dir"],
                f"reports/alert_report_{event.id}.html"
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
                
            logger.info(f"告警报告已生成: {report_file}")
        except Exception as e:
            logger.error(f"生成告警报告失败: {e}")
    
    def _generate_anomaly_report(self, event):
        """
        生成异常报告
        
        Args:
            event (Event): 异常事件对象
        """
        try:
            report_data = {
                "timestamp": time.time(),
                "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": event.to_dict(),
                "system_status": "running" if self.running else "stopped",
                "traffic_analysis": self.traffic_analyzer.get_statistics() if self.traffic_analyzer else None,
                "anomaly_detection": self.event_detector.generate_anomaly_report() if self.event_detector else None
            }
            
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
            self.event_detector.start_monitoring(self.event_manager)
        
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
    
    def _get_flow_id(self, packet):
        """
        获取数据包的流ID
        
        Args:
            packet (dict): 数据包信息
            
        Returns:
            str: 流ID
        """
        # 实际应用中应该根据五元组（源IP、源端口、目的IP、目的端口、协议）生成流ID
        src_ip = packet.get('src_ip', '0.0.0.0')
        src_port = packet.get('src_port', 0)
        dst_ip = packet.get('dst_ip', '0.0.0.0')
        dst_port = packet.get('dst_port', 0)
        protocol = packet.get('protocol', 'tcp')
        
        return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
    
    def _get_attack_priority(self, classification):
        """
        根据攻击分类获取优先级
        
        Args:
            classification (dict): 攻击分类信息
            
        Returns:
            int: 优先级，数字越小优先级越高
        """
        severity = classification.get("severity", "medium").lower()
        if severity == "critical":
            return 0
        elif severity == "high":
            return 1
        elif severity == "medium":
            return 2
        elif severity == "low":
            return 3
        else:
            return 2  # 默认为中等优先级

    def analyze_pcap_file(self, pcap_file):
        """离线分析PCAP文件
        
        Args:
            surivisor (SuriVisor): SuriVisor实例
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
                    # 准备报告数据
                    # 构建与模板匹配的数据结构
                    alerts = result.get('alerts', [])
                    
                    # 提取攻击信息
                    attacks = []
                    for alert in alerts:
                        attacks.append({
                            "type": alert.get('signature', '未知攻击'),
                            "confidence": alert.get('confidence', 90),
                            "source_ip": alert.get('src_ip', '未知'),
                            "source_port": alert.get('src_port', '未知'),
                            "target_ip": alert.get('dest_ip', '未知'),
                            "target_port": alert.get('dest_port', '未知'),
                            "protocol": alert.get('proto', '未知'),
                            "timestamp": alert.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                        })
                    
                    # 构建完整的报告数据结构
                    report_data = {
                        "timestamp": time.time(),
                        "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "system_status": "running",
                        
                        # 数据包重组信息
                        "packet_reassembly": {
                            "total_packets": result.get('total_packets', 0),
                            "total_bytes": result.get('total_bytes', 0),
                            "reassembled_packets": result.get('reassembled_packets', 0),
                            "lost_packets": result.get('lost_packets', 0),
                            "out_of_order_packets": result.get('out_of_order_packets', 0),
                            "reassembly_success_rate": result.get('reassembly_success_rate', 99.5),
                            "avg_reassembly_time": result.get('avg_reassembly_time', 1.2)
                        },
                        
                        # 流量分析信息
                        "traffic_analysis": {
                            "analyzed_flows": result.get('analyzed_flows', 0),
                            "tcp_flows": result.get('tcp_flows', 0),
                            "udp_flows": result.get('udp_flows', 0),
                            "avg_flow_size": result.get('avg_flow_size', 0),
                            "max_flow_size": result.get('max_flow_size', 0),
                            "detected_attacks": len(attacks),
                            "attacks": attacks
                        },
                        
                        # 异常检测信息
                        "anomaly_detection": {
                            "total_anomalies": result.get('total_anomalies', len(alerts)),
                            "anomalies": [{
                                "description": alert.get('signature', '未知异常'),
                                "value": alert.get('value', 1),
                                "threshold": alert.get('threshold', 0.5),
                                "severity": alert.get('severity', 1),
                                "datetime": alert.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                            } for alert in alerts]
                        },
                        
                        # 事件管理信息
                        "event_manager": {
                            "events_received": result.get('events_received', len(alerts)),
                            "events_processed": result.get('events_processed', len(alerts)),
                            "events_dropped": result.get('events_dropped', 0),
                            "avg_processing_time": result.get('avg_processing_time', 0.05),
                            "queue_size": result.get('queue_size', 0),
                            "queue_full_percentage": result.get('queue_full_percentage', 0),
                            "events_by_type": result.get('events_by_type', {"alert": len(alerts)})
                        }
                    }
                    
                    # 添加元数据
                    metadata = {
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "generator": "SuriVisor",
                        "version": self.version
                    }
                    
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
                        options={"metadata": metadata}
                    )
                    
                    print(f"\n分析报告已生成: {report_file}")
                except Exception as e:
                    print(f"生成报告时发生错误: {e}")
            
            return True
        except Exception as e:
            print(f"离线分析过程中发生错误: {e}")
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
        # 收集各组件的报告
        report = {
            "timestamp": time.time(),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system_status": "running" if self.running else "stopped"
        }
        
        # 添加流量分析器报告
        if self.traffic_analyzer:
            report["traffic_analysis"] = self.traffic_analyzer.get_statistics()
        
        # 添加异常检测器报告
        if self.event_detector:
            anomaly_report = self.event_detector.generate_anomaly_report()
            # 确保 anomaly_report 是字符串类型
            if isinstance(anomaly_report, str):
                report["anomaly_detection"] = json.loads(anomaly_report)
            else:
                report["anomaly_detection"] = anomaly_report
        
        # 添加事件管理器报告
        if self.event_manager:
            report["event_manager"] = self.event_manager.get_statistics()
        
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
                data=report,
                report_type=report_type,
                output_file=output_file
            )
        
        # 如果是JSON格式且未指定输出文件，返回JSON字符串
        if report_type == "json" and not output_file:
            return json.dumps(report, indent=4)
        
        # 否则，写入JSON文件
        try:
            # 确保输出文件的目录存在
            if output_file:
                output_dir = os.path.dirname(output_file)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=4)
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