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
from datetime import datetime

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入核心模块
from src.core.packet_reassembly.packet_reassembler import PacketReassembler
from src.core.traffic_analysis.traffic_analyzer import TrafficAnalyzer
from src.core.anomaly_detection.anomaly_detector import AnomalyDetector
from src.core.event_manager.event_manager import EventManager, Event
from src.core.report_generator.report_generator import ReportGenerator
from src.core.suricata_monitor.process_manager import SuricataProcessManager
from src.core.suricata_monitor.log_monitor import SuricataLogMonitor

# 配置日志
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   handlers=[
                       logging.FileHandler(os.path.join(os.path.dirname(__file__), '../data/logs/surivisor.log')),
                       logging.StreamHandler()
                   ])
logger = logging.getLogger("SuriVisor")


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
                "packet_reassembly_enabled": True,
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
        
        # 初始化组件
        self.packet_reassembler = None
        self.traffic_analyzer = None
        self.anomaly_detector = None
        self.event_manager = None
        self.report_generator = None
        
        # 系统状态
        # 初始化Suricata进程管理器
        logger.info("初始化Suricata进程管理器...")
        self.suricata_manager = SuricataProcessManager(
            binary_path=self.config["suricata"]["binary_path"],
            config_path=self.config["suricata"]["config_path"],
            rule_dir=self.config["suricata"]["rule_dir"],
            log_dir=os.path.join(self.config["general"]["data_dir"], "logs/suricata")
        )
        
        self.running = False
        self.processing_thread = None
        
        logger.info("SuriVisor系统初始化完成")
        
        # # 启动Web Server服务
        # if self.config["ui"]["dashboard_enabled"]:
        #     from src.api.server import create_app
        #     self.api_app = create_app(self)
        #     # 启动API服务
        #     self.api_thread = threading.Thread(
        #         target=self.api_app.run,
        #         kwargs={"host": "0.0.0.0", "port": self.config["ui"]["web_server_port"]},
        #         daemon=True
        #     )
        #     self.api_thread.start()
        #     logger.info(f"API服务已启动，监听端口 {self.config['ui']['web_server_port']}")
            
        #     # 启动Vue前端服务
        #     if self.config["ui"]["dashboard_enabled"]:
        #         frontend_dir = os.path.join(os.path.dirname(__file__), '../src/ui/dashboard')
        #         if os.path.exists(frontend_dir):
        #             self.frontend_thread = threading.Thread(
        #                 target=lambda: os.system(f"cd {frontend_dir} && npm run serve -- --port {self.config['ui']['web_frontend_port']}"),
        #                 daemon=True
        #             )
        #             self.frontend_thread.start()
        #             logger.info("Vue前端服务已启动")
    
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
            
            # 初始化日志监控器
            logger.info("初始化Suricata日志监控器...")
            self.log_monitor = SuricataLogMonitor(
                log_dir=os.path.join(self.config["general"]["data_dir"], "logs/suricata"),
                es_hosts=["http://127.0.0.1:9200"]  # 可以从配置文件中读取
            )
            
            # 注册日志事件处理器
            if self.log_monitor:
                self.log_monitor.register_callback(self._handle_suricata_event)
            
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
            
            # 初始化事件管理器
            if self.config["analysis"]["event_manager_enabled"]:
                logger.info("初始化事件管理器...")
                self.event_manager = EventManager(
                    max_queue_size=1000,
                    worker_threads=2
                )
                # 注册事件处理器
                self.event_manager.register_handler(self.handle_event)
            
            # 初始化报告生成器
            if self.config["analysis"]["report_generator_enabled"]:
                logger.info("初始化报告生成器...")
                reports_dir = os.path.join(self.config["general"]["data_dir"], "reports")
                templates_dir = os.path.join(os.path.dirname(__file__), '../templates')
                self.report_generator = ReportGenerator(
                    output_dir=reports_dir,
                    template_dir=templates_dir
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
        
        # 保存告警到文件
        alerts_dir = os.path.join(self.config["general"]["data_dir"], "alerts")
        os.makedirs(alerts_dir, exist_ok=True)
        
        alert_file = os.path.join(alerts_dir, f"alert_{int(time.time())}.json")
        try:
            with open(alert_file, 'w') as f:
                json.dump(alert_info, f, indent=4)
        except Exception as e:
            logger.error(f"保存告警信息失败: {e}")
        
        # 如果事件管理器已初始化，发送告警事件
        if self.event_manager:
            self.event_manager.create_and_emit_event(
                event_type="alert",
                source="anomaly_detector",
                priority=self._get_alert_priority(alert_info),
                data=alert_info
            )
    
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
        处理事件
        
        Args:
            event (Event): 事件对象
        """
        logger.info(f"处理事件: {event}")
        
        # 根据事件类型处理
        if event.event_type == "alert":
            # 告警事件处理
            self._handle_alert_event(event)
        elif event.event_type == "attack":
            # 攻击事件处理
            self._handle_attack_event(event)
        elif event.event_type == "system":
            # 系统事件处理
            self._handle_system_event(event)
        else:
            logger.warning(f"未知事件类型: {event.event_type}")
    
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
    
    def _handle_suricata_event(self, event_data):
        """
        处理Suricata事件
        
        Args:
            event_data (dict): Suricata事件数据
        """
        try:
            # 获取事件类型
            event_type = event_data.get('event_type')
            
            if event_type == 'alert':
                # 处理告警事件
                alert_data = {
                    'timestamp': event_data.get('timestamp'),
                    'src_ip': event_data.get('src_ip'),
                    'dest_ip': event_data.get('dest_ip'),
                    'alert': event_data.get('alert', {}),
                    'severity': event_data.get('alert', {}).get('severity', 2)
                }
                
                # 创建告警事件
                if self.event_manager:
                    self.event_manager.create_and_emit_event(
                        event_type="alert",
                        source="suricata",
                        priority=self._get_alert_priority(alert_data),
                        data=alert_data
                    )
            
            elif event_type == 'flow':
                # 处理流量事件
                flow_data = {
                    'timestamp': event_data.get('timestamp'),
                    'src_ip': event_data.get('src_ip'),
                    'dest_ip': event_data.get('dest_ip'),
                    'proto': event_data.get('proto'),
                    'app_proto': event_data.get('app_proto'),
                    'flow': event_data.get('flow', {})
                }
                
                # 如果配置了流量分析，进行分析
                if self.traffic_analyzer:
                    self.traffic_analyzer.analyze_flow(flow_data)
            
            elif event_type == 'anomaly':
                # 处理异常事件
                anomaly_data = {
                    'timestamp': event_data.get('timestamp'),
                    'type': event_data.get('anomaly', {}).get('type'),
                    'description': event_data.get('anomaly', {}).get('description')
                }
                
                # 如果配置了异常检测，进行处理
                if self.anomaly_detector:
                    self.anomaly_detector.process_anomaly(anomaly_data)
            
        except Exception as e:
            logger.error(f'处理Suricata事件时发生错误: {e}')
    
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
    
    def _generate_attack_report(self, event):
        """
        生成攻击报告
        
        Args:
            event (Event): 攻击事件对象
        """
        try:
            report_data = {
                "timestamp": time.time(),
                "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": event.to_dict(),
                "system_status": "running" if self.running else "stopped",
                "traffic_analysis": self.traffic_analyzer.get_statistics() if self.traffic_analyzer else None,
                "anomaly_detection": self.anomaly_detector.generate_anomaly_report() if self.anomaly_detector else None
            }
            
            # 生成报告文件名
            report_file = os.path.join(
                self.config["general"]["data_dir"],
                f"reports/attack_report_{event.id}.html"
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
            
            logger.info(f"攻击报告已生成: {report_file}")
        except Exception as e:
            logger.error(f"生成攻击报告失败: {e}")
    
    def start(self, start_suricata=True):
        """
        启动系统
        
        Args:
            start_suricata (bool): 是否启动Suricata进程
            
        Returns:
            bool: 启动是否成功
        """
        if self.running:
            logger.warning("系统已经在运行")
            return False
        
        # 初始化组件
        if not self.initialize_components():
            return False
        
        # 根据参数决定是否启动Suricata
        if start_suricata and self.suricata_manager:
            logger.info("正在启动Suricata进程...")
            if not self.suricata_manager.start():
                logger.error("启动Suricata失败")
                return False
            logger.info("Suricata进程启动成功")
            
            # 启动日志监控
            if self.log_monitor:
                if not self.log_monitor.start_monitoring():
                    logger.error("启动日志监控失败")
                    return False
                logger.info("Suricata日志监控已启动")
        else:
            logger.info("跳过Suricata进程启动")
        
        # 启动异常检测
        if self.anomaly_detector:
            self.anomaly_detector.start_monitoring()
        
        # 启动事件管理器
        if self.event_manager:
            self.event_manager.start()
        
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
        
        # 停止Suricata
        if self.suricata_manager:
            self.suricata_manager.stop()
        
        # 停止日志监控
        if self.log_monitor:
            self.log_monitor.stop_monitoring()
        
        # 停止异常检测
        if self.anomaly_detector:
            self.anomaly_detector.stop_monitoring()
        
        # 停止事件管理器
        if self.event_manager:
            self.event_manager.stop()
        
        # 等待处理线程结束
        if self.processing_thread:
            self.processing_thread.join(timeout=5)
            
        # 停止API服务
        if hasattr(self, 'api_thread') and self.api_thread:
            self.api_thread.join(timeout=1)
        
        logger.info("SuriVisor系统已停止")
        return True
    
    def _processing_loop(self):
        """
        主处理循环
        """
        while self.running:
            try:
                # 实现实时流量处理逻辑
                # 1. 模拟获取网络数据包
                packets = self._capture_network_packets()
                
                if packets:
                    # 2. 数据包重组
                    if self.packet_reassembler:
                        reassembled_flows = {}
                        for packet in packets:
                            flow_id = self._get_flow_id(packet)
                            seq_num = packet.get('seq_num', 0)
                            data = packet.get('data', b'')
                            is_last = packet.get('is_last', False)
                            
                            self.packet_reassembler.add_fragment(flow_id, seq_num, data, is_last)
                            
                            # 尝试重组完整流
                            if is_last or len(self.packet_reassembler.fragments[flow_id]) > 10:
                                reassembled_data = self.packet_reassembler.reassemble_flow(flow_id)
                                if reassembled_data:
                                    reassembled_flows[flow_id] = reassembled_data
                    
                    # 3. 流量分析
                    if self.traffic_analyzer and reassembled_flows:
                        for flow_id, flow_data in reassembled_flows.items():
                            # 提取流量特征
                            features = self.traffic_analyzer.extract_features(flow_id, flow_data)
                            
                            # 分类流量
                            classification = self.traffic_analyzer.classify_flow(flow_id, features)
                            
                            # 如果检测到攻击，创建事件
                            if classification and classification.get('is_attack', False):
                                if self.event_manager:
                                    self.event_manager.create_and_emit_event(
                                        event_type="attack",
                                        source="traffic_analyzer",
                                        priority=self._get_attack_priority(classification),
                                        data=classification
                                    )
                    
                    # 4. 异常检测
                    if self.anomaly_detector:
                        # 异常检测器已在start()方法中启动，会自动进行检测并通过回调函数处理告警
                        pass
                
                # 临时休眠，避免CPU占用过高
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"处理循环异常: {e}")
    
    def _capture_network_packets(self):
        """
        通过Suricata捕获网络数据包
        
        Returns:
            list: 捕获的数据包列表
        """
        packets = []
        
        # 确保Suricata进程管理器已初始化
        if not hasattr(self, 'suricata_manager') or self.suricata_manager is None:
            logger.error("Suricata进程管理器未初始化，无法捕获数据包")
            return packets
        
        # 确保Suricata正在运行
        if not self.suricata_manager.is_running():
            logger.info("Suricata未运行，正在启动...")
            interface = self.config["suricata"]["monitor_interface"]
            if not self.suricata_manager.start(interface=interface):
                logger.error(f"启动Suricata失败，无法在接口 {interface} 上捕获数据包")
                return packets
            # 等待Suricata启动并开始捕获
            time.sleep(2)
        
        # 从日志监控器获取最新的数据包信息
        if hasattr(self, 'log_monitor') and self.log_monitor is not None:
            # 确保日志监控器正在运行
            if not self.log_monitor.running:
                self.log_monitor.start_monitoring()
            
            # 获取最新的事件数据
            recent_events = self.log_monitor.get_recent_events(limit=100, event_types=['packet', 'flow'])
            
            # 处理事件数据，转换为数据包格式
            for event in recent_events:
                # 提取数据包相关信息
                packet_data = {
                    'timestamp': event.get('timestamp'),
                    'src_ip': event.get('src_ip'),
                    'dest_ip': event.get('dest_ip'),
                    'proto': event.get('proto'),
                    'src_port': event.get('src_port'),
                    'dest_port': event.get('dest_port'),
                    'payload': event.get('payload', ''),
                    'length': event.get('packet_info', {}).get('packet_len', 0),
                    'app_proto': event.get('app_proto', ''),
                    'raw_data': event
                }
                packets.append(packet_data)
        else:
            logger.error("Suricata日志监控器未初始化，无法获取捕获的数据包")
        
        logger.info(f"捕获了 {len(packets)} 个数据包")
        return packets
    
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
        
        try:
            # TODO: 解析PCAP文件，提取流量特征，进行流量分类，异常检测等处理
            # 这里模拟使用pyshark或scapy解析PCAP文件
            # 实际应用中应该使用如下代码：
            # import pyshark
            # cap = pyshark.FileCapture(pcap_file)
            # packets = [packet for packet in cap]
            
            # 模拟解析出的数据包
            packets = self._simulate_pcap_parsing(pcap_file)
            
            if not packets:
                logger.warning(f"PCAP文件中未找到数据包: {pcap_file}")
                return {"status": "warning", "message": "PCAP文件中未找到数据包"}
            
            logger.info(f"从PCAP文件中解析出{len(packets)}个数据包")
            
            # 处理解析出的数据包
            results = {
                "total_packets": len(packets),
                "processed_packets": 0,
                "reassembled_flows": 0,
                "detected_attacks": 0,
                "detected_anomalies": 0,
                "start_time": time.time()
            }
            
            # 数据包重组
            reassembled_flows = {}
            if self.packet_reassembler:
                for packet in packets:
                    flow_id = self._get_flow_id(packet)
                    seq_num = packet.get('seq_num', 0)
                    data = packet.get('data', b'')
                    is_last = packet.get('is_last', False)
                    
                    self.packet_reassembler.add_fragment(flow_id, seq_num, data, is_last)
                    results["processed_packets"] += 1
                
                # 尝试重组所有流
                for flow_id in set([self._get_flow_id(p) for p in packets]):
                    reassembled_data = self.packet_reassembler.reassemble_flow(flow_id)
                    if reassembled_data:
                        reassembled_flows[flow_id] = reassembled_data
                        results["reassembled_flows"] += 1
            
            # 流量分析
            if self.traffic_analyzer and reassembled_flows:
                for flow_id, flow_data in reassembled_flows.items():
                    # 提取流量特征
                    features = self.traffic_analyzer.extract_features(flow_id, flow_data)
                    
                    # 分类流量
                    classification = self.traffic_analyzer.classify_flow(flow_id, features)
                    
                    # 如果检测到攻击，创建事件
                    if classification and classification.get('is_attack', False):
                        results["detected_attacks"] += 1
                        if self.event_manager:
                            self.event_manager.create_and_emit_event(
                                event_type="attack",
                                source="traffic_analyzer",
                                priority=self._get_attack_priority(classification),
                                data=classification
                            )
            
            # 异常检测
            if self.anomaly_detector:
                # 将解析出的数据包送入异常检测器
                for packet in packets:
                    metrics = self._extract_packet_metrics(packet)
                    for metric_name, value in metrics.items():
                        if self.anomaly_detector.update_metric(metric_name, value):
                            results["detected_anomalies"] += 1
            
            # 生成处理报告
            results["end_time"] = time.time()
            results["processing_time"] = results["end_time"] - results["start_time"]
            
            # 如果配置了报告生成器，生成PCAP分析报告
            if self.report_generator and self.config["analysis"]["report_generator_enabled"]:
                report_file = os.path.join(
                    self.config["general"]["data_dir"],
                    f"reports/pcap_analysis_{int(time.time())}.html"
                )
                
                report_data = {
                    "timestamp": time.time(),
                    "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "pcap_file": pcap_file,
                    "results": results,
                    "packet_reassembly": self.packet_reassembler.get_reassembly_statistics() if self.packet_reassembler else None,
                    "traffic_analysis": self.traffic_analyzer.get_statistics() if self.traffic_analyzer else None,
                    "anomaly_detection": self.anomaly_detector.generate_anomaly_report() if self.anomaly_detector else None,
                    "event_manager": self.event_manager.get_statistics() if self.event_manager else None
                }
                
                self.report_generator.generate_report(
                    data=report_data,
                    report_type="html",
                    output_file=report_file
                )
                
                results["report_file"] = report_file
            
            logger.info(f"PCAP文件处理完成: {results}")
            return {"status": "success", "message": "PCAP文件处理完成", "results": results}
            
        except Exception as e:
            logger.error(f"处理PCAP文件时发生错误: {e}")
            return {"status": "error", "message": f"处理PCAP文件时发生错误: {e}"}
    
    def _simulate_pcap_parsing(self, pcap_file):
        """
        模拟解析PCAP文件（用于演示）
        
        Args:
            pcap_file (str): PCAP文件路径
            
        Returns:
            list: 模拟的数据包列表
        """
        # 这里仅用于演示，实际应用中应该使用pyshark或scapy解析PCAP文件
        # 模拟生成一些数据包
        packets = []
        
        # 模拟HTTP流量
        for i in range(10):
            packets.append({
                'src_ip': '192.168.1.100',
                'src_port': 12345 + i,
                'dst_ip': '93.184.216.34',  # example.com
                'dst_port': 80,
                'protocol': 'tcp',
                'seq_num': i,
                'data': f'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'.encode(),
                'is_last': (i == 9)
            })
        
        # 模拟端口扫描攻击
        for i in range(20):
            packets.append({
                'src_ip': '10.0.0.99',
                'src_port': 54321,
                'dst_ip': '192.168.1.1',
                'dst_port': 1000 + i,
                'protocol': 'tcp',
                'seq_num': i,
                'data': b'\x00\x00\x00\x00',  # 空数据
                'is_last': (i % 5 == 4)  # 每5个包为一个流
            })
        
        return packets
    
    def _extract_packet_metrics(self, packet):
        """
        从数据包中提取指标
        
        Args:
            packet (dict): 数据包信息
            
        Returns:
            dict: 提取的指标
        """
        # TODO: 从数据包中提取各种指标
        # 实际应用中应该根据数据包内容提取各种指标
        # 这里仅用于演示
        return {
            "packet_size": len(packet.get('data', b'')),
            "is_tcp": 1 if packet.get('protocol') == 'tcp' else 0,
            "is_udp": 1 if packet.get('protocol') == 'udp' else 0,
            "is_icmp": 1 if packet.get('protocol') == 'icmp' else 0,
            "src_port": packet.get('src_port', 0),
            "dst_port": packet.get('dst_port', 0)
        }
    
    def generate_report(self, output_file=None, report_type="json"):
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


def analyze_pcap_file(surivisor, pcap_file):
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
        if not hasattr(surivisor, 'suricata_manager') or not surivisor.suricata_manager:
            print("Suricata进程管理器未初始化，无法进行离线分析")
            return False
        
        # 设置日志目录
        log_dir = os.path.join(surivisor.config["general"]["data_dir"], "logs/suricata")
        
        print("正在使用Suricata分析PCAP文件...")
        # 调用进程管理器的analyze_pcap方法进行分析
        result = surivisor.suricata_manager.analyze_pcap(pcap_file, log_dir)
        
        if not result["success"]:
            print(f"Suricata分析失败: {result.get('error', '未知错误')}")
            return False
        
        print("PCAP文件分析完成")
        
        # 显示分析结果摘要
        print("\n分析结果摘要:")
        print(f"检测到 {result['alert_count']} 个告警")
        
        # 显示前5个告警
        if result['alerts']:
            print("\n前5个告警:")
            for i, alert in enumerate(result['alerts']):
                print(f"[{i+1}] {alert['signature']}")
                print(f"    严重程度: {alert['severity']}")
                print(f"    源IP: {alert['src_ip']} -> 目标IP: {alert['dest_ip']}")
                print()
        
        return True
    except Exception as e:
        print(f"离线分析过程中发生错误: {e}")
        return False
    finally:
        # 不需要停止Suricata进程，因为analyze_pcap方法会创建一个独立的进程
        # 只需要清理日志监控
        if hasattr(surivisor, 'log_monitor') and surivisor.log_monitor:
            surivisor.log_monitor.stop_monitoring()

def start_online_detection(surivisor):
    """启动在线检测模式
    
    Args:
        surivisor (SuriVisor): SuriVisor实例
        
    Returns:
        bool: 启动是否成功
    """
    print("\n启动在线检测模式...")
    
    # 启动系统并启动Suricata进程
    if not surivisor.start(start_suricata=True):
        print("启动在线检测模式失败")
        return False
    
    print("在线检测模式已启动")
    print("Suricata进程正在监控网络流量")
    print("按 Ctrl+C 停止检测")
    
    try:
        # 显示实时统计信息
        while True:
            # 获取Suricata状态
            if surivisor.suricata_manager:
                status = surivisor.suricata_manager.status()
                print(f"\r运行时间: {status.get('uptime', 0)}秒 | 内存使用: {status.get('memory_usage', 0)}KB", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n正在停止在线检测...")
        surivisor.stop()
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
    
    # 根据命令行参数直接进入特定模式
    if args.offline:
        analyze_pcap_file(surivisor, args.offline)
        sys.exit(0)
    elif args.online:
        start_online_detection(surivisor)
        sys.exit(0)
    
    # 交互式菜单
    while True:
        show_menu()
        choice = input("请选择操作 [0-2]: ")
        
        if choice == "1":
            # 离线分析模式
            pcap_file = select_pcap_file(surivisor.config["general"]["data_dir"])
            if pcap_file:
                analyze_pcap_file(surivisor, pcap_file)
        
        elif choice == "2":
            # 在线检测模式
            start_online_detection(surivisor)
        
        elif choice == "0":
            print("\n感谢使用SuriVisor系统，再见！")
            break
        
        else:
            print("\n无效的选择，请重试")