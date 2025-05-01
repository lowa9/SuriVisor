#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件处理器模块

该模块实现了各种类型事件的处理器，包括alert事件、anomaly事件、flow事件和stats事件的处理逻辑。
"""

import os
import sys
import time
import logging
import json
from typing import Dict, List, Any, Optional

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.core.event_manager.event_manager import EventManager, Event

# 创建 Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # 全局最低级别（DEBUG）

# --- 文件处理器（记录所有 DEBUG 及以上日志）---
file_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__),'../../../data/logs/surivisor.log'), mode='a')
file_handler.setLevel(logging.DEBUG)  # 文件记录 DEBUG+
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# # --- 控制台处理器（只显示 INFO 及以上日志）---
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.INFO)  # 控制台只显示 INFO+
# console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

# 添加处理器
logger.addHandler(file_handler)
# logger.addHandler(console_handler)

class EventHandler:
    """
    事件处理器类
    
    负责处理不同类型的事件，包括alert事件、anomaly事件、flow事件和stats事件。
    """
    
    def __init__(self, event_manager: EventManager) -> None:
        """
        初始化事件处理器
        """
        self.event_manager = event_manager
        logger.info("初始化事件处理器")
    
    def handle_alert_event(self, event: Event) -> None:
        """
        处理告警事件
        
        Args:
            event (Event): 告警事件对象
        """
        logger.info(f"处理告警事件: {event}")
        
        try:
            # 导入告警工具模块
            from src.utils.alert_utils import AlertStructure
            
            # 获取告警详情并标准化
            original_alert_data = event.data
            
            alert_data = AlertStructure.from_suricata_alert(original_alert_data)

            # 检查是否成功转换
            if not alert_data:
                logger.error("无法将告警事件转换为标准格式")
                return
            
            # 更新事件数据为标准格式
            event.data = alert_data
            
            # 获取告警信息
            alert_signature = alert_data.get('signature', '未知告警')
            alert_severity = alert_data.get('severity', 'medium')
            alert_source = alert_data.get('source_ip', '未知源IP')
            alert_dest = alert_data.get('destination_ip', '未知目标IP')
            
            # 根据告警严重程度执行不同操作
            if alert_severity in ['critical', 'high']:  # 高危告警
                logger.warning(f"高危告警: {alert_signature}, 源IP: {alert_source}, 目标IP: {alert_dest}")
                
                # 发送高危告警到WebSocket
                self._send_alert_to_websocket({
                    'type': 'high_alert',
                    'timestamp': event.timestamp,
                    'signature': alert_signature,
                    'severity': alert_severity,
                    'source_ip': alert_source,
                    'destination_ip': alert_dest,
                    'event_id': event.id
                })
            else:  # 低危告警
                logger.info(f"低危告警: {alert_signature}, 源IP: {alert_source}, 目标IP: {alert_dest}")
                # TODO: 实现低危告警的处理逻辑
            
            # 记录告警到数据库或文件
            with self.event_manager.alerts_lock:
                self.event_manager.processed_alerts.append(event)

            # 记录告警到文件
            self._save_alert_to_file(event)
            
        except Exception as e:
            logger.error(f"处理告警事件出错: {e}")
    
    def handle_anomaly_event(self, event: Event) -> None:
        """
        处理异常事件
        
        Args:
            event (Event): 异常事件对象
        """
        logger.info(f"处理异常事件: {event}")
        
        try:
            # 导入告警工具模块
            from src.utils.alert_utils import AlertStructure
            
            # 获取异常详情
            # original_anomaly_data = event.data.get('anomaly', {})
            # anomaly_type = original_anomaly_data.get('type', '未知类型')
            # anomaly_info = original_anomaly_data.get('anomaly', '未知异常信息')
            
            # 将异常事件转换为标准告警格式
            alert_data = AlertStructure.from_anomaly_event(event.data)
            
            # 记录告警到数据库或文件
            with self.event_manager.alerts_lock:
                self.event_manager.processed_alerts.append(alert_data)

            # 记录异常到数据库或文件
            self._save_anomaly_to_file(event)
            
        except Exception as e:
            logger.error(f"处理异常事件出错: {e}")
    
    def handle_flow_event(self, event: Event) -> None:
        """
        处理流量事件
        
        Args:
            event (Event): 流量事件对象
        """
        logger.info(f"处理流量事件: {event}")
        
        # try:
        #     # 获取流量详情
        #     flow_data = event.data
        #     flow_protocol = flow_data.get('protocol', '未知协议')
        #     flow_src_ip = flow_data.get('src_ip', '未知源IP')
        #     flow_dst_ip = flow_data.get('dst_ip', '未知目标IP')
        #     flow_src_port = flow_data.get('src_port', 0)
        #     flow_dst_port = flow_data.get('dst_port', 0)
        #     flow_bytes = flow_data.get('bytes', 0)
        #     flow_packets = flow_data.get('packets', 0)
            
        #     记录流量信息
        #     logger.debug(f"流量信息: {flow_protocol} {flow_src_ip}:{flow_src_port} -> {flow_dst_ip}:{flow_dst_port}, "
        #                f"字节数: {flow_bytes}, 包数: {flow_packets}")
            
        #     # 记录流量到数据库或文件
        #     self._save_flow_to_file(event)
            
        # except Exception as e:
        #     logger.error(f"处理流量事件出错: {e}")
    
    def handle_stats_event(self, event: Event) -> None:
        """
        处理统计事件
        
        Args:
            event (Event): 统计事件对象
        """
        logger.info(f"处理统计事件: {event}")
        
        # try:
        #     # 记录统计到数据库或文件
        #     self._save_stats_to_file(event)
            
        # except Exception as e:
        #     logger.error(f"处理统计事件出错: {e}")
    
    def _save_alert_to_file(self, event: Event) -> None:
        """
        将告警事件保存到文件
        
        Args:
            event (Event): 告警事件对象
        """
        try:
            # 导入告警工具模块
            from src.utils.alert_utils import AlertStructure
            
            # 确保目录存在
            alerts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../data/alerts'))
            os.makedirs(alerts_dir, exist_ok=True)
            
            # 使用AlertStructure保存告警
            if hasattr(event, 'data') and isinstance(event.data, dict):
                # 保存标准化的告警数据
                file_path = AlertStructure.save_alert_to_file(event.data, alerts_dir)
                if file_path:
                    logger.debug(f"告警事件已保存到文件: {file_path}")
                    return
            
            # 如果上面的方法失败，使用原始方法保存
            alert_file = os.path.join(alerts_dir, f"alert_{event.timestamp}.json")
            with open(alert_file, 'w', encoding='utf-8') as f:
                json.dump(event.to_dict(), f, indent=2, ensure_ascii=False)
                
            logger.debug(f"告警事件已保存到文件: {alert_file}")
        except Exception as e:
            logger.error(f"保存告警事件到文件失败: {e}")
    
    def _save_anomaly_to_file(self, event: Event) -> None:
        """
        将异常事件保存到文件
        
        Args:
            event (Event): 异常事件对象
        """
        try:
            # 导入告警工具模块
            from src.utils.alert_utils import AlertStructure
            
            # 确保目录存在
            anomalies_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../data/anomalies'))
            os.makedirs(anomalies_dir, exist_ok=True)
            
            # 使用AlertStructure保存告警
            if hasattr(event, 'data') and isinstance(event.data, dict):
                # 保存标准化的告警数据
                file_path = AlertStructure.save_alert_to_file(event.data, anomalies_dir, category="anomaly")
                if file_path:
                    logger.debug(f"异常事件已保存到文件: {file_path}")
                    return
            
            # 如果上面的方法失败，使用原始方法保存
            anomaly_file = os.path.join(anomalies_dir, f"anomaly_{event.timestamp}.json")
            with open(anomaly_file, 'w', encoding='utf-8') as f:
                json.dump(event.to_dict(), f, indent=2, ensure_ascii=False)
                
            logger.debug(f"异常事件已保存到文件: {anomaly_file}")
        except Exception as e:
            logger.error(f"保存异常事件到文件失败: {e}")
    
    def _save_flow_to_file(self, event: Event) -> None:
        """
        将流量事件保存到文件
        
        Args:
            event (Event): 流量事件对象
        """
        try:
            # 确保目录存在
            flows_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../data/flows'))
            os.makedirs(flows_dir, exist_ok=True)
            
            # 保存到文件
            flow_file = os.path.join(flows_dir, f"flow_{event.timestamp}.json")
            with open(flow_file, 'w') as f:
                json.dump(event.to_dict(), f, indent=2)
                
            logger.debug(f"流量事件已保存到文件: {flow_file}")
        except Exception as e:
            logger.error(f"保存流量事件到文件失败: {e}")
    
    def _save_stats_to_file(self, event: Event) -> None:
        """
        将统计事件保存到文件
        
        Args:
            event (Event): 统计事件对象
        """
        try:
            # 确保目录存在
            stats_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../data/stats'))
            os.makedirs(stats_dir, exist_ok=True)
            
            # 保存到文件
            stats_file = os.path.join(stats_dir, f"stats_{event.timestamp}.json")
            with open(stats_file, 'w') as f:
                json.dump(event.to_dict(), f, indent=2)
                
            logger.debug(f"统计事件已保存到文件: {stats_file}")
        except Exception as e:
            logger.error(f"保存统计事件到文件失败: {e}")
    
    def _process_traffic_summary(self, stats_data: Dict[str, Any]) -> None:
        """
        处理流量摘要统计
        
        Args:
            stats_data (Dict[str, Any]): 统计数据
        """
        logger.info("处理流量摘要统计")
        # TODO: 实现流量摘要统计的处理逻辑
    
    def _process_alert_summary(self, stats_data: Dict[str, Any]) -> None:
        """
        处理告警摘要统计
        
        Args:
            stats_data (Dict[str, Any]): 统计数据
        """
        logger.info("处理告警摘要统计")
        # TODO: 实现告警摘要统计的处理逻辑
    
    def _process_system_performance(self, stats_data: Dict[str, Any]) -> None:
        """
        处理系统性能统计
        
        Args:
            stats_data (Dict[str, Any]): 统计数据
        """
        logger.info("处理系统性能统计")
        # TODO: 实现系统性能统计的处理逻辑
        
    def _send_alert_to_websocket(self, alert_data: Dict[str, Any]) -> None:
        """
        将告警信息发送到WebSocket
        
        Args:
            alert_data (Dict[str, Any]): 告警数据
        """
        try:
            import json
            from src.utils.websocket_manager import send_to_all_clients
            
            # 发送到所有WebSocket客户端
            send_to_all_clients(alert_data)
            
            logger.debug(f"已将告警发送到WebSocket: {alert_data['signature']}")
        except ImportError:
            logger.warning("WebSocket管理器未配置，无法发送实时告警")
        except Exception as e:
            logger.error(f"发送告警到WebSocket出错: {e}")