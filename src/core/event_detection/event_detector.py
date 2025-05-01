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
from src.core.event_manager import EventManager,Event
from src.core.ElasticSearch import ESClient

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

class EventDetector:
    """
    网络异常检测器类
    
    实现了对关键网络指标的监测机制，用于及时发现并报警网络异常。
    """
    
    def __init__(self, event_manager: EventManager):
        """
        初始化网络异常检测器
        
        Args:
            config_file (str): 配置文件路径
            event_callback (callable): 告警回调函数，接收告警信息作为参数
        """
        # 告警历史
        self.alert_history = []
        
        # 事件管理器
        self.event_manager = event_manager
        
        # 监控状态
        self.monitoring_thread = None
        self.running = False  # 控制监控循环的运行标志
        
        # 初始化ES客户端
        self.es_client = ESClient()

    def start_monitoring(self):
        """
        启动监控

        Args:
            event_manager: EventManager实例
        
        Returns:
            bool: 启动是否成功
        """
        if self.running:
            logger.warning("监控已经在运行")
            return False

        self.running = True  # 设置运行标志
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
        if not self.running:
            logger.warning("监控未在运行")
            return False

        self.running = False  # 设置运行标志为False，使监控循环退出
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        logger.info("网络异常监控已停止")
        return True
        
    def _get_current_session_id(self):
        """
        从会话ID文件中读取当前会话ID
        
        Returns:
            str: 当前会话ID，如果未找到则返回None
        """
        try:
            # 从SuricataProcessManager创建的会话ID文件中读取
            session_id_file = os.path.join(os.path.dirname(__file__), '../../../data/logs/suricata/session_id.conf')
            
            if not os.path.exists(session_id_file):
                logger.warning(f"会话ID文件不存在: {session_id_file}")
                return None
                
            with open(session_id_file, 'r') as f:
                content = f.read().strip()
                
            # 解析文件内容，格式为 SURICATA_SESSION_ID=xxx
            if content and 'SURICATA_SESSION_ID=' in content:
                session_id = content.split('SURICATA_SESSION_ID=')[1].strip()
                logger.info(f"从文件读取到会话ID: {session_id}")
                return session_id
            else:
                logger.warning(f"会话ID文件格式不正确: {content}")
                return None
                
        except Exception as e:
            logger.error(f"读取会话ID文件失败: {e}")
            return None

    def _monitoring_loop(self):
        """
        启动基于ES的事件监控循环，持续拉取新增事件并加入事件管理器队列。
        Args:
            session_id (str): 会话ID
        """
        last_sort_value = None
        if not self.event_manager:
            logger.warning("未设置事件管理器实例")
            return
        session_id = self._get_current_session_id()
        while self.running:
            try:
                sources, last_sort_value = self.es_client.fetch_new_events(session_id=session_id, size = 20, last_sort_value=last_sort_value)
                for item in sources:
                    #logger.debug(f"从ES获取到新事件: {item}")
                    event = Event(
                        event_type=item['event_type'],
                        source=item.get('in_iface', 'suricata'),
                        data=json.loads(item['event'].get('original')),
                        timestamp=item['timestamp'],
                        session_id=session_id
                    )
                    #logger.debug(f"新事件: {event}")S
                    self.handle_event(event) 
                
                time.sleep(2)
            except Exception as e:
                logger.error(f"监控循环发生错误: {e}")
                time.sleep(8)  # 错误发生后等待一段时间再重试
        
    def handle_event(self, event: Event):
        """
        将event添加到队列中
        
        Args:
            event (Event): 事件对象
        """
        #logger.info(f"处理事件: {event}")
        # 如果事件管理器已初始化，发送告警事件
        try:
            self.event_manager.emit_event(event)
            #logger.info(f"事件已发送到事件管理器: {event}")
        except Exception as e:
            logger.error(f"生成并发送事件时发生错误: {e}") 