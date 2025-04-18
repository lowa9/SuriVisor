#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suricata日志监控器

负责监控和解析Suricata的日志输出，包括eve.json和alert.json等。
"""

import os
import json
import time
import logging
import threading
from typing import Optional, Dict, List, Any, Callable
from datetime import datetime

import pandas as pd
from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)

class SuricataLogMonitor:
    """Suricata日志监控器"""
    
    def __init__(self, 
                 log_dir: str = '/var/log/suricata',
                 eve_json: str = 'eve.json',
                 alert_json: str = 'alert.json',
                 es_hosts: List[str] = None,
                 es_index: str = 'suricata'):
        """初始化日志监控器
        
        Args:
            log_dir: 日志目录
            eve_json: eve.json文件名
            alert_json: alert.json文件名
            es_hosts: Elasticsearch主机列表
            es_index: Elasticsearch索引名
        """
        self.log_dir = log_dir
        self.eve_json_path = os.path.join(log_dir, eve_json)
        self.alert_json_path = os.path.join(log_dir, alert_json)
        
        # Elasticsearch客户端
        self.es_client = None
        if es_hosts:
            try:
                self.es_client = Elasticsearch(es_hosts)
                logger.info('Elasticsearch连接成功')
            except Exception as e:
                logger.error(f'连接Elasticsearch失败: {e}')
        
        self.es_index = es_index
        
        # 监控状态
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # 回调函数
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []
    
    def start_monitoring(self) -> bool:
        """启动日志监控
        
        Returns:
            bool: 启动是否成功
        """
        if self.running:
            logger.warning('日志监控已在运行')
            return False
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info('日志监控已启动')
        return True
    
    def stop_monitoring(self) -> bool:
        """停止日志监控
        
        Returns:
            bool: 停止是否成功
        """
        if not self.running:
            logger.warning('日志监控未在运行')
            return False
        
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        logger.info('日志监控已停止')
        return True
    
    def register_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """注册事件回调函数
        
        Args:
            callback: 回调函数，接收事件数据字典作为参数
        """
        self.callbacks.append(callback)
    
    def _monitor_loop(self):
        """监控循环"""
        # 记录文件位置
        file_position = 0
        
        while self.running:
            try:
                # 检查eve.json是否存在
                if not os.path.exists(self.eve_json_path):
                    time.sleep(1)
                    continue
                
                # 获取文件大小
                file_size = os.path.getsize(self.eve_json_path)
                
                # 如果文件大小变化
                if file_size > file_position:
                    with open(self.eve_json_path, 'r') as f:
                        # 移动到上次读取的位置
                        f.seek(file_position)
                        
                        # 读取新的日志行
                        for line in f:
                            try:
                                event = json.loads(line.strip())
                                
                                # 处理事件
                                self._process_event(event)
                                
                                # 保存到Elasticsearch
                                if self.es_client:
                                    try:
                                        self.es_client.index(
                                            index=self.es_index,
                                            document=event
                                        )
                                    except Exception as e:
                                        logger.error(f'保存事件到Elasticsearch失败: {e}')
                                
                            except json.JSONDecodeError as e:
                                logger.error(f'解析JSON失败: {e}')
                                continue
                    
                    # 更新文件位置
                    file_position = file_size
                
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f'监控循环发生错误: {e}')
                time.sleep(1)
    
    def _process_event(self, event: Dict[str, Any]):
        """处理事件
        
        Args:
            event: 事件数据字典
        """
        # 调用所有注册的回调函数
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f'调用回调函数失败: {e}')
    
    def analyze_logs(self, start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None) -> pd.DataFrame:
        """分析日志数据
        
        Args:
            start_time: 开始时间
            end_time: 结束时间
            
        Returns:
            pd.DataFrame: 分析结果数据框
        """
        try:
            # 读取eve.json文件
            events = []
            with open(self.eve_json_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        
                        # 解析时间戳
                        timestamp = datetime.strptime(
                            event['timestamp'],
                            '%Y-%m-%dT%H:%M:%S.%f%z'
                        )
                        
                        # 时间过滤
                        if start_time and timestamp < start_time:
                            continue
                        if end_time and timestamp > end_time:
                            continue
                        
                        events.append(event)
                        
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.error(f'解析事件失败: {e}')
                        continue
            
            # 转换为DataFrame
            df = pd.DataFrame(events)
            
            # 基本统计
            stats = {
                'total_events': len(df),
                'event_types': df['event_type'].value_counts().to_dict(),
                'alert_categories': df[df['event_type'] == 'alert']['alert.category']
                    .value_counts().to_dict() if 'alert.category' in df.columns else {},
                'src_ips': df['src_ip'].value_counts().head(10).to_dict()
                    if 'src_ip' in df.columns else {},
                'dest_ips': df['dest_ip'].value_counts().head(10).to_dict()
                    if 'dest_ip' in df.columns else {}
            }
            
            logger.info(f'日志分析完成: {stats}')
            return df
            
        except Exception as e:
            logger.error(f'分析日志失败: {e}')
            return pd.DataFrame()
    
    def get_alerts(self, hours: int = 24) -> pd.DataFrame:
        """获取最近的告警
        
        Args:
            hours: 最近小时数
            
        Returns:
            pd.DataFrame: 告警数据框
        """
        try:
            end_time = datetime.now()
            start_time = end_time.replace(hour=end_time.hour - hours)
            
            # 获取所有事件
            df = self.analyze_logs(start_time, end_time)
            
            # 过滤告警事件
            alerts = df[df['event_type'] == 'alert'].copy()
            
            # 添加严重程度
            if 'alert.severity' in alerts.columns:
                alerts['severity'] = alerts['alert.severity'].map({
                    1: 'High',
                    2: 'Medium',
                    3: 'Low'
                })
            
            return alerts
            
        except Exception as e:
            logger.error(f'获取告警失败: {e}')
            return pd.DataFrame()
            
    def get_es_data(self, query: Dict[str, Any] = None, size: int = 100) -> List[Dict[str, Any]]:
        """从Elasticsearch查询数据
        
        Args:
            query: Elasticsearch查询DSL
            size: 返回结果数量
            
        Returns:
            List[Dict[str, Any]]: 查询结果列表
        """
        if not self.es_client:
            logger.error('Elasticsearch客户端未初始化')
            return []
            
        try:
            if not query:
                query = {"match_all": {}}
                
            result = self.es_client.search(
                index=self.es_index,
                body={"query": query},
                size=size
            )
            
            return [hit['_source'] for hit in result['hits']['hits']]
            
        except Exception as e:
            logger.error(f'查询Elasticsearch失败: {e}')
            return []