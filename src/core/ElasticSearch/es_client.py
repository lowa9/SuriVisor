#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Elasticsearch客户端模块

提供统一的ES查询接口，供其他模块使用。
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)  

class ESClient:
    """Elasticsearch客户端类"""
    
    def __init__(self, hosts: List[str] = None):
        """初始化ES客户端
        
        Args:
            hosts: ES主机列表，默认为localhost:9200
        """
        if not hosts:
            hosts = ['http://localhost:9200']
            
        try:
            self.client = Elasticsearch(hosts)
            logger.info('Elasticsearch连接成功')
        except Exception as e:
            logger.error(f'连接Elasticsearch失败: {e}')
            self.client = None
    
    def query_events(self, 
                     index_pattern: str = 'suricata-*',
                     event_type: Optional[str] = None,
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     query: Optional[Dict[str, Any]] = None,
                     size: int = 100) -> List[Dict[str, Any]]:
        """查询事件数据
        
        Args:
            index_pattern: 索引模式
            event_type: 事件类型
            start_time: 开始时间
            end_time: 结束时间
            query: 自定义查询DSL
            size: 返回结果数量
            
        Returns:
            List[Dict[str, Any]]: 查询结果列表
        """
        if not self.client:
            logger.error('Elasticsearch客户端未初始化')
            return []
            
        try:
            # 构建查询条件
            must_conditions = []
            
            # 添加事件类型过滤
            if event_type:
                must_conditions.append({
                    'term': {'event_type': event_type}
                })
            
            # 添加时间范围过滤
            if start_time or end_time:
                time_range = {}
                if start_time:
                    time_range['gte'] = start_time.isoformat()
                if end_time:
                    time_range['lte'] = end_time.isoformat()
                must_conditions.append({
                    'range': {'timestamp': time_range}
                })
            
            # 构建最终查询
            if query:
                final_query = query
            elif must_conditions:
                final_query = {'bool': {'must': must_conditions}}
            else:
                final_query = {'match_all': {}}
            
            # 执行查询
            result = self.client.search(
                index=index_pattern,
                body={'query': final_query},
                size=size
            )
            
            return [hit['_source'] for hit in result['hits']['hits']]
            
        except Exception as e:
            logger.error(f'查询Elasticsearch失败: {e}')
            return []
    
    def query_alerts(self, 
                     hours: int = 24,
                     severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """查询告警事件
        
        Args:
            hours: 最近小时数
            severity: 告警严重程度
            
        Returns:
            List[Dict[str, Any]]: 告警列表
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # 构建查询条件
        must_conditions = [
            {'term': {'event_type': 'alert'}}
        ]
        
        # 添加严重程度过滤
        if severity:
            must_conditions.append({
                'term': {'alert.severity': severity}
            })
        
        query = {
            'bool': {
                'must': must_conditions,
                'filter': {
                    'range': {
                        'timestamp': {
                            'gte': start_time.isoformat(),
                            'lte': end_time.isoformat()
                        }
                    }
                }
            }
        }
        
        return self.query_events(query=query)
    
    def query_packets(self,
                      flow_id: Optional[str] = None,
                      protocol: Optional[str] = None,
                      minutes: int = 5) -> List[Dict[str, Any]]:
        """查询数据包信息
        
        Args:
            flow_id: 流ID
            protocol: 协议
            minutes: 最近分钟数
            
        Returns:
            List[Dict[str, Any]]: 数据包列表
        """
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        # 构建查询条件
        must_conditions = [
            {'term': {'event_type': 'packet'}}
        ]
        
        if flow_id:
            must_conditions.append({
                'term': {'flow_id': flow_id}
            })
        
        if protocol:
            must_conditions.append({
                'term': {'proto': protocol}
            })
        
        query = {
            'bool': {
                'must': must_conditions,
                'filter': {
                    'range': {
                        'timestamp': {
                            'gte': start_time.isoformat(),
                            'lte': end_time.isoformat()
                        }
                    }
                }
            }
        }
        
        return self.query_events(query=query)