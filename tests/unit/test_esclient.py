#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Elasticsearch客户端测试模块

测试ESClient类的功能，并打印查询结果的事件字段信息。
"""

import logging
import sys
import os
from datetime import datetime, timedelta
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.core.es_client import ESClient  # 假设ESClient类保存在esclient.py中

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def print_events(events: list, title: str):
    """打印事件列表的字段信息"""
    print(f"\n=== {title} (共 {len(events)} 条) ===")
    if not events:
        print("无结果")
        return
    
    # 打印第一条事件的所有字段（示例）
    first_event = events[0]
    print("\n事件字段结构：")
    for field, value in first_event.items():
        print(f"  - {field}: {type(value).__name__} (示例值: {repr(value)})")
    
    # 打印所有事件的简要信息（可选）
    print("\n简要事件列表：")
    for i, event in enumerate(events[:5]):  # 最多打印5条
        timestamp = event.get('timestamp', '未知时间')
        event_type = event.get('event_type', '未知类型')
        print(f"{i+1}. [{timestamp}] {event_type}")

def test_query_events(client: ESClient):
    """测试通用事件查询"""
    # 查询最近1小时的所有事件
    events = client.query_events(
        start_time=datetime.now() - timedelta(hours=1),
        end_time=datetime.now(),
        size=3
    )
    print_events(events, "query_events - 最近1小时所有事件")

def test_query_alerts(client: ESClient):
    """测试告警查询"""
    # 查询最近24小时的告警
    alerts = client.query_alerts(hours=24)
    print_events(alerts, "query_alerts - 最近24小时告警")

    # 查询最近1小时的高危告警
    high_alerts = client.query_alerts(hours=1, severity="high")
    print_events(high_alerts, "query_alerts - 最近1小时高危告警")

def test_query_packets(client: ESClient):
    """测试数据包查询"""
    # 查询最近5分钟的TCP数据包
    packets = client.query_packets(protocol="tcp", minutes=5)
    print_events(packets, "query_packets - 最近5分钟TCP数据包")

if __name__ == "__main__":
    # 初始化ES客户端（根据实际情况修改hosts）
    es_hosts = ["http://localhost:9200"]  # 替换为你的ES地址
    client = ESClient(hosts=es_hosts)
    
    if not client.client:
        logger.error("无法连接Elasticsearch，退出测试")
        exit(1)
    
    # 执行测试
    test_query_events(client)
    test_query_alerts(client)
    test_query_packets(client)