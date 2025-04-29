#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Elasticsearch客户端模块

提供统一的ES查询接口，供其他模块使用。
"""
import os
import json
import logging
from typing import Optional, Tuple, List
from elasticsearch import Elasticsearch

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

        self.pit_id = None

    def fetch_new_events(
        self,
        session_id: Optional[str] = None,
        last_sort_value: Optional[list] = None,
        size: int = 100,
        pit_keep_alive: str = "1m"
    ) -> Tuple[List[dict], Optional[list]]:
        """
        基于PIT和search_after进行增量拉取。
        """
        if not self.client:
            logger.error('Elasticsearch 客户端未初始化')
            return [], last_sort_value

        index_pattern = f"suricata-*" if not session_id else f"suricata-*-{session_id}"

        try:
            pit_response = self.client.open_point_in_time(index=index_pattern, keep_alive=pit_keep_alive)
            pit_id = pit_response["id"]
        except Exception as e:
            logger.error(f"PIT 快照创建失败: {e}")
            return [], last_sort_value

        # 构造查询
        query = {
            "size": size,
            "sort": [{"@timestamp": "asc"}],
            "pit": {
                "id": pit_id,
                "keep_alive": pit_keep_alive
            },
            "query": {
                "range": {
                    "@timestamp": {
                        "gt": last_sort_value[0] if last_sort_value else "now-5m"  # 默认向前查5分钟
                    }
                }
            }
        }

        if last_sort_value:
            query["search_after"] = last_sort_value

        try:
            response = self.client.search(body=query)
            hits = response.body["hits"]["hits"]

            if not hits:
                logger.debug("未获取到新事件")
                return [], last_sort_value

            # 获取最新 sort 值（用于下一次 search_after）
            new_last_sort_value = hits[-1]["sort"]
            events = [hit["_source"] for hit in hits]
            logger.debug(f"ES查询结果: {json.dumps(events, indent=2)}")
            logger.info(f"拉取到 {len(events)} 条新事件")

            return events, new_last_sort_value

        except Exception as e:
            logger.error(f"ES 查询异常: {e}")
            return [], last_sort_value

    
    # def fetch_new_events(self, session_id: str = None, last_sort_value: dict = None, size: int = 100, pit_keep_alive: str = "1m") -> (list, dict):
    #     """
    #     基于session_id和last_sort_value拉取所有新增事件，并返回新的last_sort_value。
    #     Args:
    #         session_id (str): 会话ID，用于区分不同的索引后缀
    #         last_sort_value (dict): 上次查询的排序值
    #         size (int): 每次拉取的最大事件数
    #         pit_keep_alive (str): PIT快照保活时间
    #     Returns:
    #         (list, dict): 新增事件列表, 新的last_sort_value
    #     """
    #     if not self.client:
    #         logger.error('Elasticsearch客户端未初始化')
    #         return [], last_sort_value

    #     logger.debug(f"session_id: {session_id}, last_sort_value: {last_sort_value}")
    #     pit_index = f"suricata-*" if not session_id else f"suricata-*-{session_id}"
    #     try:
    #         self.pit_id = self.client.open_point_in_time(index=pit_index, keep_alive=pit_keep_alive)["id"]
    #     except Exception as e:
    #         logger.error(f"PIT快照创建失败: {e}")
    #         return [], last_sort_value
    #     query = {
    #         "size": size,
    #         "query": {"match_all": {}},
    #         "sort": [{"@timestamp": "asc"}],
    #         "pit": {"id": self.pit_id, "keep_alive": pit_keep_alive}
    #     }
    #     if last_sort_value:
    #         query["search_after"] = last_sort_value
    #     try:
    #         #logger.debug(f"ES查询条件: {json.dumps(query)}")
    #         response = self.client.search(body=query)
    #         hits = response.body["hits"]["hits"]
    #         if not hits:
    #             logger.debug("未拉取到新事件")
    #             return [], last_sort_value
    #         logger.debug(f"ES查询结果: {json.dumps(response.body)}")
    #         new_last_sort_value = hits[-1]["sort"]
    #         events = [hit["_source"] for hit in hits]
            
    #         # 这里的event结构大致是：
    #         # "_source": {
    #         # "session_id": "766ea23e-cca9-49b3-923e-79fbe8382a48",
    #         # "event_original_time": "2025-04-28T23:39:07.069883-0700",
    #         # "host": {
    #         #     "name": "ubuntu"
    #         # },
    #         # "event_type": "stats",
    #         # "@version": "1",
    #         # "event": {
    #         #     "original": """{"timestamp":"2025-04-28T23:39:07.069883-0700","event_type":"stats","stats":{"uptime":9,"capture":{"kernel_packets":525,"kernel_drops":0,"errors":0,"afpacket":{
            
    #         # 或者：
    #             # "_source": {
    #             # "src_port": 38626,
    #             # "dest_port": 443,
    #             # "proto": "TCP",
    #             # "app_proto": "tls",
    #             # "session_id": "766ea23e-cca9-49b3-923e-79fbe8382a48",
    #             # "event_original_time": "2025-04-28T23:39:13.010161-0700",
    #             # "tcp": {
    #             #     "ack": true,
    #             #     "psh": true,
    #             #     "state": "closed",
    #             #     "ts_max_regions": 1,
    #             #     "tcp_flags_ts": "1b",
    #             #     "tcp_flags": "1b",
    #             #     "syn": true,
    #             #     "fin": true,
    #             #     "tcp_flags_tc": "1b",
    #             #     "tc_max_regions": 1
    #             # },
    #             # "flow": {
    #             #     "alerted": false,
    #             #     "pkts_toclient": 25,
    #             #     "bytes_toclient": 3439,
    #             #     "state": "closed",
    #             #     "end": "2025-04-28T23:39:11.287400-0700",
    #             #     "reason": "shutdown",
    #             #     "bytes_toserver": 26501,
    #             #     "pkts_toserver": 25,
    #             #     "age": 1,
    #             #     "start": "2025-04-28T23:39:10.464654-0700"
    #             # },
    #             # "src_ip": "192.168.6.128",
    #             # "host": {
    #             #     "name": "ubuntu"
    #             # },
    #             # "event_type": "flow",
    #             # "in_iface": "ens33",
    #             # "@version": "1",
    #             # "timestamp": "2025-04-28T23:39:13.010161-0700",
    #             # "flow_id": 1714199474292958,
    #             # "@timestamp": "2025-04-29T06:39:13.010Z",
    #         logger.info(f"拉取{len(events)}条新事件")
    #         return events, new_last_sort_value
    #     except Exception as e:
    #         logger.error(f"ES查询异常: {e}")
    #         return [], last_sort_value