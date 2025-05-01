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
from urllib3.exceptions import ConnectionError as URLCConnectionError
# 创建 Logger
logging.basicConfig(level=logging.DEBUG)
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
    
    def __init__(
        self, 
        hosts: List[str] = None,
        max_retries: int = 3,
        verify_certs: bool = False,
        http_auth: Optional[tuple] = None,
        fallback_mode: bool = False
    ):
        """初始化ES客户端（增强版）
        
        Args:
            hosts: ES节点列表，默认为 ["http://localhost:9200"]
            max_retries: 连接失败重试次数
            verify_certs: 是否验证SSL证书
            http_auth: 认证信息 (username, password)
            fallback_mode: 是否启用降级模式，在降级模式下，即使连接失败也不会抛出异常
        """
        self.client = None
        self.pit_id = None
        self.fallback_mode = fallback_mode
        self.connection_status = {
            "connected": False,
            "last_error": None,
            "hosts": hosts if hosts else ["http://localhost:9200"],
            "last_attempt": None
        }
        
        if not hosts:
            hosts = ["http://localhost:9200"]

        # 基础配置
        self.es_config = {
            "hosts": hosts,
            "max_retries": max_retries,
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            "verify_certs": verify_certs,
            "request_timeout": 10,  # 设置请求超时时间为10秒
        }
        
        # 可选认证
        if http_auth:
            self.es_config["http_auth"] = http_auth

        # 尝试连接
        self._try_connect(max_retries)
    
    def _try_connect(self, max_retries: int = 1):
        """尝试连接到Elasticsearch
        
        Args:
            max_retries: 最大重试次数
        
        Returns:
            bool: 连接是否成功
        """
        import time
        from datetime import datetime
        
        self.connection_status["last_attempt"] = datetime.now()
        
        for attempt in range(max_retries):
            try:
                # 如果不是第一次尝试，添加延迟
                if attempt > 0:
                    delay = min(2 ** attempt, 30)  # 指数退避，最大30秒
                    logger.info(f"第{attempt+1}次重试连接ES，等待{delay}秒...")
                    time.sleep(delay)
                
                self.client = Elasticsearch(**self.es_config)
                if self.client.ping():  # 主动验证连接
                    logger.info(f"成功连接到 Elasticsearch 集群: {self.es_config['hosts']}")
                    self.connection_status["connected"] = True
                    self.connection_status["last_error"] = None
                    return True
                else:
                    error_msg = "Ping 测试失败"
                    self.connection_status["last_error"] = error_msg
                    if not self.fallback_mode:
                        raise ConnectionError(error_msg)
                    
            except Exception as e:  # 先捕获所有异常
                error_msg = f"{type(e).__name__}: {str(e)}"
                self.connection_status["last_error"] = error_msg
                logger.error(f"连接异常详情: {error_msg}")
                
                # 特殊处理SSL错误
                if "SSL" in str(e) and self.es_config.get("verify_certs", False):
                    logger.warning("尝试关闭SSL验证并重试")
                    self.es_config["verify_certs"] = False
                    continue
        
        # 所有重试都失败
        if not self.fallback_mode:
            logger.error(f"无法连接到Elasticsearch集群，已达到最大重试次数({max_retries})")
        else:
            logger.warning(f"无法连接到Elasticsearch集群，系统将以降级模式运行")
        
        self.connection_status["connected"] = False
        return False

    def reconnect(self):
        """尝试重新连接到Elasticsearch
        
        当之前的连接失败后，可以调用此方法尝试重新连接
        
        Returns:
            bool: 重连是否成功
        """
        logger.info("尝试重新连接到Elasticsearch集群...")
        return self._try_connect(max_retries=1)
    
    def get_connection_status(self):
        """获取连接状态信息
        
        Returns:
            dict: 连接状态信息
        """
        return self.connection_status
        
    def diagnose_connection(self) -> dict:
        """诊断连接问题并提供可能的解决方案
        
        Returns:
            dict: 诊断结果，包含状态、错误信息和建议
        """
        result = {
            "status": "connected" if self.connection_status.get("connected", False) else "disconnected",
            "last_error": self.connection_status.get("last_error"),
            "hosts": self.connection_status.get("hosts", []),
            "last_attempt": self.connection_status.get("last_attempt"),
            "suggestions": []
        }
        
        # 如果连接成功，不需要提供建议
        if result["status"] == "connected":
            result["suggestions"].append("Elasticsearch连接正常，无需修复")
            return result
            
        # 根据错误类型提供建议
        error = result["last_error"] or ""
        
        # 连接超时或连接被拒绝
        if "ConnectionTimeout" in error or "ConnectionRefused" in error or "connect timeout" in error.lower():
            result["suggestions"].extend([
                "1. 检查Elasticsearch服务是否已启动",
                "2. 验证Elasticsearch主机地址和端口是否正确",
                "3. 检查网络连接和防火墙设置",
                f"4. 尝试手动访问: curl -X GET {result['hosts'][0] if result['hosts'] else 'http://localhost:9200'}"
            ])
        
        # SSL/TLS相关错误
        elif "SSL" in error or "certificate" in error.lower():
            result["suggestions"].extend([
                "1. 检查SSL/TLS证书配置",
                "2. 如果是自签名证书，可以设置verify_certs=False",
                "3. 确保证书路径正确且证书有效"
            ])
        
        # 认证错误
        elif "AuthenticationException" in error or "unauthorized" in error.lower():
            result["suggestions"].extend([
                "1. 检查用户名和密码是否正确",
                "2. 验证用户是否有足够的权限",
                "3. 检查Elasticsearch的安全设置"
            ])
        
        # Ping测试失败
        elif "Ping 测试失败" in error:
            result["suggestions"].extend([
                "1. 确认Elasticsearch服务正在运行",
                "2. 检查Elasticsearch日志中是否有错误",
                "3. 验证集群健康状态: curl -X GET http://localhost:9200/_cluster/health",
                "4. 检查Elasticsearch配置是否允许外部连接"
            ])
        
        # 通用建议
        result["suggestions"].extend([
            "- 确保Elasticsearch版本兼容",
            "- 检查Elasticsearch日志以获取更多信息",
            "- 考虑增加连接超时时间",
            "- 如果问题持续存在，可以启用fallback_mode=True以降级模式运行"
        ])
        
        return result
    
    def fetch_new_events(
        self,
        session_id: Optional[str] = None,
        last_sort_value: Optional[list] = None,
        size: int = 100,
        pit_keep_alive: str = "1m"
    ) -> Tuple[List[dict], Optional[list]]:
        """
        基于PIT和search_after进行增量拉取。
        
        在降级模式下，如果ES不可用，将返回空列表。
        """
        # 检查连接状态，如果未连接且启用了降级模式，直接返回空结果
        if not self.client:
            if self.fallback_mode:
                logger.warning('Elasticsearch客户端未初始化，以降级模式运行')
                return [], last_sort_value
            else:
                logger.error('Elasticsearch客户端未初始化')
                return [], last_sort_value

        # 如果连接状态为False，尝试重新连接一次
        if not self.connection_status.get("connected", False):
            if not self.reconnect() and not self.fallback_mode:
                logger.error("无法连接到Elasticsearch，无法获取事件")
                return [], last_sort_value

        index_pattern = f"suricata-*" if not session_id else f"suricata-*-{session_id}"

        try:
            # 显式设置请求头，确保Content-Type和Accept头部正确
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            pit_response = self.client.open_point_in_time(
                index=index_pattern, 
                keep_alive=pit_keep_alive,
                headers=headers
            )
            pit_id = pit_response["id"]
        except Exception as e:
            error_msg = f"PIT快照创建失败: {type(e).__name__}: {str(e)}"
            self.connection_status["last_error"] = error_msg
            logger.error(error_msg)
            if not self.fallback_mode:
                # 在非降级模式下，尝试重新连接
                self.reconnect()
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
            # 显式设置请求头，确保Content-Type和Accept头部正确
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            response = self.client.search(body=query, headers=headers)
            hits = response.body["hits"]["hits"]

            if not hits:
                logger.debug("未获取到新事件")
                return [], last_sort_value

            # 获取最新 sort 值（用于下一次 search_after）
            new_last_sort_value = hits[-1]["sort"]
            events = [hit["_source"] for hit in hits]
            #logger.debug(f"ES查询结果: {json.dumps(events)}")
            #logger.info(f"拉取到 {len(events)} 条新事件")
            
            # 更新连接状态
            self.connection_status["connected"] = True
            self.connection_status["last_error"] = None

            return events, new_last_sort_value

        except Exception as e:
            error_msg = f"ES查询异常: {type(e).__name__}: {str(e)}"
            self.connection_status["last_error"] = error_msg
            logger.error(error_msg)
            
            # 在非降级模式下，尝试重新连接
            if not self.fallback_mode:
                self.reconnect()
                
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