#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebSocket管理器模块

该模块提供WebSocket连接管理功能，用于实时推送告警信息到前端页面。
使用Flask-SocketIO实现WebSocket通信。
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any, Set

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# 创建 Logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# --- 文件处理器（记录所有 DEBUG 及以上日志）---
file_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__),'../../data/logs/surivisor.log'), mode='a')
file_handler.setLevel(logging.DEBUG)  # 文件记录 DEBUG+
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# 添加处理器
logger.addHandler(file_handler)

# 存储所有活跃的WebSocket连接
active_websockets: Set = set()

def register_websocket(sid) -> None:
    """
    注册新的WebSocket连接
    
    Args:
        sid: WebSocket会话ID
    """
    active_websockets.add(sid)
    logger.debug(f"新的WebSocket连接已注册，当前连接数: {len(active_websockets)}")

def unregister_websocket(sid) -> None:
    """
    注销WebSocket连接
    
    Args:
        sid: WebSocket会话ID
    """
    if sid in active_websockets:
        active_websockets.remove(sid)
        logger.debug(f"WebSocket连接已注销，当前连接数: {len(active_websockets)}")

def send_to_client(sid, message: str) -> None:
    """
    向单个WebSocket客户端发送消息
    
    Args:
        sid: WebSocket会话ID
        message (str): 要发送的消息
    """
    try:
        # 导入socketio实例
        from src.main import socketio
        
        socketio.emit('alert', message, room=sid)
        logger.debug(f"消息已发送到WebSocket客户端 {sid}")
    except Exception as e:
        logger.error(f"向WebSocket客户端发送消息失败: {e}")
        # 如果发送失败，可能是连接已关闭，尝试注销该连接
        unregister_websocket(sid)

def send_to_all_clients(message) -> None:
    """
    向所有WebSocket客户端广播消息
    
    Args:
        message: 要广播的消息，可以是字典或JSON字符串
    """
    try:
        # 避免循环导入，使用全局函数
        from src.main import send_to_all_clients as socketio_send
        
        # 调用main.py中的发送函数
        socketio_send(message)
        logger.debug(f"消息已广播到所有WebSocket客户端，共{len(active_websockets)}个")
    except Exception as e:
        logger.error(f"向WebSocket客户端广播消息失败: {e}")

def get_active_connections_count() -> int:
    """
    获取当前活跃的WebSocket连接数
    
    Returns:
        int: 活跃连接数
    """
    return len(active_websockets)