#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件管理器模块

该模块实现了统一的事件管理机制，用于协调系统中各模块产生的事件，
包括事件的注册、分发、过滤和优先级处理。
"""

import os
import sys
import time
import logging
import json
import threading
from queue import PriorityQueue, Empty
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Callable, Any, Optional, Tuple

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

class Event:
    """
    事件类
    
    表示系统中发生的一个事件，包含事件类型、优先级、来源、时间戳和详细信息。
    """
    
    def __init__(self, event_type: str, source: str, priority: int = 0, data: Optional[Dict[str, Any]] = None):
        """
        初始化事件
        
        Args:
            event_type (str): 事件类型
            source (str): 事件来源
            priority (int): 事件优先级，数字越小优先级越高
            data (Dict[str, Any]): 事件详细信息
        """
        self.event_type = event_type
        self.source = source
        self.priority = priority
        self.data = data or {}
        self.timestamp = time.time()
        self.datetime = datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        self.id = f"{self.event_type}_{int(self.timestamp * 1000)}_{id(self)}"
    
    def __lt__(self, other):
        """
        比较事件优先级，用于优先队列排序
        
        Args:
            other (Event): 另一个事件
            
        Returns:
            bool: 如果self优先级高于other，返回True
        """
        return self.priority < other.priority
    
    def to_dict(self) -> Dict[str, Any]:
        """
        将事件转换为字典
        
        Returns:
            Dict[str, Any]: 事件字典表示
        """
        return {
            "id": self.id,
            "event_type": self.event_type,
            "source": self.source,
            "priority": self.priority,
            "timestamp": self.timestamp,
            "datetime": self.datetime,
            "data": self.data
        }
    
    def __str__(self) -> str:
        """
        事件的字符串表示
        
        Returns:
            str: 事件的字符串表示
        """
        return f"Event[{self.id}]: {self.event_type} from {self.source} at {self.datetime} (priority: {self.priority})"


class EventFilter:
    """
    事件过滤器类
    
    用于根据条件过滤事件。
    """
    
    def __init__(self, event_types: Optional[List[str]] = None, sources: Optional[List[str]] = None, 
                 min_priority: Optional[int] = None, max_priority: Optional[int] = None,
                 custom_filter: Optional[Callable[[Event], bool]] = None):
        """
        初始化事件过滤器
        
        Args:
            event_types (List[str]): 事件类型列表，如果为None则匹配所有类型
            sources (List[str]): 事件来源列表，如果为None则匹配所有来源
            min_priority (int): 最小优先级（包含），如果为None则无下限
            max_priority (int): 最大优先级（包含），如果为None则无上限
            custom_filter (Callable[[Event], bool]): 自定义过滤函数
        """
        self.event_types = event_types
        self.sources = sources
        self.min_priority = min_priority
        self.max_priority = max_priority
        self.custom_filter = custom_filter
    
    def match(self, event: Event) -> bool:
        """
        检查事件是否匹配过滤条件
        
        Args:
            event (Event): 要检查的事件
            
        Returns:
            bool: 如果事件匹配过滤条件，返回True
        """
        # 检查事件类型
        if self.event_types is not None and event.event_type not in self.event_types:
            return False
        
        # 检查事件来源
        if self.sources is not None and event.source not in self.sources:
            return False
        
        # 检查最小优先级
        if self.min_priority is not None and event.priority < self.min_priority:
            return False
        
        # 检查最大优先级
        if self.max_priority is not None and event.priority > self.max_priority:
            return False
        
        # 应用自定义过滤器
        if self.custom_filter is not None and not self.custom_filter(event):
            return False
        
        return True


class EventManager:
    """
    事件管理器类
    
    负责事件的注册、分发、过滤和优先级处理。
    """
    
    def __init__(self, max_queue_size: int = 1000, worker_threads: int = 2):
        """
        初始化事件管理器
        
        Args:
            max_queue_size (int): 事件队列最大大小
            worker_threads (int): 工作线程数量
        """
        self.max_queue_size = max_queue_size
        self.worker_threads = worker_threads
        
        # 事件队列
        self.event_queue = PriorityQueue(maxsize=max_queue_size)
        
        # 事件处理器映射，格式: {event_type: [(handler, filter), ...]}
        self.handlers = defaultdict(list)
        
        # 全局事件处理器，处理所有类型的事件
        self.global_handlers = []
        
        # 事件统计信息
        self.stats = {
            "events_received": 0,
            "events_processed": 0,
            "events_dropped": 0,
            "events_by_type": defaultdict(int),
            "events_by_source": defaultdict(int),
            "events_by_priority": defaultdict(int),
            "processing_time": 0,
            "avg_processing_time": 0
        }
        
        # 线程控制
        self.running = False
        self.worker_threads_list = []
        
        logger.info(f"初始化事件管理器: 最大队列大小={max_queue_size}, 工作线程数={worker_threads}")
    
    def register_handler(self, handler: Callable[[Event], None], event_types: Optional[List[str]] = None, 
                        event_filter: Optional[EventFilter] = None) -> None:
        """
        注册事件处理器
        
        Args:
            handler (Callable[[Event], None]): 事件处理函数
            event_types (List[str]): 要处理的事件类型列表，如果为None则处理所有类型
            event_filter (EventFilter): 事件过滤器
        """
        if event_types is None:
            # 注册为全局处理器
            self.global_handlers.append((handler, event_filter))
            logger.debug(f"注册全局事件处理器: {handler.__name__}")
        else:
            # 注册为特定类型的处理器
            for event_type in event_types:
                self.handlers[event_type].append((handler, event_filter))
                logger.debug(f"注册事件处理器: {handler.__name__} 用于事件类型 {event_type}")
    
    def unregister_handler(self, handler: Callable[[Event], None], event_types: Optional[List[str]] = None) -> None:
        """
        注销事件处理器
        
        Args:
            handler (Callable[[Event], None]): 事件处理函数
            event_types (List[str]): 要注销的事件类型列表，如果为None则注销所有类型
        """
        if event_types is None:
            # 从全局处理器中注销
            self.global_handlers = [(h, f) for h, f in self.global_handlers if h != handler]
            
            # 从所有类型的处理器中注销
            for event_type in list(self.handlers.keys()):
                self.handlers[event_type] = [(h, f) for h, f in self.handlers[event_type] if h != handler]
                
                # 如果没有处理器，删除该类型
                if not self.handlers[event_type]:
                    del self.handlers[event_type]
            
            logger.debug(f"注销所有事件类型的处理器: {handler.__name__}")
        else:
            # 从指定类型的处理器中注销
            for event_type in event_types:
                if event_type in self.handlers:
                    self.handlers[event_type] = [(h, f) for h, f in self.handlers[event_type] if h != handler]
                    
                    # 如果没有处理器，删除该类型
                    if not self.handlers[event_type]:
                        del self.handlers[event_type]
                    
                    logger.debug(f"注销事件处理器: {handler.__name__} 用于事件类型 {event_type}")
    
    def emit_event(self, event: Event) -> bool:
        """
        发送事件到事件队列
        
        Args:
            event (Event): 要发送的事件
            
        Returns:
            bool: 如果成功加入队列，返回True
        """
        try:
            # 尝试将事件加入队列
            self.event_queue.put_nowait(event)
            
            # 更新统计信息
            self.stats["events_received"] += 1
            self.stats["events_by_type"][event.event_type] += 1
            self.stats["events_by_source"][event.source] += 1
            self.stats["events_by_priority"][event.priority] += 1
            
            logger.debug(f"事件已加入队列: {event}")
            return True
        except Exception as e:
            # 队列已满或其他错误
            self.stats["events_dropped"] += 1
            logger.warning(f"事件加入队列失败: {e}")
            return False
    
    def create_and_emit_event(self, event_type: str, source: str, priority: int = 0, 
                             data: Optional[Dict[str, Any]] = None) -> bool:
        """
        创建并发送事件
        
        Args:
            event_type (str): 事件类型
            source (str): 事件来源
            priority (int): 事件优先级
            data (Dict[str, Any]): 事件详细信息
            
        Returns:
            bool: 如果成功加入队列，返回True
        """
        event = Event(event_type, source, priority, data)
        return self.emit_event(event)
    
    def _process_event(self, event: Event) -> None:
        """
        处理单个事件
        
        Args:
            event (Event): 要处理的事件
        """
        start_time = time.time()
        handlers_called = 0
        
        # 调用特定类型的处理器
        if event.event_type in self.handlers:
            for handler, event_filter in self.handlers[event.event_type]:
                # 检查过滤器
                if event_filter is None or event_filter.match(event):
                    try:
                        handler(event)
                        handlers_called += 1
                    except Exception as e:
                        logger.error(f"事件处理器 {handler.__name__} 处理事件 {event.id} 时出错: {e}")
        
        # 调用全局处理器
        for handler, event_filter in self.global_handlers:
            # 检查过滤器
            if event_filter is None or event_filter.match(event):
                try:
                    handler(event)
                    handlers_called += 1
                except Exception as e:
                    logger.error(f"全局事件处理器 {handler.__name__} 处理事件 {event.id} 时出错: {e}")
        
        # 更新统计信息
        processing_time = time.time() - start_time
        self.stats["events_processed"] += 1
        self.stats["processing_time"] += processing_time
        self.stats["avg_processing_time"] = self.stats["processing_time"] / self.stats["events_processed"]
        
        if handlers_called == 0:
            logger.warning(f"事件 {event.id} 没有匹配的处理器")
        else:
            logger.debug(f"事件 {event.id} 已处理，调用了 {handlers_called} 个处理器，耗时 {processing_time:.6f} 秒")
    
    def _worker_thread(self) -> None:
        """
        工作线程函数，从队列中获取并处理事件
        """
        logger.info(f"事件处理线程 {threading.current_thread().name} 已启动")
        
        while self.running:
            try:
                # 从队列中获取事件，最多等待1秒
                event = self.event_queue.get(timeout=1)
                
                # 处理事件
                self._process_event(event)
                
                # 标记任务完成
                self.event_queue.task_done()
            except Empty:
                # 队列为空，继续等待
                continue
            except Exception as e:
                logger.error(f"事件处理线程异常: {e}")
        
        logger.info(f"事件处理线程 {threading.current_thread().name} 已停止")
    
    def start(self) -> bool:
        """
        启动事件管理器
        
        Returns:
            bool: 启动是否成功
        """
        if self.running:
            logger.warning("事件管理器已经在运行")
            return False
        
        # 设置运行标志
        self.running = True
        
        # 启动工作线程
        for i in range(self.worker_threads):
            thread = threading.Thread(target=self._worker_thread, name=f"EventWorker-{i}")
            thread.daemon = True
            thread.start()
            self.worker_threads_list.append(thread)
        
        logger.info(f"事件管理器已启动，工作线程数: {self.worker_threads}")
        return True
    
    def stop(self) -> bool:
        """
        停止事件管理器
        
        Returns:
            bool: 停止是否成功
        """
        if not self.running:
            logger.warning("事件管理器未在运行")
            return False
        
        # 设置停止标志
        self.running = False
        
        # 等待所有工作线程结束
        for thread in self.worker_threads_list:
            thread.join(timeout=5)
        
        # 清空线程列表
        self.worker_threads_list.clear()
        
        logger.info("事件管理器已停止")
        return True
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取事件管理器统计信息
        
        Returns:
            Dict[str, Any]: 统计信息字典
        """
        # 复制统计信息，避免返回可变对象
        stats_copy = self.stats.copy()
        
        # 将defaultdict转换为普通dict
        stats_copy["events_by_type"] = dict(stats_copy["events_by_type"])
        stats_copy["events_by_source"] = dict(stats_copy["events_by_source"])
        stats_copy["events_by_priority"] = dict(stats_copy["events_by_priority"])
        
        # 添加当前队列大小
        stats_copy["queue_size"] = self.event_queue.qsize()
        stats_copy["queue_full_percentage"] = (self.event_queue.qsize() / self.max_queue_size) * 100
        
        # 添加处理器信息
        stats_copy["registered_handlers"] = {
            "global": len(self.global_handlers),
            "by_type": {event_type: len(handlers) for event_type, handlers in self.handlers.items()}
        }
        
        return stats_copy
    
    def clear_statistics(self) -> None:
        """
        清除统计信息
        """
        self.stats = {
            "events_received": 0,
            "events_processed": 0,
            "events_dropped": 0,
            "events_by_type": defaultdict(int),
            "events_by_source": defaultdict(int),
            "events_by_priority": defaultdict(int),
            "processing_time": 0,
            "avg_processing_time": 0
        }
        logger.info("事件管理器统计信息已清除")