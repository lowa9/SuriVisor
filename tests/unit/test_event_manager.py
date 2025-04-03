#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EventManager单元测试

测试事件管理器的核心功能，包括事件注册、分发、过滤和优先级处理。
"""

import os
import sys
import unittest
import time
from threading import Thread

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.core.event_manager.event_manager import EventManager, Event, EventFilter


class TestEventManager(unittest.TestCase):
    """
    EventManager单元测试类
    """
    
    def setUp(self):
        """
        测试前准备
        """
        self.event_manager = EventManager(max_queue_size=100, worker_threads=2)
        self.received_events = []
    
    def tearDown(self):
        """
        测试后清理
        """
        if self.event_manager.running:
            self.event_manager.stop()
    
    def test_event_creation(self):
        """
        测试事件创建
        """
        event = Event("test_event", "test_source", 1, {"key": "value"})
        
        self.assertEqual(event.event_type, "test_event")
        self.assertEqual(event.source, "test_source")
        self.assertEqual(event.priority, 1)
        self.assertEqual(event.data, {"key": "value"})
        self.assertTrue(hasattr(event, "timestamp"))
        self.assertTrue(hasattr(event, "datetime"))
        self.assertTrue(hasattr(event, "id"))
    
    def test_event_comparison(self):
        """
        测试事件优先级比较
        """
        event1 = Event("test_event", "test_source", 1)
        event2 = Event("test_event", "test_source", 2)
        
        self.assertTrue(event1 < event2)  # 数字越小优先级越高
    
    def test_event_to_dict(self):
        """
        测试事件转换为字典
        """
        event = Event("test_event", "test_source", 1, {"key": "value"})
        event_dict = event.to_dict()
        
        self.assertEqual(event_dict["event_type"], "test_event")
        self.assertEqual(event_dict["source"], "test_source")
        self.assertEqual(event_dict["priority"], 1)
        self.assertEqual(event_dict["data"], {"key": "value"})
        self.assertTrue("timestamp" in event_dict)
        self.assertTrue("datetime" in event_dict)
        self.assertTrue("id" in event_dict)
    
    def test_event_filter_match(self):
        """
        测试事件过滤器匹配
        """
        event = Event("test_event", "test_source", 1)
        
        # 测试事件类型过滤
        filter1 = EventFilter(event_types=["test_event"])
        self.assertTrue(filter1.match(event))
        
        filter2 = EventFilter(event_types=["other_event"])
        self.assertFalse(filter2.match(event))
        
        # 测试事件来源过滤
        filter3 = EventFilter(sources=["test_source"])
        self.assertTrue(filter3.match(event))
        
        filter4 = EventFilter(sources=["other_source"])
        self.assertFalse(filter4.match(event))
        
        # 测试优先级过滤
        filter5 = EventFilter(min_priority=0, max_priority=2)
        self.assertTrue(filter5.match(event))
        
        filter6 = EventFilter(min_priority=2)
        self.assertFalse(filter6.match(event))
        
        # 测试自定义过滤器
        filter7 = EventFilter(custom_filter=lambda e: e.event_type == "test_event")
        self.assertTrue(filter7.match(event))
        
        filter8 = EventFilter(custom_filter=lambda e: e.event_type == "other_event")
        self.assertFalse(filter8.match(event))
    
    def test_register_handler(self):
        """
        测试注册事件处理器
        """
        def handler(event):
            pass
        
        # 注册特定类型的处理器
        self.event_manager.register_handler(handler, event_types=["test_event"])
        self.assertEqual(len(self.event_manager.handlers["test_event"]), 1)
        
        # 注册全局处理器
        self.event_manager.register_handler(handler)
        self.assertEqual(len(self.event_manager.global_handlers), 1)
    
    def test_unregister_handler(self):
        """
        测试注销事件处理器
        """
        def handler1(event):
            pass
        
        def handler2(event):
            pass
        
        # 注册处理器
        self.event_manager.register_handler(handler1, event_types=["test_event"])
        self.event_manager.register_handler(handler2, event_types=["test_event"])
        self.assertEqual(len(self.event_manager.handlers["test_event"]), 2)
        
        # 注销特定处理器
        self.event_manager.unregister_handler(handler1, event_types=["test_event"])
        self.assertEqual(len(self.event_manager.handlers["test_event"]), 1)
        
        # 注销所有处理器
        self.event_manager.unregister_handler(handler2)
        self.assertFalse("test_event" in self.event_manager.handlers)
    
    def test_emit_event(self):
        """
        测试发送事件
        """
        event = Event("test_event", "test_source", 1)
        
        # 发送事件
        result = self.event_manager.emit_event(event)
        self.assertTrue(result)
        self.assertEqual(self.event_manager.stats["events_received"], 1)
        self.assertEqual(self.event_manager.stats["events_by_type"]["test_event"], 1)
        self.assertEqual(self.event_manager.stats["events_by_source"]["test_source"], 1)
        self.assertEqual(self.event_manager.stats["events_by_priority"][1], 1)
    
    def test_create_and_emit_event(self):
        """
        测试创建并发送事件
        """
        # 创建并发送事件
        result = self.event_manager.create_and_emit_event(
            "test_event", "test_source", 1, {"key": "value"})
        
        self.assertTrue(result)
        self.assertEqual(self.event_manager.stats["events_received"], 1)
        self.assertEqual(self.event_manager.stats["events_by_type"]["test_event"], 1)
    
    def event_handler(self, event):
        """
        测试用事件处理器
        """
        self.received_events.append(event)
    
    def test_process_event(self):
        """
        测试事件处理
        """
        # 注册处理器
        self.event_manager.register_handler(self.event_handler, event_types=["test_event"])
        
        # 创建事件
        event = Event("test_event", "test_source", 1)
        
        # 处理事件
        self.event_manager._process_event(event)
        
        # 验证处理结果
        self.assertEqual(len(self.received_events), 1)
        self.assertEqual(self.received_events[0].event_type, "test_event")
        self.assertEqual(self.event_manager.stats["events_processed"], 1)
    
    def test_start_stop(self):
        """
        测试启动和停止事件管理器
        """
        # 启动事件管理器
        result = self.event_manager.start()
        self.assertTrue(result)
        self.assertTrue(self.event_manager.running)
        self.assertEqual(len(self.event_manager.worker_threads_list), 2)
        
        # 再次启动应该返回False
        result = self.event_manager.start()
        self.assertFalse(result)
        
        # 停止事件管理器
        result = self.event_manager.stop()
        self.assertTrue(result)
        self.assertFalse(self.event_manager.running)
        self.assertEqual(len(self.event_manager.worker_threads_list), 0)
        
        # 再次停止应该返回False
        result = self.event_manager.stop()
        self.assertFalse(result)
    
    def test_end_to_end(self):
        """
        测试完整的事件处理流程
        """
        # 注册处理器
        self.event_manager.register_handler(self.event_handler, event_types=["test_event"])
        
        # 启动事件管理器
        self.event_manager.start()
        
        # 发送事件
        event = Event("test_event", "test_source", 1, {"key": "value"})
        self.event_manager.emit_event(event)
        
        # 等待事件处理完成
        time.sleep(0.5)
        
        # 验证处理结果
        self.assertEqual(len(self.received_events), 1)
        self.assertEqual(self.received_events[0].event_type, "test_event")
        self.assertEqual(self.event_manager.stats["events_processed"], 1)
    
    def test_priority_queue(self):
        """
        测试事件优先级队列
        """
        # 注册处理器
        self.event_manager.register_handler(self.event_handler)
        
        # 启动事件管理器
        self.event_manager.start()
        
        # 发送多个不同优先级的事件
        event1 = Event("test_event", "test_source", 3, {"id": 1})  # 低优先级
        event2 = Event("test_event", "test_source", 1, {"id": 2})  # 高优先级
        event3 = Event("test_event", "test_source", 2, {"id": 3})  # 中优先级
        
        self.event_manager.emit_event(event1)
        self.event_manager.emit_event(event2)
        self.event_manager.emit_event(event3)
        
        # 等待事件处理完成
        time.sleep(0.5)
        
        # 验证处理顺序（应该按优先级处理）
        self.assertEqual(len(self.received_events), 3)
        self.assertEqual(self.received_events[0].data["id"], 2)  # 高优先级先处理
        self.assertEqual(self.received_events[1].data["id"], 3)  # 中优先级其次
        self.assertEqual(self.received_events[2].data["id"], 1)  # 低优先级最后
    
    def test_get_statistics(self):
        """
        测试获取统计信息
        """
        # 发送一些事件
        self.event_manager.create_and_emit_event("test_event1", "source1", 1)
        self.event_manager.create_and_emit_event("test_event2", "source2", 2)
        
        # 获取统计信息
        stats = self.event_manager.get_statistics()
        
        # 验证统计信息
        self.assertEqual(stats["events_received"], 2)
        self.assertEqual(stats["events_by_type"]["test_event1"], 1)
        self.assertEqual(stats["events_by_type"]["test_event2"], 1)
        self.assertEqual(stats["events_by_source"]["source1"], 1)
        self.assertEqual(stats["events_by_source"]["source2"], 1)
        self.assertEqual(stats["queue_size"], 2)
    
    def test_clear_statistics(self):
        """
        测试清除统计信息
        """
        # 发送一些事件
        self.event_manager.create_and_emit_event("test_event", "test_source", 1)
        
        # 清除统计信息
        self.event_manager.clear_statistics()
        
        # 验证统计信息已清除
        self.assertEqual(self.event_manager.stats["events_received"], 0)
        self.assertEqual(len(self.event_manager.stats["events_by_type"]), 0)


if __name__ == "__main__":
    unittest.main()