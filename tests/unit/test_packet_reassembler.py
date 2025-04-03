#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
import os
from datetime import datetime, timedelta
import time

# 添加src目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), '../../src'))

from core.packet_reassembly.packet_reassembler import PacketReassembler

class TestPacketReassembler(unittest.TestCase):
    def setUp(self):
        """每个测试用例前的设置"""
        self.reassembler = PacketReassembler(timeout=5, max_fragments=10, buffer_size=1024)
    
    def test_add_fragment(self):
        """测试添加数据包分片"""
        flow_id = "test_flow_1"
        data = b"Hello, world!"
        
        # 测试正常添加分片
        self.assertTrue(self.reassembler.add_fragment(flow_id, 0, data))
        self.assertEqual(len(self.reassembler.fragments[flow_id]), 1)
        
        # 测试超过最大分片数限制
        for i in range(10):
            self.reassembler.add_fragment(flow_id, i+1, data)
        self.assertFalse(self.reassembler.add_fragment(flow_id, 11, data))
    
    def test_reassemble_flow(self):
        """测试数据包重组"""
        flow_id = "test_flow_2"
        
        # 按顺序添加分片
        self.reassembler.add_fragment(flow_id, 0, b"Hello, ")
        self.reassembler.add_fragment(flow_id, 1, b"world")
        self.reassembler.add_fragment(flow_id, 2, b"!", is_last=True)
        
        # 测试重组
        is_complete, data = self.reassembler.reassemble_flow(flow_id)
        self.assertTrue(is_complete)
        self.assertEqual(data, b"Hello, world!")
    
    def test_out_of_order_reassembly(self):
        """测试乱序数据包重组"""
        flow_id = "test_flow_3"
        
        # 乱序添加分片
        self.reassembler.add_fragment(flow_id, 2, b"world!", is_last=True)
        self.reassembler.add_fragment(flow_id, 0, b"Hello, ")
        self.reassembler.add_fragment(flow_id, 1, b" ")
        
        # 测试重组
        is_complete, data = self.reassembler.reassemble_flow(flow_id)
        self.assertEqual(data, b"Hello,  world!")
        self.assertTrue(is_complete)
    
    def test_cleanup_expired_flows(self):
        """测试过期流清理"""
        flow_id = "test_flow_4"
        self.reassembler.add_fragment(flow_id, 0, b"test data")
        
        # 模拟等待超时
        time.sleep(6)
        
        # 清理过期流
        cleaned = self.reassembler.cleanup_expired_flows()
        self.assertEqual(cleaned, 1)
        self.assertNotIn(flow_id, self.reassembler.fragments)
    
    def test_get_reassembly_statistics(self):
        """测试获取重组统计信息"""
        flow_id = "test_flow_5"
        
        # 添加一些测试数据
        self.reassembler.add_fragment(flow_id, 0, b"test")
        self.reassembler.add_fragment(flow_id, 1, b"data")
        
        # 获取统计信息
        stats = self.reassembler.get_reassembly_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('total_flows', stats)
        self.assertIn('total_packets', stats)
        self.assertIn('reassembly_rate', stats)

if __name__ == '__main__':
    unittest.main()