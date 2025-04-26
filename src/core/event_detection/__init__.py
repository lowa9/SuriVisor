#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络报文异常处理机制模块

该模块提供了用于网络异常检测和告警的工具和算法，
旨在及时发现并报警网络异常，保证关键网络指标监测覆盖率达到80%，并确保报警响应时间不超过3分钟。
"""

from .event_detector import EventDetector

__all__ = ['EventDetector']