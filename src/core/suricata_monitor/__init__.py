# -*- coding: utf-8 -*-

"""
Suricata监控模块

该模块负责管理Suricata进程和监控其日志输出。
"""

from .process_manager import SuricataProcessManager

__all__ = ['SuricataProcessManager', 'SuricataLogMonitor']