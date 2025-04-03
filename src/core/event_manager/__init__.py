#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
事件管理模块

该模块负责统一管理和协调系统中各模块产生的事件，包括事件的分发、过滤和优先级处理。
目标是确保关键事件的处理延迟不超过1秒。
"""

from .event_manager import EventManager