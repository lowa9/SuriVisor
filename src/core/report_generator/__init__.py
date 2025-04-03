#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
报告生成模块

该模块负责整合分析结果生成报告，提供多种报告格式和定制化选项。
目标是支持至少3种报告格式，并确保报告生成时间不超过5秒。
"""

from .report_generator import ReportGenerator