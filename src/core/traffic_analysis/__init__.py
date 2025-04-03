#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
流量分析模块

该模块提供了用于网络流量分析和威胁识别的工具和算法，
旨在自动化识别网络流量中的潜在威胁，达到60%的分类准确率。
"""

from .traffic_analyzer import TrafficAnalyzer

__all__ = ['TrafficAnalyzer']