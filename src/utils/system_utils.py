"""系统工具模块

提供系统配置和性能监控的工具函数，包括：
- 系统资源监控
- 性能指标收集
- 配置文件管理
- 系统状态检查
"""

from typing import Dict, List, Optional, Any
import psutil
import json
import os
import time
import logging
from dataclasses import dataclass

@dataclass
class SystemMetrics:
    """系统指标数据类"""
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_io_counters: Dict[str, Any]
    timestamp: float

class SystemMonitor:
    """系统监控类
    
    用于监控系统资源使用情况
    """
    
    def __init__(self, metrics_file: str):
        """初始化系统监控器
        
        Args:
            metrics_file: 指标数据存储文件路径
        """
        self.metrics_file = metrics_file
        self.metrics_history: List[SystemMetrics] = []
    
    def collect_metrics(self) -> SystemMetrics:
        """收集系统指标
        
        Returns:
            系统指标数据
        """
        metrics = SystemMetrics(
            cpu_percent=psutil.cpu_percent(interval=1),
            memory_percent=psutil.virtual_memory().percent,
            disk_usage_percent=psutil.disk_usage('/').percent,
            network_io_counters=psutil.net_io_counters()._asdict(),
            timestamp=time.time()
        )
        self.metrics_history.append(metrics)
        return metrics
    
    def save_metrics(self) -> None:
        """保存指标数据到文件"""
        try:
            metrics_data = [
                {
                    'cpu_percent': m.cpu_percent,
                    'memory_percent': m.memory_percent,
                    'disk_usage_percent': m.disk_usage_percent,
                    'network_io_counters': m.network_io_counters,
                    'timestamp': m.timestamp
                }
                for m in self.metrics_history
            ]
            
            with open(self.metrics_file, 'w') as f:
                json.dump(metrics_data, f, indent=2)
        except Exception as e:
            logging.error(f"保存指标数据失败: {e}")
            raise
    
    def get_average_metrics(self, time_window: int = 300) -> Optional[SystemMetrics]:
        """获取指定时间窗口内的平均指标
        
        Args:
            time_window: 时间窗口（秒），默认5分钟
        
        Returns:
            平均系统指标数据
        """
        current_time = time.time()
        recent_metrics = [
            m for m in self.metrics_history
            if current_time - m.timestamp <= time_window
        ]
        
        if not recent_metrics:
            return None
        
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        avg_disk = sum(m.disk_usage_percent for m in recent_metrics) / len(recent_metrics)
        
        # 计算网络IO的平均值
        network_counters = recent_metrics[-1].network_io_counters
        
        return SystemMetrics(
            cpu_percent=avg_cpu,
            memory_percent=avg_memory,
            disk_usage_percent=avg_disk,
            network_io_counters=network_counters,
            timestamp=current_time
        )

class SystemConfig:
    """系统配置类
    
    用于管理系统配置参数
    """
    
    def __init__(self, config_dir: str):
        """初始化系统配置管理器
        
        Args:
            config_dir: 配置文件目录
        """
        self.config_dir = config_dir
        self.configs: Dict[str, Dict[str, Any]] = {}
        self.load_all_configs()
    
    def load_all_configs(self) -> None:
        """加载所有配置文件"""
        try:
            for filename in os.listdir(self.config_dir):
                if filename.endswith('.json'):
                    config_name = os.path.splitext(filename)[0]
                    config_path = os.path.join(self.config_dir, filename)
                    with open(config_path, 'r') as f:
                        self.configs[config_name] = json.load(f)
        except Exception as e:
            logging.error(f"加载配置文件失败: {e}")
            raise
    
    def get_config(self, config_name: str) -> Dict[str, Any]:
        """获取指定配置
        
        Args:
            config_name: 配置名称
        
        Returns:
            配置数据
        """
        return self.configs.get(config_name, {})
    
    def update_config(self, config_name: str, config_data: Dict[str, Any]) -> None:
        """更新配置
        
        Args:
            config_name: 配置名称
            config_data: 新的配置数据
        """
        try:
            self.configs[config_name] = config_data
            config_path = os.path.join(self.config_dir, f"{config_name}.json")
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            logging.error(f"更新配置失败: {e}")
            raise

# 导出类
__all__ = ['SystemMetrics', 'SystemMonitor', 'SystemConfig']