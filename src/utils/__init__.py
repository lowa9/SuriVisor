"""
SuriVisor工具函数模块

该模块提供了系统所需的通用工具函数，包括：
- 日志记录
- 配置管理
- 文件操作
- 数据格式转换
- 性能监控
"""

from typing import Any, Dict, List, Optional
import logging
import json
import os
import time

# 配置日志格式
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class ConfigManager:
    """配置管理类
    
    用于加载和管理系统配置文件
    """
    
    def __init__(self, config_path: str):
        """初始化配置管理器
        
        Args:
            config_path: 配置文件路径
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> None:
        """加载配置文件"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            logging.error(f"加载配置文件失败: {e}")
            raise
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项
        
        Args:
            key: 配置项键名
            default: 默认值
        
        Returns:
            配置项值
        """
        return self.config.get(key, default)

class FileManager:
    """文件管理类
    
    用于处理PCAP文件的存储和管理
    """
    
    def __init__(self, base_dir: str):
        """初始化文件管理器
        
        Args:
            base_dir: 基础目录路径
        """
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
    
    def save_pcap(self, data: bytes, filename: str) -> str:
        """保存PCAP文件
        
        Args:
            data: PCAP文件数据
            filename: 文件名
        
        Returns:
            保存的文件路径
        """
        file_path = os.path.join(self.base_dir, filename)
        try:
            with open(file_path, 'wb') as f:
                f.write(data)
            return file_path
        except Exception as e:
            logging.error(f"保存PCAP文件失败: {e}")
            raise

class PerformanceMonitor:
    """性能监控类
    
    用于监控系统性能指标
    """
    
    def __init__(self):
        self.start_time = 0.0
        self.metrics: Dict[str, List[float]] = {}
    
    def start(self) -> None:
        """开始计时"""
        self.start_time = time.time()
    
    def end(self, metric_name: str) -> float:
        """结束计时并记录指标
        
        Args:
            metric_name: 指标名称
        
        Returns:
            耗时（秒）
        """
        duration = time.time() - self.start_time
        if metric_name not in self.metrics:
            self.metrics[metric_name] = []
        self.metrics[metric_name].append(duration)
        return duration
    
    def get_average(self, metric_name: str) -> Optional[float]:
        """获取指标平均值
        
        Args:
            metric_name: 指标名称
        
        Returns:
            平均值，如果指标不存在则返回None
        """
        if metric_name in self.metrics and self.metrics[metric_name]:
            return sum(self.metrics[metric_name]) / len(self.metrics[metric_name])
        return None

# 导出类
__all__ = ['ConfigManager', 'FileManager', 'PerformanceMonitor']