"""报告生成工具模块

提供报告生成和数据可视化的工具函数，包括：
- HTML报告生成
- 数据可视化
- 统计图表生成
- 异常事件记录
"""

from typing import Dict, List, Any, Optional
import json
import os
import time
from datetime import datetime
import logging
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

class ReportGenerator:
    """报告生成类
    
    用于生成分析报告和可视化图表
    """
    
    def __init__(self, output_dir: str):
        """初始化报告生成器
        
        Args:
            output_dir: 报告输出目录
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_flow_analysis_chart(self, flow_stats: Dict[str, Dict[str, Any]]) -> str:
        """生成流量分析图表
        
        Args:
            flow_stats: 流量统计数据
        
        Returns:
            图表HTML文件路径
        """
        # 准备数据
        data = []
        for flow_key, stats in flow_stats.items():
            data.append({
                'flow': flow_key,
                'packets': stats['packet_count'],
                'bytes': stats['byte_count'],
                'duration': stats.get('end_time', 0) - stats.get('start_time', 0)
            })
        
        df = pd.DataFrame(data)
        
        # 创建流量分布图
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=df['flow'],
            y=df['bytes'],
            name='字节数'
        ))
        fig.add_trace(go.Bar(
            x=df['flow'],
            y=df['packets'],
            name='数据包数'
        ))
        
        fig.update_layout(
            title='流量分布统计',
            xaxis_title='流标识',
            yaxis_title='数量',
            barmode='group'
        )
        
        # 保存图表
        output_file = os.path.join(self.output_dir, 'flow_analysis.html')
        fig.write_html(output_file)
        return output_file
    
    def generate_anomaly_chart(self, anomaly_data: List[Dict[str, Any]]) -> str:
        """生成异常检测图表
        
        Args:
            anomaly_data: 异常检测数据
        
        Returns:
            图表HTML文件路径
        """
        df = pd.DataFrame(anomaly_data)
        
        # 创建异常检测散点图
        fig = px.scatter(
            df,
            x='timestamp',
            y='anomaly_score',
            color='type',
            title='异常检测结果',
            labels={
                'timestamp': '时间',
                'anomaly_score': '异常分数',
                'type': '异常类型'
            }
        )
        
        output_file = os.path.join(self.output_dir, 'anomaly_detection.html')
        fig.write_html(output_file)
        return output_file
    
    def generate_performance_chart(self, performance_data: List[Dict[str, float]]) -> str:
        """生成性能监控图表
        
        Args:
            performance_data: 性能监控数据
        
        Returns:
            图表HTML文件路径
        """
        df = pd.DataFrame(performance_data)
        
        # 创建性能指标折线图
        fig = go.Figure()
        for metric in df.columns:
            if metric != 'timestamp':
                fig.add_trace(go.Scatter(
                    x=df['timestamp'],
                    y=df[metric],
                    name=metric
                ))
        
        fig.update_layout(
            title='系统性能监控',
            xaxis_title='时间',
            yaxis_title='指标值'
        )
        
        output_file = os.path.join(self.output_dir, 'performance_monitoring.html')
        fig.write_html(output_file)
        return output_file
    
    def generate_html_report(self, 
                           flow_stats: Dict[str, Dict[str, Any]],
                           anomaly_data: List[Dict[str, Any]],
                           performance_data: List[Dict[str, float]]) -> str:
        """生成HTML格式的综合报告
        
        Args:
            flow_stats: 流量统计数据
            anomaly_data: 异常检测数据
            performance_data: 性能监控数据
        
        Returns:
            报告文件路径
        """
        # 生成图表
        flow_chart = self.generate_flow_analysis_chart(flow_stats)
        anomaly_chart = self.generate_anomaly_chart(anomaly_data)
        performance_chart = self.generate_performance_chart(performance_data)
        
        # 生成报告HTML
        report_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>网络流量分析报告</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; }}
                .chart {{ width: 100%; height: 500px; }}
            </style>
        </head>
        <body>
            <h1>网络流量分析报告</h1>
            <div class="section">
                <h2>流量统计分析</h2>
                <iframe class="chart" src="{os.path.basename(flow_chart)}"></iframe>
            </div>
            <div class="section">
                <h2>异常检测结果</h2>
                <iframe class="chart" src="{os.path.basename(anomaly_chart)}"></iframe>
            </div>
            <div class="section">
                <h2>系统性能监控</h2>
                <iframe class="chart" src="{os.path.basename(performance_chart)}"></iframe>
            </div>
            <div class="section">
                <h2>报告生成时间</h2>
                <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </body>
        </html>
        """
        
        report_file = os.path.join(self.output_dir, 'report.html')
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_template)
        
        return report_file

class EventLogger:
    """事件记录类
    
    用于记录系统事件和异常情况
    """
    
    def __init__(self, log_file: str):
        """初始化事件记录器
        
        Args:
            log_file: 日志文件路径
        """
        self.log_file = log_file
        self.events: List[Dict[str, Any]] = []
    
    def log_event(self, event_type: str, description: str, severity: str = 'info') -> None:
        """记录事件
        
        Args:
            event_type: 事件类型
            description: 事件描述
            severity: 严重程度（info/warning/error）
        """
        event = {
            'timestamp': time.time(),
            'type': event_type,
            'description': description,
            'severity': severity
        }
        self.events.append(event)
        
        try:
            with open(self.log_file, 'a') as f:
                json.dump(event, f)
                f.write('\n')
        except Exception as e:
            logging.error(f"记录事件失败: {e}")
    
    def get_events(self, 
                   event_type: Optional[str] = None,
                   severity: Optional[str] = None,
                   start_time: Optional[float] = None,
                   end_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """获取事件记录
        
        Args:
            event_type: 事件类型过滤
            severity: 严重程度过滤
            start_time: 开始时间戳
            end_time: 结束时间戳
        
        Returns:
            过滤后的事件列表
        """
        filtered_events = self.events
        
        if event_type:
            filtered_events = [e for e in filtered_events if e['type'] == event_type]
        
        if severity:
            filtered_events = [e for e in filtered_events if e['severity'] == severity]
        
        if start_time:
            filtered_events = [e for e in filtered_events if e['timestamp'] >= start_time]
        
        if end_time:
            filtered_events = [e for e in filtered_events if e['timestamp'] <= end_time]
        
        return filtered_events

# 导出类
__all__ = ['ReportGenerator', 'EventLogger']