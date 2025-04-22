#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Suricata进程管理器

负责Suricata进程的启动、停止和状态监控。
"""

import os
import sys
import time
import signal
import logging
import subprocess
import json
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SuricataProcessManager:
    """Suricata进程管理器"""
    
    def __init__(self, 
                 binary_path: str = '/usr/bin/suricata',
                 config_path: str = '/etc/suricata/suricata.yaml',
                 rule_dir: str = '/etc/suricata/rules',
                 log_dir: str = '/var/log/suricata',
                 pid_file: str = '/var/run/suricata.pid'):
        """初始化Suricata进程管理器
        
        Args:
            binary_path: Suricata可执行文件路径
            config_path: Suricata配置文件路径
            rule_dir: Suricata规则目录
            log_dir: 日志目录
            pid_file: PID文件路径
        """
        self.binary_path = binary_path
        self.config_path = config_path
        self.rule_dir = rule_dir  # 修正变量名
        self.log_dir = log_dir
        self.pid_file = pid_file
        
        # Suricata进程
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        
        # 确保日志目录存在
        os.makedirs(log_dir, exist_ok=True)
    
    def start(self, interface: str = 'ens33') -> bool:
        """启动Suricata进程
        
        Args:
            interface: 要监控的网络接口
            
        Returns:
            bool: 启动是否成功
        """
        if self.running:
            logger.warning('Suricata进程已在运行')
            return False
        
        try:
            # 检查并清理过期的PID文件
            if os.path.exists(self.pid_file):
                try:
                    with open(self.pid_file, 'r') as f:
                        old_pid = int(f.read().strip())
                    # 检查PID是否存在
                    try:
                        os.kill(old_pid, 0)
                        logger.warning(f'发现运行中的Suricata进程(PID:{old_pid})，尝试停止...')
                        os.kill(old_pid, signal.SIGTERM)
                        time.sleep(2)
                    except ProcessLookupError:
                        # PID不存在，文件过期
                        pass
                except (ValueError, IOError) as e:
                    logger.warning(f'PID文件格式错误: {e}')
                
                # 删除PID文件
                try:
                    os.remove(self.pid_file)
                    logger.info('已清理过期的PID文件')
                except OSError as e:
                    logger.error(f'删除PID文件失败: {e}')
                    return False
            # 构建命令行参数
            cmd = [
                self.binary_path,
                '-c', self.config_path,
                '--pidfile', self.pid_file,
                '-i', interface,
                '--set', f'default-rule-path={self.rule_dir}',
                '--set', f'default-log-dir={self.log_dir}'
            ]
            
            # 启动进程
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1  # 行缓冲
            )
            
            # 等待进程启动
            time.sleep(2)
            
            # 检查进程状态
            if self.process.poll() is None:
                self.running = True
                logger.info('Suricata进程启动成功')
                return True
            else:
                error = self.process.stderr.read()
                logger.error(f'Suricata进程启动失败: {error}')
                return False
                
        except Exception as e:
            logger.error(f'启动Suricata进程时发生错误: {e}')
            return False
    
    def stop(self) -> bool:
        """停止Suricata进程
        
        Returns:
            bool: 停止是否成功
        """
        if not self.running:
            logger.warning('Suricata进程未在运行')
            return False
        
        try:
            # 首先尝试优雅关闭
            if self.process:
                self.process.send_signal(signal.SIGTERM)
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # 如果超时，强制关闭
                    self.process.kill()
                    self.process.wait()
            
            self.running = False
            self.process = None
            
            # 删除PID文件
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
            
            logger.info('Suricata进程已停止')
            return True
            
        except Exception as e:
            logger.error(f'停止Suricata进程时发生错误: {e}')
            return False
    
    def status(self) -> Dict[str, Any]:
        """获取Suricata进程状态
        
        Returns:
            Dict[str, Any]: 进程状态信息
        """
        status_info = {
            'running': self.running,
            'pid': None,
            'uptime': None,
            'memory_usage': None,
            'error': None
        }
        
        if self.running and self.process:
            try:
                # 获取进程信息
                status_info['pid'] = self.process.pid
                
                # 获取进程统计信息
                with open(f'/proc/{self.process.pid}/stat', 'r') as f:
                    stats = f.read().split()
                    start_time = float(stats[21]) / os.sysconf('SC_CLK_TCK')
                    uptime = time.time() - start_time
                    status_info['uptime'] = int(uptime)
                
                # 获取内存使用情况
                with open(f'/proc/{self.process.pid}/status', 'r') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            status_info['memory_usage'] = int(line.split()[1])
                            break
                
            except Exception as e:
                status_info['error'] = str(e)
        
        return status_info
    
    def is_running(self) -> bool:
        """检查Suricata进程是否在运行
        
        Returns:
            bool: 是否在运行
        """
        if not self.process:
            return False
        
        # 检查进程状态
        return self.process.poll() is None
    
    def analyze_pcap(self, pcap_file: str, log_dir: str = None, callback = None) -> Dict[str, Any]:
        """离线分析PCAP文件（非实时模式）
        
        Args:
            pcap_file: PCAP文件路径
            log_dir: 日志输出目录，如果为None则使用默认日志目录
            callback: 回调函数，接收告警事件作为参数
            
        Returns:
            Dict[str, Any]: 分析结果，包含成功状态和分析摘要
        """
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP文件不存在: {pcap_file}")
            return {"success": False, "error": f"PCAP文件不存在: {pcap_file}"}
        
        # 使用当前配置的日志目录或指定的日志目录
        output_log_dir = log_dir if log_dir else self.log_dir
        os.makedirs(output_log_dir, exist_ok=True)
        
        try:
            # 构建Suricata离线分析命令
            cmd = [
                self.binary_path,
                '-c', self.config_path,
                '-r', pcap_file,
                '--set', f'default-rule-path={self.rule_dir}',
                '-l', output_log_dir
            ]
            
            logger.info(f"开始离线分析PCAP文件: {pcap_file}")
            logger.debug(f"执行命令: {' '.join(cmd)}")
            
            # 启动独立的Suricata进程进行分析
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # 分析结果处理
            eve_json = os.path.join(output_log_dir, "eve.json")
            result = {"success": True, "alerts": [], "alert_count": 0}
            
            # 检查eve.json文件是否存在，如果存在则记录当前行数
            initial_line_count = 0
            if os.path.exists(eve_json):
                with open(eve_json, 'r') as f:
                    initial_line_count = sum(1 for _ in f)
                logger.info(f"分析前eve.json已有{initial_line_count}行")
            
            logger.info(f"等待Suricata完成PCAP分析...")
            
            # 等待分析完成
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Suricata分析失败: {stderr}")
                return {"success": False, "error": stderr}
            
            # 等待eve.json文件创建
            max_wait = 30  # 最大等待时间（秒）
            wait_time = 0
            while not os.path.exists(eve_json) and wait_time < max_wait:
                time.sleep(1)
                wait_time += 1
            
            if not os.path.exists(eve_json):
                logger.warning(f"等待{max_wait}秒后eve.json文件仍未创建")
                return {"success": False, "error": "未能创建分析结果文件"}
            
            # 分析完成后处理结果
            try:
                # 初始化数据包统计信息
                result["total_packets"] = 0
                result["reassembled_packets"] = 0
                result["lost_packets"] = 0
                result["total_bytes"] = 0
                result["tcp_flows"] = 0
                result["udp_flows"] = 0
                result["analyzed_flows"] = 0

                # 读取eve.json文件，只处理新增的行
                with open(eve_json, 'r') as f:
                    # 跳过已有的行
                    for _ in range(initial_line_count):
                        next(f, None)
                    
                    # 处理新增的行
                    for line in f:
                        if not line.strip():
                            continue
                            
                        try:
                            event = json.loads(line)
                            
                            # 处理告警事件
                            if event.get('event_type') == 'alert':
                                alert_info = {
                                    "signature": event.get('alert', {}).get('signature', '未知告警'),
                                    "severity": event.get('alert', {}).get('severity', '未知'),
                                    "src_ip": event.get('src_ip', '未知'),
                                    "src_port": event.get('src_port', '未知'),
                                    "dest_ip": event.get('dest_ip', '未知'),
                                    "dest_port": event.get('dest_port', '未知'),
                                    "proto": event.get('proto', '未知'),
                                    "timestamp": event.get('timestamp', ''),
                                    "category": event.get('alert', {}).get('category', ''),
                                    "action": event.get('alert', {}).get('action', '')
                                }
                                
                                # 添加到告警列表
                                result["alerts"].append(alert_info)
                                result["alert_count"] += 1
                                
                                # 如果提供了回调函数，调用它
                                if callback and callable(callback):
                                    callback(alert_info)
                                    
                                logger.info(f"检测到告警: {alert_info['signature']}")
                            
                            # 处理统计事件，提取数据包信息
                            elif event.get('event_type') == 'stats':
                                stats = event.get('stats', {})
                                decoder = stats.get('decoder', {})
                                flow = stats.get('flow', {})
                                defrag = stats.get('defrag', {})
                                
                                # 提取总数据包数
                                if 'pkts' in decoder:
                                    result["total_packets"] = decoder['pkts']
                                
                                # 提取总字节数
                                if 'bytes' in decoder:
                                    result["total_bytes"] = decoder['bytes']

                                # 提取所有的流量数
                                if 'total' in flow:
                                    result["analyzed_flows"] = flow['total']

                                # 提取分析的tcp流量数
                                if 'tcp' in flow:
                                    result["tcp_flows"] = flow['tcp']

                                # 提取分析的udp流量数
                                if 'udp' in flow:
                                    result["udp_flows"] = flow['udp']
                                
                                # 提取IPv4和IPv6重组数据包数
                                ipv4_reassembled = defrag.get('ipv4', {}).get('reassembled', 0)
                                ipv6_reassembled = defrag.get('ipv6', {}).get('reassembled', 0)
                                result["reassembled_packets"] = ipv4_reassembled + ipv6_reassembled
                                
                                # 计算丢失的数据包数（简单估算：总数据包 - 重组数据包）
                                # 注意：这是一个简化的计算，实际丢失数据包可能需要更复杂的逻辑
                                fragments_ipv4 = defrag.get('ipv4', {}).get('fragments', 0)
                                fragments_ipv6 = defrag.get('ipv6', {}).get('fragments', 0)
                                total_fragments = fragments_ipv4 + fragments_ipv6
                                
                                if total_fragments > result["reassembled_packets"]:
                                    result["lost_packets"] = total_fragments - result["reassembled_packets"]
                                
                                logger.info(f"提取到数据包统计信息: 总数据包={result['total_packets']}, 重组数据包={result['reassembled_packets']}, 丢失数据包={result['lost_packets']}")
                                
                        except json.JSONDecodeError:
                            logger.warning(f"无法解析JSON行: {line}")
                            continue
            except Exception as e:
                logger.error(f"处理分析结果时发生错误: {e}")
                return {"success": False, "error": str(e)}
            
            # 等待分析完成
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Suricata分析失败: {stderr}")
                return {"success": False, "error": stderr}
            
            # 如果从eve.json中没有获取到数据包统计信息，尝试从suricata.log中获取
            if result["total_packets"] == 0:
                suricata_log = os.path.join(output_log_dir, "suricata.log")
                if os.path.exists(suricata_log):
                    try:
                        with open(suricata_log, 'r') as f:
                            for line in f:
                                # 查找包含数据包统计信息的行
                                if "pcap: read" in line and "packets" in line:
                                    # 例如: [536457 - RX#01] 2025-04-21 23:07:45 Notice: pcap: read 1 file, 1577 packets, 223252 bytes
                                    parts = line.split()
                                    for i, part in enumerate(parts):
                                        if part == "packets,":
                                            result["total_packets"] = int(parts[i-1])
                                            logger.info(f"从suricata.log中提取到总数据包数: {result['total_packets']}")
                                            break
                    except Exception as e:
                        logger.warning(f"从suricata.log提取数据包统计信息时出错: {e}")
            
            logger.info("PCAP文件分析完成")
            result["log_file"] = eve_json
            
            # 确保数据包统计信息存在于结果中
            if "total_packets" not in result or result["total_packets"] == 0:
                # 如果无法从日志中获取，尝试从pcap文件名中提取（如果文件名中包含数据包数量信息）
                logger.warning("无法从日志中获取数据包统计信息，使用默认值")
            
            # 确保所有必要的字段都存在
            if "reassembled_packets" not in result:
                result["reassembled_packets"] = 0
            if "lost_packets" not in result:
                result["lost_packets"] = 0
            
            return result
            
        except Exception as e:
            logger.error(f"离线分析过程中发生错误: {e}")
            return {"success": False, "error": str(e)}
    
    def __del__(self):
        """析构函数，确保进程被正确关闭"""
        self.stop()