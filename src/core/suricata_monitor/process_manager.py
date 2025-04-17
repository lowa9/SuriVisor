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
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SuricataProcessManager:
    """Suricata进程管理器"""
    
    def __init__(self, 
                 binary_path: str = '/usr/bin/suricata',
                 config_path: str = '/etc/suricata/suricata.yaml',
                 rule_path: str = '/etc/suricata/rules',
                 log_dir: str = '/var/log/suricata',
                 pid_file: str = '/var/run/suricata.pid'):
        """初始化Suricata进程管理器
        
        Args:
            binary_path: Suricata可执行文件路径
            config_path: Suricata配置文件路径
            rule_path: Suricata规则目录
            log_dir: 日志目录
            pid_file: PID文件路径
        """
        self.binary_path = binary_path
        self.config_path = config_path
        self.rule_path = rule_path
        self.log_dir = log_dir
        self.pid_file = pid_file
        
        # Suricata进程
        self.process: Optional[subprocess.Popen] = None
        self.running = False
        
        # 确保日志目录存在
        os.makedirs(log_dir, exist_ok=True)
    
    def start(self, interface: str = 'any') -> bool:
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
                '--set', f'default-rule-path={self.rule_path}',
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
    
    def __del__(self):
        """析构函数，确保进程被正确关闭"""
        self.stop()