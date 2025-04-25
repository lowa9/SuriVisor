#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
会话ID功能测试脚本

用于验证Suricata实时分析时的会话ID功能是否正常工作。
"""

import os
import sys
import time
import json
import logging

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入SuricataProcessManager
from src.core.suricata_monitor.process_manager import SuricataProcessManager

# 配置日志
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SessionIDTest")

def main():
    # 初始化Suricata进程管理器
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/logs/suricata'))
    manager = SuricataProcessManager(
        binary_path='/usr/bin/suricata',
        config_path='/home/kai/SuriVisor/config/suricata.yaml',  # 根据实际情况调整
        rule_dir='/home/kai/SuriVisor/config/rules',            # 根据实际情况调整
        log_dir=log_dir,
        pid_file=os.path.join(log_dir, 'suricata.pid')
    )
    
    try:
        # 启动Suricata进程
        logger.info("正在启动Suricata进程...")
        if manager.start(interface='ens33'):  # 根据实际情况调整网络接口
            # 获取会话ID
            session_id = manager.get_current_session_id()
            logger.info(f"Suricata进程启动成功，会话ID: {session_id}")
            
            # 验证会话ID文件是否存在
            if os.path.exists(manager.session_id_file):
                with open(manager.session_id_file, 'r') as f:
                    content = f.read().strip()
                    logger.info(f"会话ID文件内容: {content}")
                    
                    # 验证文件内容是否正确
                    expected = f"SURICATA_SESSION_ID={session_id}"
                    if content == expected:
                        logger.info("会话ID文件内容验证成功")
                    else:
                        logger.error(f"会话ID文件内容验证失败，期望: {expected}, 实际: {content}")
            else:
                logger.error(f"会话ID文件不存在: {manager.session_id_file}")
            
            # 运行一段时间，让Logstash有时间处理数据
            logger.info("Suricata正在运行，请等待Logstash处理数据...")
            logger.info("您可以在Kibana中查询session_id字段验证功能是否正常工作")
            logger.info(f"会话ID: {session_id}")
            
            # 等待用户输入以停止
            input("按Enter键停止Suricata进程...")
            
            # 停止Suricata进程
            logger.info("正在停止Suricata进程...")
            if manager.stop():
                logger.info("Suricata进程已停止")
                
                # 验证会话ID文件是否被删除
                if not os.path.exists(manager.session_id_file):
                    logger.info("会话ID文件已被正确删除")
                else:
                    logger.warning(f"会话ID文件未被删除: {manager.session_id_file}")
            else:
                logger.error("停止Suricata进程失败")
        else:
            logger.error("启动Suricata进程失败")
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在停止Suricata进程...")
        manager.stop()
    except Exception as e:
        logger.exception(f"测试过程中发生错误: {e}")
        manager.stop()

if __name__ == "__main__":
    main()