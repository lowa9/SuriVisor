#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SuriVisor - 基于Suricata的威胁分析系统

该文件是系统的Web应用入口，提供基于Flask的Web界面，用于在线和离线分析。
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_from_directory
from werkzeug.utils import secure_filename

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入SuriVisor类
from src.SuriVisor import SuriVisor

# 配置日志
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                   handlers=[
                       logging.FileHandler(os.path.join(os.path.dirname(__file__), '../data/logs/web_server.log')),
                       logging.StreamHandler()
                   ])
logger = logging.getLogger("WebServer")

# 创建Flask应用
app = Flask(__name__, 
            static_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), '../static')),
            template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), "../templates")))

# 配置上传文件目录
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), '../data/pcap')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 允许上传的文件扩展名
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

# 创建SuriVisor实例
surivisor = SuriVisor()

# 检查文件扩展名是否允许
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 首页路由
@app.route('/')
def index():
    return render_template('index.html')

# API路由：获取系统状态
@app.route('/api/status', methods=['GET'])
def get_status():
    status = {
        "running": surivisor.running,
        "timestamp": time.time(),
        "datetime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "components": {
            "packet_reassembler": surivisor.packet_reassembler is not None,
            "traffic_analyzer": surivisor.traffic_analyzer is not None,
            "anomaly_detector": surivisor.anomaly_detector is not None,
            "event_manager": hasattr(surivisor, 'event_manager') and surivisor.event_manager is not None,
            "report_generator": hasattr(surivisor, 'report_generator') and surivisor.report_generator is not None,
            "suricata_manager": hasattr(surivisor, 'suricata_manager') and surivisor.suricata_manager is not None
        }
    }
    return jsonify(status)

# API路由：启动在线分析
@app.route('/api/online/start', methods=['POST'])
def start_online_analysis():
    try:
        # 获取请求参数
        data = request.get_json() or {}
        start_suricata = data.get('start_suricata', True)
        
        # 启动在线分析
        if surivisor.running:
            return jsonify({"success": False, "message": "系统已经在运行"})
        
        # 初始化在线组件并启动
        success = surivisor.start(start_suricata=start_suricata)
        
        if success:
            return jsonify({"success": True, "message": "在线分析已启动"})
        else:
            return jsonify({"success": False, "message": "启动在线分析失败"})
    except Exception as e:
        logger.error(f"启动在线分析时发生错误: {e}")
        return jsonify({"success": False, "message": f"发生错误: {str(e)}"}), 500

# API路由：停止在线分析
@app.route('/api/online/stop', methods=['POST'])
def stop_online_analysis():
    try:
        if not surivisor.running:
            return jsonify({"success": False, "message": "系统未在运行"})
        
        success = surivisor.stop()
        
        if success:
            return jsonify({"success": True, "message": "在线分析已停止"})
        else:
            return jsonify({"success": False, "message": "停止在线分析失败"})
    except Exception as e:
        logger.error(f"停止在线分析时发生错误: {e}")
        return jsonify({"success": False, "message": f"发生错误: {str(e)}"}), 500

# API路由：上传PCAP文件进行离线分析
@app.route('/api/offline/upload', methods=['POST'])
def upload_pcap():
    # 检查是否有文件上传
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "没有上传文件"})
    
    file = request.files['file']
    
    # 检查文件名是否为空
    if file.filename == '':
        return jsonify({"success": False, "message": "未选择文件"})
    
    # 检查文件类型是否允许
    if not allowed_file(file.filename):
        return jsonify({"success": False, "message": f"不支持的文件类型，允许的类型: {', '.join(ALLOWED_EXTENSIONS)}"})
    
    try:
        # 安全地获取文件名并保存文件
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
        
        file.save(file_path)
        logger.info(f"文件已上传: {file_path}")
        
        return jsonify({
            "success": True, 
            "message": "文件上传成功",
            "file_path": file_path,
            "filename": saved_filename
        })
    except Exception as e:
        logger.error(f"上传文件时发生错误: {e}")
        return jsonify({"success": False, "message": f"上传文件时发生错误: {str(e)}"}), 500

# API路由：分析已上传的PCAP文件
@app.route('/api/offline/analyze', methods=['POST'])
def analyze_pcap():
    try:
        data = request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({"success": False, "message": "缺少文件路径参数"})
        
        file_path = data['file_path']
        
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return jsonify({"success": False, "message": f"文件不存在: {file_path}"})
        
        # 执行离线分析
        logger.info(f"开始分析PCAP文件: {file_path}")
        success = surivisor.analyze_pcap_file(file_path)
        
        if success:
            # 获取生成的报告文件
            reports_dir = os.path.join(os.path.dirname(__file__), '../data/reports')
            pcap_basename = os.path.basename(file_path)
            report_prefix = f"pcap_analysis_{os.path.splitext(pcap_basename)[0]}"
            
            # 查找最新的报告文件
            report_files = [f for f in os.listdir(reports_dir) if f.startswith(report_prefix) and f.endswith('.html')]
            report_files.sort(reverse=True)  # 按文件名排序，最新的在前面
            
            report_url = None
            if report_files:
                report_url = f"/reports/{report_files[0]}"
            
            return jsonify({
                "success": True, 
                "message": "PCAP文件分析完成",
                "report_url": report_url
            })
        else:
            return jsonify({"success": False, "message": "PCAP文件分析失败"})
    except Exception as e:
        logger.error(f"分析PCAP文件时发生错误: {e}")
        return jsonify({"success": False, "message": f"分析PCAP文件时发生错误: {str(e)}"}), 500

# 路由：获取报告文件
@app.route('/reports/<path:filename>')
def get_report(filename):
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/reports'))
    logger.info(f"报告目录: {reports_dir}")
    return send_from_directory(reports_dir, filename)

# API路由：获取系统报告
@app.route('/api/reports/generate', methods=['POST'])
def generate_system_report():
    try:
        data = request.get_json() or {}
        report_type = data.get('report_type', 'html')
        
        # 生成报告
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"system_report_{timestamp}.{report_type}"
        report_path = os.path.join(os.path.dirname(__file__), f'../data/reports/{report_filename}')
        
        # 调用SuriVisor的报告生成方法
        report_file = surivisor.generate_report(output_file=report_path, report_type=report_type)
        
        if report_file:
            return jsonify({
                "success": True, 
                "message": "系统报告生成成功",
                "report_url": f"/reports/{report_filename}"
            })
        else:
            return jsonify({"success": False, "message": "生成系统报告失败"})
    except Exception as e:
        logger.error(f"生成系统报告时发生错误: {e}")
        return jsonify({"success": False, "message": f"生成系统报告时发生错误: {str(e)}"}), 500

# API路由：获取告警列表
@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        # 获取告警目录
        alerts_dir = os.path.join(os.path.dirname(__file__), '../data/alerts')
        os.makedirs(alerts_dir, exist_ok=True)
        
        # 读取所有告警文件
        alerts = []
        for alert_file in os.listdir(alerts_dir):
            if alert_file.endswith('.json'):
                try:
                    with open(os.path.join(alerts_dir, alert_file), 'r') as f:
                        alert_data = json.load(f)
                        alerts.append(alert_data)
                except Exception as e:
                    logger.error(f"读取告警文件 {alert_file} 时发生错误: {e}")
        
        # 按时间戳排序，最新的在前面
        alerts.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        
        return jsonify({
            "success": True,
            "alerts": alerts,
            "total": len(alerts)
        })
    except Exception as e:
        logger.error(f"获取告警列表时发生错误: {e}")
        return jsonify({"success": False, "message": f"获取告警列表时发生错误: {str(e)}"}), 500

# 主函数
if __name__ == '__main__':
    # 确保必要的目录存在
    os.makedirs(os.path.join(os.path.dirname(__file__), '../data/logs'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), '../data/pcap'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), '../data/reports'), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), '../data/alerts'), exist_ok=True)
    
    # 启动Flask应用
    port = surivisor.config["ui"]["web_server_port"]
    app.run(host='0.0.0.0', port=port, debug=surivisor.config["general"]["debug"])