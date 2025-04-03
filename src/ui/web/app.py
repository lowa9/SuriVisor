#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SuriVisor Web界面

该模块实现了SuriVisor的Web界面，提供了流量分析、异常检测和PCAP管理等功能。
"""

import os
import sys
import json
import time
import logging
import datetime
import threading
from flask import Flask, render_template, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

# 导入核心模块
from src.core.packet_reassembly.enhanced_reassembler import EnhancedPacketReassembler
from src.core.traffic_analysis.traffic_analyzer import TrafficAnalyzer
from src.core.anomaly_detection.anomaly_detector import AnomalyDetector

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 创建Flask应用
app = Flask(__name__)

# 配置
app.config['UPLOAD_FOLDER'] = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../data/pcap'))
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 限制上传文件大小为500MB
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng'}

# 确保上传目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 全局变量
reassembler = None
traffic_analyzer = None
anomaly_detector = None
replay_status = {
    'running': False,
    'paused': False,
    'file': None,
    'progress': 0,
    'packets_sent': 0,
    'bytes_sent': 0,
    'start_time': 0,
    'speed': 1.0,
    'interface': None,
    'filter': None,
    'loop': 1,
    'analyze': False,
    'thread': None
}


def allowed_file(filename):
    """
    检查文件扩展名是否允许上传
    
    Args:
        filename (str): 文件名
        
    Returns:
        bool: 是否允许上传
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def get_pcap_info(file_path):
    """
    获取PCAP文件信息
    
    Args:
        file_path (str): PCAP文件路径
        
    Returns:
        dict: PCAP文件信息
    """
    import pyshark
    
    try:
        # 使用pyshark读取PCAP文件
        cap = pyshark.FileCapture(file_path, only_summaries=True)
        
        # 获取基本信息
        packet_count = 0
        protocols = {}
        first_timestamp = None
        last_timestamp = None
        total_bytes = 0
        
        # 读取前100个数据包进行分析
        packets = []
        for i, packet in enumerate(cap):
            if i >= 100:
                break
                
            packet_count += 1
            
            # 提取协议
            protocol = packet.protocol
            protocols[protocol] = protocols.get(protocol, 0) + 1
            
            # 提取时间戳
            timestamp = float(packet.time)
            if first_timestamp is None or timestamp < first_timestamp:
                first_timestamp = timestamp
            if last_timestamp is None or timestamp > last_timestamp:
                last_timestamp = timestamp
            
            # 提取大小
            try:
                packet_length = int(packet.length)
                total_bytes += packet_length
            except:
                pass
            
            # 添加到预览列表
            if i < 20:  # 只保存前20个数据包用于预览
                packets.append({
                    'number': i + 1,
                    'time': packet.time,
                    'source': packet.source,
                    'destination': packet.destination,
                    'protocol': protocol,
                    'length': packet.length if hasattr(packet, 'length') else 'N/A',
                    'info': packet.info
                })
        
        # 计算持续时间
        duration = last_timestamp - first_timestamp if first_timestamp and last_timestamp else 0
        
        # 获取文件大小
        file_size = os.path.getsize(file_path)
        
        # 获取上传时间（使用文件修改时间）
        upload_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        
        return {
            'filename': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': file_size,
            'file_size_human': format_size(file_size),
            'upload_time': upload_time,
            'packet_count': packet_count,
            'duration': duration,
            'duration_human': format_duration(duration),
            'protocols': protocols,
            'packets': packets,
            'total_bytes': total_bytes,
            'bytes_per_second': total_bytes / duration if duration > 0 else 0
        }
    except Exception as e:
        logger.error(f"获取PCAP文件信息失败: {e}")
        return {
            'filename': os.path.basename(file_path),
            'file_path': file_path,
            'file_size': os.path.getsize(file_path),
            'file_size_human': format_size(os.path.getsize(file_path)),
            'upload_time': datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
            'error': str(e)
        }


def format_size(size_bytes):
    """
    格式化文件大小
    
    Args:
        size_bytes (int): 文件大小（字节）
        
    Returns:
        str: 格式化后的文件大小
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def format_duration(seconds):
    """
    格式化持续时间
    
    Args:
        seconds (float): 持续时间（秒）
        
    Returns:
        str: 格式化后的持续时间
    """
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)
    
    if hours > 0:
        return f"{hours}时{minutes}分{seconds}秒"
    elif minutes > 0:
        return f"{minutes}分{seconds}秒"
    else:
        return f"{seconds}秒"


def replay_pcap(file_path, interface, speed=1.0, bpf_filter=None, loop=1, analyze=False):
    """
    回放PCAP文件
    
    Args:
        file_path (str): PCAP文件路径
        interface (str): 网络接口
        speed (float): 回放速度
        bpf_filter (str): BPF过滤器
        loop (int): 循环次数
        analyze (bool): 是否进行分析
    """
    global replay_status
    
    try:
        import pyshark
        from scapy.all import rdpcap, sendp
        
        # 更新状态
        replay_status['running'] = True
        replay_status['paused'] = False
        replay_status['file'] = file_path
        replay_status['progress'] = 0
        replay_status['packets_sent'] = 0
        replay_status['bytes_sent'] = 0
        replay_status['start_time'] = time.time()
        replay_status['speed'] = speed
        replay_status['interface'] = interface
        replay_status['filter'] = bpf_filter
        replay_status['loop'] = loop
        replay_status['analyze'] = analyze
        
        # 读取PCAP文件
        logger.info(f"开始读取PCAP文件: {file_path}")
        packets = rdpcap(file_path)
        total_packets = len(packets)
        logger.info(f"读取完成，共{total_packets}个数据包")
        
        # 获取第一个数据包的时间戳作为基准
        if total_packets > 0:
            base_time = packets[0].time
        else:
            logger.warning("PCAP文件中没有数据包")
            replay_status['running'] = False
            return
        
        # 循环回放
        for loop_count in range(loop):
            if not replay_status['running']:
                break
                
            logger.info(f"开始第{loop_count + 1}次回放")
            
            # 回放数据包
            last_time = base_time
            for i, packet in enumerate(packets):
                # 检查是否停止
                if not replay_status['running']:
                    break
                    
                # 检查是否暂停
                while replay_status['paused']:
                    time.sleep(0.1)
                    if not replay_status['running']:
                        break
                
                # 计算延迟
                if i > 0:
                    delay = (packet.time - last_time) / speed
                    if delay > 0:
                        time.sleep(delay)
                
                # 应用BPF过滤器
                if bpf_filter:
                    # 简单实现，实际应该使用更复杂的BPF解析
                    if 'tcp' in bpf_filter and packet.haslayer('TCP'):
                        pass  # 通过过滤器
                    elif 'udp' in bpf_filter and packet.haslayer('UDP'):
                        pass  # 通过过滤器
                    elif 'icmp' in bpf_filter and packet.haslayer('ICMP'):
                        pass  # 通过过滤器
                    else:
                        continue  # 不通过过滤器，跳过该数据包
                
                # 发送数据包
                sendp(packet, iface=interface, verbose=0)
                
                # 更新状态
                replay_status['packets_sent'] += 1
                replay_status['bytes_sent'] += len(packet)
                replay_status['progress'] = (i + 1 + loop_count * total_packets) / (total_packets * loop) * 100
                
                # 更新时间戳
                last_time = packet.time
                
                # 如果启用分析，将数据包发送到分析器
                if analyze and traffic_analyzer:
                    # 这里应该实现将数据包发送到分析器的逻辑
                    pass
            
            logger.info(f"第{loop_count + 1}次回放完成")
        
        logger.info("回放完成")
        replay_status['running'] = False
        replay_status['progress'] = 100
    
    except Exception as e:
        logger.error(f"回放PCAP文件失败: {e}")
        replay_status['running'] = False


@app.route('/')
def index():
    """
    首页
    """
    return render_template('index.html')


@app.route('/pcap')
def pcap_manager():
    """
    PCAP管理页面
    """
    return render_template('pcap.html')


@app.route('/api/pcap/list')
def api_pcap_list():
    """
    获取PCAP文件列表
    """
    try:
        pcap_files = []
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            if allowed_file(filename):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file_info = {
                    'filename': filename,
                    'file_size': os.path.getsize(file_path),
                    'file_size_human': format_size(os.path.getsize(file_path)),
                    'upload_time': datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                }
                pcap_files.append(file_info)
        
        return jsonify({
            'status': 'success',
            'data': pcap_files
        })
    except Exception as e:
        logger.error(f"获取PCAP文件列表失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/upload', methods=['POST'])
def api_pcap_upload():
    """
    上传PCAP文件
    """
    try:
        # 检查是否有文件
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'message': '没有文件部分'
            }), 400
        
        file = request.files['file']
        
        # 检查文件名
        if file.filename == '':
            return jsonify({
                'status': 'error',
                'message': '没有选择文件'
            }), 400
        
        # 检查文件类型
        if not allowed_file(file.filename):
            return jsonify({
                'status': 'error',
                'message': '不支持的文件类型'
            }), 400
        
        # 保存文件
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # 获取文件信息
        file_info = {
            'filename': filename,
            'file_size': os.path.getsize(file_path),
            'file_size_human': format_size(os.path.getsize(file_path)),
            'upload_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return jsonify({
            'status': 'success',
            'data': file_info
        })
    except Exception as e:
        logger.error(f"上传PCAP文件失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/info/<filename>')
def api_pcap_info(filename):
    """
    获取PCAP文件信息
    
    Args:
        filename (str): 文件名
    """
    try:
        # 检查文件是否存在
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        if not os.path.exists(file_path):
            return jsonify({
                'status': 'error',
                'message': '文件不存在'
            }), 404
        
        # 获取文件信息
        file_info = get_pcap_info(file_path)
        
        return jsonify({
            'status': 'success',
            'data': file_info
        })
    except Exception as e:
        logger.error(f"获取PCAP文件信息失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/download/<filename>')
def api_pcap_download(filename):
    """
    下载PCAP文件
    
    Args:
        filename (str): 文件名
    """
    try:
        # 检查文件是否存在
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        if not os.path.exists(file_path):
            abort(404)
        
        # 发送文件
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        logger.error(f"下载PCAP文件失败: {e}")
        abort(500)


@app.route('/api/pcap/delete/<filename>', methods=['DELETE'])
def api_pcap_delete(filename):
    """
    删除PCAP文件
    
    Args:
        filename (str): 文件名
    """
    try:
        # 检查文件是否存在
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        if not os.path.exists(file_path):
            return jsonify({
                'status': 'error',
                'message': '文件不存在'
            }), 404
        
        # 删除文件
        os.remove(file_path)
        
        return jsonify({
            'status': 'success',
            'message': '文件已删除'
        })
    except Exception as e:
        logger.error(f"删除PCAP文件失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/replay/start', methods=['POST'])
def api_pcap_replay_start():
    """
    开始回放PCAP文件
    """
    global replay_status
    
    try:
        # 检查是否已经在回放
        if replay_status['running'] and not replay_status['paused']:
            return jsonify({
                'status': 'error',
                'message': '已经有回放在进行中'
            }), 400
        
        # 获取参数
        data = request.json
        filename = data.get('filename')
        interface = data.get('interface')
        speed = float(data.get('speed', 1.0))
        bpf_filter = data.get('filter')
        loop = int(data.get('loop', 1))
        analyze = bool(data.get('analyze', False))
        
        # 检查文件是否存在
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        if not os.path.exists(file_path):
            return jsonify({
                'status': 'error',
                'message': '文件不存在'
            }), 404
        
        # 如果已暂停，继续回放
        if replay_status['running'] and replay_status['paused']:
            replay_status['paused'] = False
            return jsonify({
                'status': 'success',
                'message': '回放已继续'
            })
        
        # 启动回放线程
        replay_thread = threading.Thread(
            target=replay_pcap,
            args=(file_path, interface, speed, bpf_filter, loop, analyze)
        )
        replay_thread.daemon = True
        replay_thread.start()
        
        replay_status['thread'] = replay_thread
        
        return jsonify({
            'status': 'success',
            'message': '回放已开始'
        })
    except Exception as e:
        logger.error(f"开始回放PCAP文件失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/replay/pause', methods=['POST'])
def api_pcap_replay_pause():
    """
    暂停回放PCAP文件
    """
    global replay_status
    
    try:
        # 检查是否在回放
        if not replay_status['running']:
            return jsonify({
                'status': 'error',
                'message': '没有回放在进行中'
            }), 400
        
        # 检查是否已经暂停
        if replay_status['paused']:
            return jsonify({
                'status': 'error',
                'message': '回放已经暂停'
            }), 400
        
        # 暂停回放
        replay_status['paused'] = True
        
        return jsonify({
            'status': 'success',
            'message': '回放已暂停'
        })
    except Exception as e:
        logger.error(f"暂停回放PCAP文件失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/replay/stop', methods=['POST'])
def api_pcap_replay_stop():
    """
    停止回放PCAP文件
    """
    global replay_status
    
    try:
        # 检查是否在回放
        if not replay_status['running']:
            return jsonify({
                'status': 'error',
                'message': '没有回放在进行中'
            }), 400
        
        # 停止回放
        replay_status['running'] = False
        replay_status['paused'] = False
        
        # 等待线程结束
        if replay_status['thread'] and replay_status['thread'].is_alive():
            replay_status['thread'].join(timeout=2)
        
        return jsonify({
            'status': 'success',
            'message': '回放已停止'
        })
    except Exception as e:
        logger.error(f"停止回放PCAP文件失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/pcap/replay/status')
def api_pcap_replay_status():
    """
    获取回放状态
    """
    global replay_status
    
    try:
        # 计算实时速率
        current_time = time.time()
        elapsed_time = current_time - replay_status['start_time'] if replay_status['start_time'] > 0 else 0
        packets_per_second = replay_status['packets_sent'] / elapsed_time if elapsed_time > 0 else 0
        bytes_per_second = replay_status['bytes_sent'] / elapsed_time if elapsed_time > 0 else 0
        
        status = {
            'running': replay_status['running'],
            'paused': replay_status['paused'],
            'file': os.path.basename(replay_status['file']) if replay_status['file'] else None,
            'progress': replay_status['progress'],
            'packets_sent': replay_status['packets_sent'],
            'bytes_sent': replay_status['bytes_sent'],
            'bytes_sent_human': format_size(replay_status['bytes_sent']),
            'elapsed_time': elapsed_time,
            'elapsed_time_human': format_duration(elapsed_time),
            'packets_per_second': packets_per_second,
            'bytes_per_second': bytes_per_second,
            'bytes_per_second_human': format_size(bytes_per_second) + '/s',
            'speed': replay_status['speed'],
            'interface': replay_status['interface'],
            'filter': replay_status['filter'],
            'loop': replay_status['loop'],
            'analyze': replay_status['analyze']
        }
        
        return jsonify({
            'status': 'success',
            'data': status
        })
    except Exception as e:
        logger.error(f"获取回放状态失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/interfaces')
def api_interfaces():
    """
    获取网络接口列表
    """
    try:
        import netifaces
        
        interfaces = []
        for iface in netifaces.interfaces():
            # 排除回环接口
            if iface != 'lo':
                try:
                    # 获取接口地址
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        interfaces.append({
                            'name': iface,
                            'ip': ip
                        })
                    else:
                        interfaces.append({
                            'name': iface,
                            'ip': 'N/A'
                        })
                except:
                    interfaces.append({
                        'name': iface,
                        'ip': 'Error'
                    })
        
        return jsonify({
            'status': 'success',
            'data': interfaces
        })
    except Exception as e:
        logger.error(f"获取网络接口列表失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/stats')
def api_stats():
    """
    获取系统统计信息
    """
    global reassembler, traffic_analyzer, anomaly_detector
    
    try:
        stats = {
            'timestamp': time.time(),
            'datetime': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 获取重组器统计信息
        if reassembler:
            stats['reassembler'] = reassembler.get_reassembly_statistics()
        
        # 获取流量分析器统计信息
        if traffic_analyzer:
            stats['analyzer'] = traffic_analyzer.get_statistics()
        
        # 获取异常检测器统计信息
        if anomaly_detector:
            # 这里应该实现获取异常检测器统计信息的逻辑
            pass
        
        return jsonify({
            'status': 'success',
            'data': stats
        })
    except Exception as e:
        logger.error(f"获取系统统计信息失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/alerts')
def api_alerts():
    """
    获取告警信息
    """
    global anomaly_detector
    
    try:
        if not anomaly_detector:
            return jsonify({
                'status': 'error',
                'message': '异常检测器未初始化'
            }), 400
        
        # 获取告警历史
        alerts = anomaly_detector.alert_history
        
        return jsonify({
            'status': 'success',
            'data': alerts
        })
    except Exception as e:
        logger.error(f"获取告警信息失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/init', methods=['POST'])
def api_init():
    """
    初始化系统组件
    """
    global reassembler, traffic_analyzer, anomaly_detector
    
    try:
        data = request.json or {}
        
        # 初始化重组器
        if not reassembler:
            timeout = data.get('timeout', 60)
            max_fragments = data.get('max_fragments', 2000)
            buffer_size = data.get('buffer_size', 20971520)
            cleanup_interval = data.get('cleanup_interval', 300)
            enable_adaptive_timeout = data.get('enable_adaptive_timeout', True)
            
            reassembler = EnhancedPacketReassembler(
                timeout=timeout,
                max_fragments=max_fragments,
                buffer_size=buffer_size,
                cleanup_interval=cleanup_interval,
                enable_adaptive_timeout=enable_adaptive_timeout
            )
            logger.info("重组器初始化完成")
        
        # 初始化流量分析器
        if not traffic_analyzer:
            # 这里应该根据实际情况初始化流量分析器
            traffic_analyzer = TrafficAnalyzer()
            logger.info("流量分析器初始化完成")
        
        # 初始化异常检测器
        if not anomaly_detector:
            # 这里应该根据实际情况初始化异常检测器
            config_path = data.get('anomaly_config', os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../config/anomaly_detection.json')))
            anomaly_detector = AnomalyDetector(config_path=config_path)
            logger.info("异常检测器初始化完成")
        
        return jsonify({
            'status': 'success',
            'message': '系统组件初始化完成'
        })
    except Exception as e:
        logger.error(f"初始化系统组件失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


def init_components():
    """
    初始化系统组件
    """
    global reassembler, traffic_analyzer, anomaly_detector
    
    try:
        # 初始化重组器
        if not reassembler:
            reassembler = EnhancedPacketReassembler()
            logger.info("重组器初始化完成")
        
        # 初始化流量分析器
        if not traffic_analyzer:
            traffic_analyzer = TrafficAnalyzer()
            logger.info("流量分析器初始化完成")
        
        # 初始化异常检测器
        if not anomaly_detector:
            config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../config/anomaly_detection.json'))
            if os.path.exists(config_path):
                anomaly_detector = AnomalyDetector(config_path=config_path)
                logger.info("异常检测器初始化完成")
            else:
                logger.warning(f"异常检测配置文件不存在: {config_path}")
    except Exception as e:
        logger.error(f"初始化系统组件失败: {e}")


if __name__ == '__main__':
    # 初始化系统组件
    init_components()
    
    # 启动Flask应用
    app.run(host='0.0.0.0', port=5000, debug=True)