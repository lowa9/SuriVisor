# src/api/server.py

from flask import Flask, jsonify, request
from src.main import SuriVisor

def create_app(surivisor_instance):
    """
    创建Flask应用并注册所有API端点
    
    Args:
        surivisor_instance (SuriVisor): 已初始化的SuriVisor实例
    """
    app = Flask(__name__)
    
    # 存储SuriVisor实例引用
    app.surivisor = surivisor_instance

    @app.route('/api/start', methods=['POST'])
    def start_system():
        """启动系统端点"""
        if app.surivisor.start():
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "启动失败"}), 500

    @app.route('/api/stop', methods=['POST'])
    def stop_system():
        """停止系统端点"""
        if app.surivisor.stop():
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "停止失败"}), 500

    @app.route('/api/status', methods=['GET'])
    def get_status():
        """获取系统状态"""
        return jsonify({
            "running": app.surivisor.running,
            "components": {
                "suricata": app.surivisor.suricata_manager is not None,
                "traffic_analysis": app.surivisor.traffic_analyzer is not None
            }
        })

    @app.route('/api/events', methods=['GET'])
    def get_events():
        """获取最近事件"""
        if app.surivisor.event_manager:
            events = app.surivisor.event_manager.get_recent_events(limit=50)
            return jsonify({"events": [e.to_dict() for e in events]})
        return jsonify({"events": []})

    @app.route('/api/analyze/pcap', methods=['POST'])
    def analyze_pcap():
        """分析PCAP文件"""
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "未提供文件"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"status": "error", "message": "未选择文件"}), 400
        
        if app.surivisor.packet_reassembler:
            result = app.surivisor.packet_reassembler.process_pcap(file)
            return jsonify({"status": "success", "result": result})
        
        return jsonify({"status": "error", "message": "数据包重组器未初始化"}), 500

    @app.route('/api/threats/detect', methods=['POST'])
    def detect_threats():
        """检测流量中的威胁"""
        data = request.get_json()
        if not data or 'flow_data' not in data:
            return jsonify({"status": "error", "message": "无效请求数据"}), 400
        
        if app.surivisor.traffic_analyzer:
            threats = app.surivisor.traffic_analyzer.detect_threats(data['flow_data'])
            return jsonify({"status": "success", "threats": threats})
        
        return jsonify({"status": "error", "message": "流量分析器未初始化"}), 500

    @app.route('/api/es/data', methods=['GET'])
    def get_es_data():
        """获取Elasticsearch中的数据"""
        if not app.surivisor.suricata_monitor:
            return jsonify({"status": "error", "message": "Suricata监控器未初始化"}), 500
            
        try:
            # 获取查询参数
            query = request.args.get('query')
            size = int(request.args.get('size', 100))
            
            # 解析查询参数
            es_query = json.loads(query) if query else None
            
            # 查询数据
            data = app.surivisor.suricata_monitor.get_es_data(es_query, size)
            return jsonify({"status": "success", "data": data})
            
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
            
    return app