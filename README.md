# SuriVisor - 基于Suricata的威胁分析系统

## 项目概述

SuriVisor是一个基于Suricata的综合性网络威胁分析系统，旨在提供高效的离线流量分析、网络报文异常处理以及实时威胁检测功能。本系统通过整合多种安全分析技术，为网络安全分析人员提供一个强大的工具平台。

## 系统目标

### 1. 离线流量分析工具
- 构建不少于5种典型网络攻击场景（扫描、DDoS、ARP攻击、暴力破解等）
- 开发高效的数据包重组算法，确保在网络拥塞情况下达到60%以上的还原率
- 实现用户友好的界面，支持报文的下载和回放分析
- 实现自动化的流量模式识别与分类，达到60%的分类准确率

### 2. 网络报文异常处理机制
- 设计并实现对关键网络指标（乱序比例、丢包比例等）的监测机制
- 保证关键网络指标监测覆盖率达到80%，报警响应时间不超过3分钟
- 构造不少于5种网络攻击场景，记录异常事件并生成详细报告

### 3. 系统集成与性能优化
- 集成实时流量分析、威胁检测和流量回放功能
- 确保系统在大规模流量场景下稳定运行，满足实时性要求
- 实现实时告警通知机制，支持WebSocket推送
- 提供协议分布可视化和流量统计图表

## 系统架构

系统采用模块化设计，主要包含以下核心组件：

1. **Suricata核心引擎**：负责网络流量捕获和初步分析
2. **数据包重组模块**：实现高效的数据包重组算法
3. **流量分析模块**：处理捕获的流量数据，识别潜在威胁
4. **异常检测模块**：监测网络异常指标，生成告警
5. **用户界面**：提供友好的操作界面和可视化展示
6. **报告系统**：生成详细的分析报告和安全建议
7. **WebSocket服务**：提供实时告警推送功能
8. **降级机制**：在系统负载过高时自动降级，确保核心功能可用

## 项目结构

```
SuriVisor/
├── .data/                 # 数据存储目录
│   └── es_data/           # Elasticsearch数据
├── config/                # 配置文件
│   ├── logstash/          # Logstash配置
│   │   ├── README.md      # Logstash配置说明
│   │   └── suricata.conf  # Suricata日志处理配置
│   ├── rules/             # Suricata规则
│   │   ├── README.md      # 规则说明
│   │   ├── brute_force.rules      # 暴力破解检测规则
│   │   ├── classification.config  # 分类配置
│   │   ├── ddos_detection.rules   # DDoS检测规则
│   │   └── scan_detection.rules   # 扫描检测规则
│   ├── suricata.yaml      # Suricata配置文件
│   └── system.conf        # 系统配置文件
├── data/                  # 数据目录
│   └── logs/              # 系统日志
│       ├── suricata/      # Suricata运行日志
│       └── web_server.log # Web服务器日志
├── docker-compose.yml     # Docker部署配置
├── requirements.txt       # Python依赖项
├── scripts/               # 脚本工具
│   ├── clean.sh           # 清理脚本
│   ├── setup.sh           # 系统安装脚本
│   └── start.sh           # 启动脚本
├── src/                   # 源代码目录
│   ├── SuriVisor.py       # 主类实现
│   ├── core/              # 核心功能模块
│   │   ├── ElasticSearch/ # ES客户端模块
│   │   ├── event_detection/   # 事件检测模块
│   │   ├── event_manager/     # 事件管理模块
│   │   ├── report_generator/  # 报告生成模块
│   │   ├── suricata_monitor/  # Suricata监控模块
│   │   └── traffic_analysis/  # 流量分析模块
│   ├── main.py            # Web应用入口
│   └── utils/             # 工具函数
│       ├── __init__.py
│       ├── alert_utils.py # 告警处理工具
│       ├── result_utils.py # 结果处理工具
│       ├── system_utils.py # 系统工具
│       └── websocket_manager.py # WebSocket管理器
├── templates/             # 模板文件
│   ├── index.html         # 主页模板
│   └── report.html        # 报告模板
├── tests/                 # 测试目录
│   ├── integration/       # 集成测试
│   ├── sc.json            # 测试配置
│   └── unit/              # 单元测试
│       ├── test_anomaly_detector.py
│       ├── test_esclient.py
│       ├── test_event_manager.py
│       ├── test_packet_reassembler.py
│       ├── test_report_generator.py
│       └── test_traffic_analyzer.py
└── tools/                 # 辅助工具
    ├── deploy_logstash_config.sh # Logstash配置部署工具
    └── test_session_id.py        # 会话ID测试工具
```

## 实现计划

### 阶段一：基础架构搭建（已完成）
- 搭建Suricata运行环境
- 设计并实现系统核心架构
- 开发基础数据处理模块

### 阶段二：核心功能实现（已完成）
- 实现数据包重组算法
- 开发流量分析模块
- 构建异常检测机制
- 实现WebSocket实时通知功能

### 阶段三：用户界面与集成（进行中）
- 开发Web界面和仪表盘
- 集成各功能模块
- 实现报告生成系统
- 添加协议分布可视化功能

### 阶段四：测试与优化（计划中）
- 构建测试场景
- 进行性能测试和优化
- 系统集成测试
- 实现系统降级机制

## 技术栈

- **后端**：
  - Python 3.8+
  - Flask 2.0+ (Web服务)
  - Flask-SocketIO 5.3+ (WebSocket支持)
  - Suricata 6.0+ (网络流量分析)
- **前端**：
  - Vue.js 3.x (仪表盘)
  - Element Plus (UI组件库)
  - Socket.IO 客户端 (实时通信)
- **数据分析**：
  - Pandas 1.3+
  - NumPy 1.21+
  - Scikit-learn 1.0+
- **网络分析**：
  - Pyshark 0.4
  - Scapy 2.4
- **数据库**：
  - Elasticsearch 7.x (日志存储)
  - SQLite (轻量级数据存储)
- **可视化**：
  - ECharts 5.x (数据可视化)
  - Chart.js 3.x (图表展示)
- **其他工具**：
  - Logstash (日志收集)
  - Kibana (日志可视化)
  - Docker (容器化部署)

## 特色功能

### 实时告警通知
系统通过WebSocket技术实现实时告警推送，当检测到网络威胁时，立即在用户界面显示告警信息，无需刷新页面。

### 协议分布可视化
提供直观的协议分布图表，帮助分析人员快速了解网络流量组成，识别异常流量模式。

### 降级机制
在系统负载过高或资源受限时，自动启用降级模式，确保核心安全监测功能不受影响。

### 容器化部署
支持通过Docker容器化部署，简化安装过程，提高系统可移植性。

## 预期成果

1. 一个完整的基于Suricata的威胁分析系统
2. 高效的数据包重组算法实现
3. 准确的流量模式识别与分类系统
4. 完善的网络异常监测与报警机制
5. 详细的系统文档和使用手册
6. 实时告警通知与可视化展示功能
