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

## 系统架构

系统采用模块化设计，主要包含以下核心组件：

1. **Suricata核心引擎**：负责网络流量捕获和初步分析
2. **数据包重组模块**：实现高效的数据包重组算法
3. **流量分析模块**：处理捕获的流量数据，识别潜在威胁
4. **异常检测模块**：监测网络异常指标，生成告警
5. **用户界面**：提供友好的操作界面和可视化展示
6. **报告系统**：生成详细的分析报告和安全建议

## 项目结构

```
SuriVisor/
├── config/                 # 配置文件
│   ├── suricata.yaml       # Suricata配置文件
│   └── system.conf         # 系统配置文件
├── data/                   # 数据目录
│   ├── alerts/             # Suricata告警日志
│   ├── logs/               # 系统日志
│   │   └── suricata/       # Suricata运行日志
│   ├── pcap/               # 网络流量捕获文件
│   ├── reports/            # 生成的报告
│   └── scenarios/          # 攻击场景配置
├── scripts/                # 脚本工具
│   ├── setup.sh            # 系统安装脚本
│   └── start.sh            # 启动脚本
├── src/                    # 源代码目录
│   ├── api/                # API接口
│   │   └── server.py       # REST API服务
│   ├── core/               # 核心功能模块
│   │   ├── anomaly_detection/  # 异常检测模块
│   │   ├── event_manager/      # 事件管理模块
│   │   ├── packet_reassembly/  # 数据包重组算法
│   │   ├── report_generator/   # 报告生成模块
│   │   ├── suricata_monitor/   # Suricata监控模块
│   │   └── traffic_analysis/   # 流量分析模块
│   ├── main.py             # 主程序入口
│   ├── ui/                 # 用户界面
│   │   └── dashboard/      # 数据可视化仪表盘
│   └── utils/              # 工具函数
│       ├── __init__.py
│       ├── packet_utils.py # 数据包处理工具
│       ├── report_utils.py # 报告生成工具
│       └── system_utils.py # 系统工具
├── templates/              # 模板文件
│   └── report.html         # 报告模板
└── tests/                  # 测试目录
    ├── integration/        # 集成测试
    └── unit/              # 单元测试
        ├── test_anomaly_detector.py
        ├── test_event_manager.py
        ├── test_packet_reassembler.py
        ├── test_report_generator.py
        └── test_traffic_analyzer.py
```

## 实现计划

### 阶段一：基础架构搭建
- 搭建Suricata运行环境
- 设计并实现系统核心架构
- 开发基础数据处理模块

### 阶段二：核心功能实现
- 实现数据包重组算法
- 开发流量分析模块
- 构建异常检测机制

### 阶段三：用户界面与集成
- 开发Web界面和仪表盘
- 集成各功能模块
- 实现报告生成系统

### 阶段四：测试与优化
- 构建测试场景
- 进行性能测试和优化
- 系统集成测试

## 技术栈

- **后端**：
  - Python 3.8+
  - FastAPI (API服务)
  - Suricata 6.0+ (网络流量分析)
- **前端**：
  - Vue.js 3.x (仪表盘)
  - Element Plus (UI组件库)
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

## 预期成果

1. 一个完整的基于Suricata的威胁分析系统
2. 高效的数据包重组算法实现
3. 准确的流量模式识别与分类系统
4. 完善的网络异常监测与报警机制
5. 详细的系统文档和使用手册
