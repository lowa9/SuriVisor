# SuriVisor 系统架构概览

本文档提供了SuriVisor系统的架构概览，包括系统组件、调用关系、数据流向和类关系。

## 目录

- [系统组件](#系统组件)
- [系统架构图](#系统架构图)
- [数据流向图](#数据流向图)
- [类关系图](#类关系图)
- [系统工作流程](#系统工作流程)

## 系统组件

SuriVisor系统由以下主要组件构成：

1. **SuriVisor主类**：系统的核心类，负责初始化和协调各个组件
2. **SuricataProcessManager**：管理Suricata进程，监控其运行状态
3. **TrafficAnalyzer**：分析网络流量，识别流量模式
4. **EventDetector**：检测网络异常，生成异常事件
5. **EventManager**：管理事件的注册、分发和处理
6. **EventHandler**：处理不同类型的事件
7. **ReportGenerator**：生成多种格式的分析报告

## 系统架构图

以下Mermaid图表展示了SuriVisor系统中各模块的调用关系：

```mermaid
graph TD
    %% 主要组件定义
    SuriVisor["SuriVisor 主类"] --> |初始化| SPM["SuricataProcessManager\n(Suricata进程管理器)"] 
    SuriVisor --> |初始化| TA["TrafficAnalyzer\n(流量分析器)"]
    SuriVisor --> |初始化| EM["EventManager\n(事件管理器)"]
    SuriVisor --> |初始化| ED["EventDetector\n(事件检测器)"]
    SuriVisor --> |初始化| EH["EventHandler\n(事件处理器)"]
    SuriVisor --> |初始化| RG["ReportGenerator\n(报告生成器)"]
    
    %% 组件间的关系
    SPM --> |产生告警| EM
    TA --> |分析流量| EM
    ED --> |检测异常| EM
    EM --> |分发事件| EH
    
    %% 事件处理器处理不同类型的事件
    EH --> |处理告警事件| AlertHandler["告警事件处理"]
    EH --> |处理异常事件| AnomalyHandler["异常事件处理"]
    EH --> |处理流量事件| FlowHandler["流量事件处理"]
    
    %% 报告生成
    AlertHandler --> |生成报告| RG
    AnomalyHandler --> |生成报告| RG
    FlowHandler --> |生成报告| RG
    
    %% 事件流向
    subgraph 事件流
        Event1["告警事件(alert)"] --> EM
        Event2["异常事件(anomaly)"] --> EM
        Event3["流量事件(flow)"] --> EM
    end
    
    %% 数据存储和输出
    RG --> |生成| Reports["多种格式报告\n(JSON/HTML/PDF/CSV)"]
    
    %% 样式设置
    classDef main fill:#f9f,stroke:#333,stroke-width:2px;
    classDef component fill:#bbf,stroke:#33f,stroke-width:1px;
    classDef event fill:#bfb,stroke:#3f3,stroke-width:1px;
    classDef handler fill:#fbb,stroke:#f33,stroke-width:1px;
    classDef output fill:#ffb,stroke:#ff3,stroke-width:1px;
    
    class SuriVisor main;
    class SPM,TA,EM,ED,EH,RG component;
    class Event1,Event2,Event3 event;
    class AlertHandler,AnomalyHandler,FlowHandler handler;
    class Reports output;
```

## 数据流向图

以下Mermaid图表展示了SuriVisor系统中数据的流向和处理过程：

```mermaid
flowchart TD
    %% 数据源
    NetworkTraffic["网络流量"] --> Suricata["Suricata引擎"]
    
    %% Suricata输出
    Suricata --> |生成告警| AlertLog["告警日志"]
    Suricata --> |记录流量| FlowLog["流量日志"]
    Suricata --> |统计信息| StatsLog["统计日志"]
    
    %% SuriVisor组件处理
    AlertLog --> SPM["SuricataProcessManager"]
    FlowLog --> TA["TrafficAnalyzer"]
    StatsLog --> TA
    
    %% 事件生成
    SPM --> |生成告警事件| AlertEvent["告警事件"]
    TA --> |生成流量事件| FlowEvent["流量事件"]
    TA --> |检测异常| ED["EventDetector"]
    ED --> |生成异常事件| AnomalyEvent["异常事件"]
    
    %% 事件管理
    AlertEvent --> EM["EventManager"]
    FlowEvent --> EM
    AnomalyEvent --> EM
    
    %% 事件处理
    EM --> |分发告警事件| AlertHandler["告警事件处理"]
    EM --> |分发异常事件| AnomalyHandler["异常事件处理"]
    EM --> |分发流量事件| FlowHandler["流量事件处理"]
    
    %% 处理结果
    AlertHandler --> |处理结果| ProcessedData["处理后的数据"]
    AnomalyHandler --> |处理结果| ProcessedData
    FlowHandler --> |处理结果| ProcessedData
    
    %% 报告生成
    ProcessedData --> RG["ReportGenerator"]
    RG --> |JSON格式| JSONReport["JSON报告"]
    RG --> |HTML格式| HTMLReport["HTML报告"]
    RG --> |PDF格式| PDFReport["PDF报告"]
    RG --> |CSV格式| CSVReport["CSV报告"]
    
    %% 样式设置
    classDef dataSource fill:#f9f9f9,stroke:#333,stroke-width:1px;
    classDef logFile fill:#e6f7ff,stroke:#1890ff,stroke-width:1px;
    classDef component fill:#f0f5ff,stroke:#597ef7,stroke-width:1px;
    classDef event fill:#f6ffed,stroke:#52c41a,stroke-width:1px;
    classDef handler fill:#fff7e6,stroke:#fa8c16,stroke-width:1px;
    classDef report fill:#fff2e8,stroke:#fa541c,stroke-width:1px;
    
    class NetworkTraffic,Suricata dataSource;
    class AlertLog,FlowLog,StatsLog logFile;
    class SPM,TA,ED,EM,RG component;
    class AlertEvent,FlowEvent,AnomalyEvent event;
    class AlertHandler,AnomalyHandler,FlowHandler handler;
    class JSONReport,HTMLReport,PDFReport,CSVReport report;
```

## 类关系图

以下Mermaid图表展示了SuriVisor系统中各个类之间的关系：

```mermaid
classDiagram
    %% 主类
    class SuriVisor {
        +version: str
        +config: Dict
        +running: bool
        +event_manager: EventManager
        +suricata_manager: SuricataProcessManager
        +report_generator: ReportGenerator
        +traffic_analyzer: TrafficAnalyzer
        +event_detector: EventDetector
        +event_handler: EventHandler
        +__init__(config_file)
        +load_config(config_file)
        +validate_suricata_config()
        +start()
        +stop()
        +get_status()
    }
    
    %% 事件相关类
    class Event {
        +id: str
        +event_type: str
        +source: str
        +severity: int
        +timestamp: float
        +data: Dict
        +__init__(event_type, source, severity, data)
        +to_dict()
    }
    
    class EventManager {
        +max_queue_size: int
        +worker_threads: int
        +event_queue: PriorityQueue
        +handlers: Dict
        +global_handlers: List
        +stats: Dict
        +running: bool
        +__init__(max_queue_size, worker_threads)
        +register_handler(handler, event_types, event_filter)
        +unregister_handler(handler, event_types)
        +emit_event(event)
        +create_and_emit_event(event_type, source, severity, data)
        +start()
        +stop()
        +get_statistics()
    }
    
    class EventHandler {
        +event_manager: EventManager
        +__init__(event_manager)
        +handle_alert_event(event)
        +handle_anomaly_event(event)
        +handle_flow_event(event)
    }
    
    class EventFilter {
        +filter_criteria: Dict
        +__init__(filter_criteria)
        +match(event)
    }
    
    %% 流量分析相关类
    class TrafficAnalyzer {
        +running: bool
        +eve_json_path: str
        +traffic_stats: Dict
        +network_metrics: Dict
        +tcp_health: Dict
        +__init__()
        +reset()
        +start(output_log_dir)
        +stop()
        +analyze_traffic()
        +get_statistics()
    }
    
    %% 事件检测相关类
    class EventDetector {
        +alert_history: List
        +event_manager: EventManager
        +monitoring_thread: Thread
        +running: bool
        +es_client: ESClient
        +__init__(event_manager)
        +start_monitoring()
        +stop_monitoring()
    }
    
    %% Suricata进程管理相关类
    class SuricataProcessManager {
        +binary_path: str
        +config_path: str
        +rule_dir: str
        +log_dir: str
        +process: Process
        +running: bool
        +__init__(binary_path, config_path, rule_dir, log_dir)
        +start(interface)
        +stop()
        +restart()
        +is_running()
        +get_status()
    }
    
    %% 报告生成相关类
    class ReportGenerator {
        +output_dir: str
        +template_dir: str
        +jinja_env: Environment
        +stats: Dict
        +__init__(output_dir, template_dir)
        +generate_report(data, report_type, output_file, options)
    }
    
    %% 类之间的关系
    SuriVisor "1" --> "1" EventManager: 包含
    SuriVisor "1" --> "1" SuricataProcessManager: 包含
    SuriVisor "1" --> "1" ReportGenerator: 包含
    SuriVisor "1" --> "1" TrafficAnalyzer: 包含
    SuriVisor "1" --> "1" EventDetector: 包含
    SuriVisor "1" --> "1" EventHandler: 包含
    
    EventManager "1" --> "*" Event: 管理
    EventManager "1" --> "*" EventFilter: 使用
    
    EventHandler "1" --> "1" EventManager: 使用
    
    EventDetector "1" --> "1" EventManager: 使用
    
    Event <|-- AlertEvent: 继承
    Event <|-- AnomalyEvent: 继承
    Event <|-- FlowEvent: 继承
```

## 系统工作流程

1. **初始化阶段**：
   - SuriVisor主类加载配置文件
   - 初始化各个组件（SuricataProcessManager、TrafficAnalyzer、EventManager、EventDetector、EventHandler、ReportGenerator）
   - 注册各类事件处理器

2. **数据采集阶段**：
   - SuricataProcessManager启动Suricata进程
   - Suricata引擎捕获网络流量并进行分析
   - 生成告警日志、流量日志和统计日志

3. **数据处理阶段**：
   - SuricataProcessManager处理告警日志，生成告警事件
   - TrafficAnalyzer处理流量日志和统计日志，生成流量事件
   - EventDetector基于TrafficAnalyzer的分析结果检测异常，生成异常事件

4. **事件管理阶段**：
   - EventManager接收所有类型的事件
   - 根据事件类型将事件分发给相应的处理器

5. **事件处理阶段**：
   - EventHandler处理不同类型的事件
   - 告警事件处理器处理告警事件
   - 异常事件处理器处理异常事件
   - 流量事件处理器处理流量事件

6. **报告生成阶段**：
   - ReportGenerator根据处理后的数据生成多种格式的报告
   - 支持JSON、HTML、PDF和CSV等格式

这种模块化的设计使得系统具有良好的可扩展性和可维护性，各个组件之间通过明确的接口进行交互，降低了系统的耦合度。