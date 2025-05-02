# SuriVisor 系统类关系图

以下Mermaid图表展示了SuriVisor系统中各个类之间的关系。

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

## 类关系说明

1. **SuriVisor**: 系统的主类，负责初始化和协调各个组件。包含以下主要组件：
   - EventManager: 事件管理器
   - SuricataProcessManager: Suricata进程管理器
   - ReportGenerator: 报告生成器
   - TrafficAnalyzer: 流量分析器
   - EventDetector: 事件检测器
   - EventHandler: 事件处理器

2. **事件相关类**:
   - Event: 事件基类，定义了事件的基本属性和方法
   - EventManager: 管理事件的注册、分发和处理
   - EventHandler: 处理不同类型的事件
   - EventFilter: 事件过滤器，用于过滤特定条件的事件

3. **流量分析相关类**:
   - TrafficAnalyzer: 流量分析器，分析网络流量并生成流量统计信息

4. **事件检测相关类**:
   - EventDetector: 事件检测器，检测网络异常并生成异常事件

5. **Suricata进程管理相关类**:
   - SuricataProcessManager: 管理Suricata进程，监控其运行状态

6. **报告生成相关类**:
   - ReportGenerator: 报告生成器，生成多种格式的分析报告

这种类关系设计使得系统具有良好的模块化和可扩展性，各个组件之间通过明确的接口进行交互，降低了系统的耦合度。