# SuriVisor 系统数据流向图

以下Mermaid图表展示了SuriVisor系统中数据的流向和处理过程。

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

## 数据流向说明

1. **数据采集阶段**:
   - 网络流量被Suricata引擎捕获和分析
   - Suricata生成告警日志、流量日志和统计日志

2. **数据处理阶段**:
   - SuricataProcessManager处理告警日志，生成告警事件
   - TrafficAnalyzer处理流量日志和统计日志，生成流量事件
   - EventDetector基于TrafficAnalyzer的分析结果检测异常，生成异常事件

3. **事件管理阶段**:
   - EventManager接收所有类型的事件
   - 根据事件类型将事件分发给相应的处理器

4. **事件处理阶段**:
   - 告警事件处理器处理告警事件
   - 异常事件处理器处理异常事件
   - 流量事件处理器处理流量事件

5. **报告生成阶段**:
   - ReportGenerator根据处理后的数据生成多种格式的报告
   - 支持JSON、HTML、PDF和CSV等格式

这种数据流向设计使得系统能够高效地处理和分析网络流量，及时发现并报告潜在的安全威胁。