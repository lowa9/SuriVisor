# SuriVisor 系统架构图

以下Mermaid图表展示了SuriVisor系统中各模块的调用关系和数据流向。

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

## 组件说明

1. **SuriVisor 主类**: 系统的核心类，负责初始化和协调各个组件
2. **SuricataProcessManager**: 管理Suricata进程，监控其运行状态
3. **TrafficAnalyzer**: 分析网络流量，识别流量模式
4. **EventDetector**: 检测网络异常，生成异常事件
5. **EventManager**: 管理事件的注册、分发和处理
6. **EventHandler**: 处理不同类型的事件
7. **ReportGenerator**: 生成多种格式的分析报告

## 事件流向

系统中的事件主要有三种类型：
- **告警事件(alert)**: 由Suricata生成的告警
- **异常事件(anomaly)**: 由事件检测器检测到的网络异常
- **流量事件(flow)**: 由流量分析器生成的流量统计信息

所有事件都通过事件管理器进行分发，由相应的事件处理器进行处理，最终可以生成分析报告。