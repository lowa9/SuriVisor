# Elasticsearch 连接问题排查指南

## 问题描述

在SuriVisor系统启动过程中，出现了Elasticsearch连接失败的问题，日志中显示：

```
src.core.ElasticSearch.es_client - ERROR - 连接异常详情: <class 'ConnectionError'>|Ping 测试失败
```

## 解决方案

我们对系统进行了以下改进，使其在Elasticsearch不可用时仍能正常运行：

1. **添加降级模式**：修改了`ESClient`类，添加了`fallback_mode`参数，在降级模式下即使ES连接失败，系统也能继续运行
2. **改进错误处理**：增强了错误处理机制，提供更详细的错误信息和重试逻辑
3. **添加诊断工具**：创建了诊断脚本，帮助排查和解决ES连接问题

## 使用方法

### 启用降级模式

在初始化`ESClient`时，可以设置`fallback_mode=True`参数：

```python
from src.core.ElasticSearch.es_client import ESClient

# 启用降级模式
client = ESClient(fallback_mode=True)
```

在降级模式下，即使ES连接失败，系统也会继续运行，但相关功能可能受限。

### 使用诊断工具

我们提供了一个诊断工具，可以帮助排查ES连接问题：

```bash
# 基本用法
python scripts/diagnose_es.py

# 指定ES主机地址
python scripts/diagnose_es.py --hosts http://localhost:9200

# 保存诊断结果到文件
python scripts/diagnose_es.py --output diagnosis_result.json
```

### 手动重连

如果需要手动重新连接ES，可以使用`reconnect()`方法：

```python
from src.core.ElasticSearch.es_client import ESClient

client = ESClient(fallback_mode=True)
# 尝试重新连接
success = client.reconnect()
```

### 获取连接状态和诊断信息

```python
from src.core.ElasticSearch.es_client import ESClient

client = ESClient(fallback_mode=True)

# 获取连接状态
status = client.get_connection_status()
print(f"连接状态: {status['connected']}")

# 获取诊断信息和建议
diagnosis = client.diagnose_connection()
print("诊断结果:")
for suggestion in diagnosis['suggestions']:
    print(f"- {suggestion}")
```

## 常见问题

1. **ES服务未启动**：确保Elasticsearch服务已启动并正常运行
   ```bash
   # 检查ES服务状态
   systemctl status elasticsearch
   # 或
   service elasticsearch status
   ```

2. **网络连接问题**：检查网络连接和防火墙设置
   ```bash
   # 测试ES连接
   curl -X GET http://localhost:9200
   ```

3. **配置错误**：检查ES配置文件中的监听地址和端口

4. **认证问题**：如果启用了认证，确保提供了正确的用户名和密码

## 进一步改进

未来可以考虑以下改进：

1. 添加本地缓存机制，在ES不可用时使用本地存储
2. 实现自动重连和健康检查机制
3. 提供更详细的监控和告警功能