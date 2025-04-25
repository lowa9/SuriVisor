# Logstash 配置说明

## 会话ID功能

本配置实现了在Suricata实时分析时创建全局会话ID，并将其包含在所有Elasticsearch索引数据中的功能。

### 工作原理

1. 当SuricataProcessManager启动Suricata进程时，会自动生成一个唯一的UUID作为会话ID
2. 该会话ID会被写入到`/home/kai/SuriVisor/data/logs/suricata/session_id.conf`文件中
3. Logstash配置通过Ruby过滤器读取此文件，并将会话ID添加到每个事件中
4. 所有发送到Elasticsearch的事件都会包含此会话ID字段

### 配置文件

- **SuricataProcessManager**: 已修改为支持会话ID生成和管理
- **suricata.conf**: Logstash配置文件，包含读取会话ID并添加到事件的逻辑

### 使用方法

1. 确保Logstash使用项目中的配置文件：
   ```bash
   sudo cp /home/kai/SuriVisor/config/logstash/suricata.conf /etc/logstash/conf.d/
   sudo systemctl restart logstash
   ```

2. 启动Suricata实时分析时，会话ID会自动生成并应用

3. 在Elasticsearch中查询时，可以使用`session_id`字段筛选特定分析会话的数据

### 注意事项

- 每次启动Suricata进程都会生成新的会话ID
- 停止Suricata进程时会自动清除会话ID文件
- 如果需要手动设置会话ID，可以调用`SuricataProcessManager.write_session_id_file()`方法