# Suricata 规则配置说明

## 规则文件说明

本目录包含以下规则文件：

1. **suricata.yaml** - Suricata主配置文件，包含了Suricata的全局配置和规则文件路径

2. **brute_force.rules** - 应用层暴力破解检测规则，用于检测以下服务的暴力破解攻击：
   - FTP服务暴力破解检测（端口21）
   - TELNET服务暴力破解检测（端口23）
   - HTTP服务暴力破解检测（Web登录页面）

## 离线分析PCAP文件

要使用Suricata对PCAP文件进行离线分析，请使用以下命令：

```bash
suricata -c /home/kai/SuriVisor/config/suricata.yaml -r /path/to/pcap/file.pcap
```

例如，分析FTP暴力破解PCAP文件：

```bash
suricata -c /home/kai/SuriVisor/config/suricata.yaml -r /home/kai/SuriVisor/data/pcap/FTP服务暴力猜测用户口令.pcap
```

## 规则配置注意事项

1. 确保在`suricata.yaml`文件中正确加载了所有规则文件
2. 应用层检测需要启用相应的应用层解析器（如HTTP、FTP、TELNET等）
3. 检查日志输出目录是否有写入权限

## 日志查看

分析完成后，可以在以下位置查看检测结果：

- 告警日志：`/var/log/suricata/fast.log`
- 详细事件日志：`/var/log/suricata/eve.json`

可以使用以下命令查看告警：

```bash
cat /var/log/suricata/fast.log
```

或者使用jq工具查看JSON格式的事件日志：

```bash
cat /var/log/suricata/eve.json | jq '.alert'
```