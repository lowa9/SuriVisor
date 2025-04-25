#!/bin/bash
# 部署Logstash配置脚本

set -e

echo "开始部署Logstash配置..."

# 确保目录存在
mkdir -p /home/kai/SuriVisor/data/logs/suricata

# 检查是否有sudo权限
if [ "$(id -u)" -ne 0 ]; then
    echo "警告: 此脚本需要sudo权限来复制配置文件到/etc/logstash目录"
    echo "请使用sudo运行此脚本"
    exit 1
fi

# 复制配置文件
echo "复制Logstash配置文件..."
cp /home/kai/SuriVisor/config/logstash/suricata.conf /etc/logstash/conf.d/

# 设置正确的权限
chown logstash:logstash /etc/logstash/conf.d/suricata.conf
chmod 644 /etc/logstash/conf.d/suricata.conf

# 确保Logstash可以读取session_id文件
echo "设置日志目录权限..."
chmod -R 755 /home/kai/SuriVisor/data/logs
chown -R logstash:logstash /home/kai/SuriVisor/data/logs/suricata

# 重启Logstash服务
echo "重启Logstash服务..."
systemctl restart logstash

# 等待Logstash启动
echo "等待Logstash服务启动..."
sleep 5

# 检查Logstash状态
if systemctl is-active --quiet logstash; then
    echo "Logstash服务已成功重启"
else
    echo "警告: Logstash服务可能未正确启动，请检查日志"
    systemctl status logstash
fi

echo "配置部署完成！"
echo "现在您可以运行测试脚本: python3 /home/kai/SuriVisor/tools/test_session_id.py"