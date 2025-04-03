#!/bin/bash

echo "开始安装SuriVisor所需依赖..."

# 检查是否已安装Suricata
if command -v suricata &> /dev/null; then
    echo "Suricata已安装"
else
    echo "安装Suricata..."
    sudo apt-get update
    sudo apt-get install -y suricata
fi

# 安装Python依赖
echo "安装Python依赖..."
sudo apt-get install -y python3-pip python3-dev

# 创建虚拟环境
echo "创建Python虚拟环境..."
python3 -m pip install --user virtualenv
python3 -m virtualenv venv
source venv/bin/activate

# 安装项目依赖
echo "安装项目Python依赖..."
pip install numpy pandas scikit-learn pyshark scapy flask matplotlib seaborn

# 安装前端依赖
echo "安装前端依赖..."
sudo apt-get install -y nodejs npm
npm install -g @vue/cli

echo "依赖安装完成！"

# 初始化Suricata配置
echo "配置Suricata..."
if [ -f "/etc/suricata/suricata.yaml" ]; then
    cp /etc/suricata/suricata.yaml config/suricata.yaml
    echo "已复制Suricata配置文件到项目目录"
fi

# 创建基本系统配置
cat > config/system.conf << EOF
[General]
Debug = False
LogLevel = INFO
DataDir = data/

[Suricata]
BinaryPath = /usr/bin/suricata
ConfigPath = config/suricata.yaml
RulePath = /etc/suricata/rules

[Analysis]
PacketReassemblyEnabled = True
AnomalyDetectionEnabled = True
TrafficAnalysisEnabled = True

[UI]
WebServerPort = 8080
DashboardEnabled = True
ReportGenerationEnabled = True
EOF

echo "系统配置已创建"
echo "SuriVisor环境设置完成！"