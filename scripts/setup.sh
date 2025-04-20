#!/bin/bash

echo "开始安装SuriVisor所需依赖..."

# 检查是否已安装Suricata
if command -v suricata &> /dev/null; then
    echo "Suricata已安装"
else
    echo "安装Suricata..."
    sudo apt-get update
    sudo apt-get install -y suricata suricata-update
fi

# 安装suricata-update工具（如果未随Suricata一起安装）
if ! command -v suricata-update &> /dev/null; then
    echo "安装suricata-update工具..."
    sudo apt-get install -y suricata-update
fi

# 检查Python依赖
echo "检查Python依赖..."
if ! command -v python3 &> /dev/null || ! command -v pip3 &> /dev/null; then
    echo "安装Python基础依赖..."
    sudo apt-get install -y python3-pip python3-dev python3-venv
else
    echo "Python基础依赖已安装"
fi

# 检查虚拟环境
echo "检查Python虚拟环境..."
if [ ! -d "venv" ]; then
    echo "创建Python虚拟环境..."
    python3 -m venv venv
else
    echo "虚拟环境已存在"
fi

# 激活虚拟环境
echo "激活Python虚拟环境..."
source venv/bin/activate

# 检查并安装项目依赖
echo "检查项目Python依赖..."
required_packages="elasticsearch numpy pandas scikit-learn pyshark scapy flask matplotlib seaborn weasyprint PyYAML"
for package in $required_packages; do
    if ! pip show $package &> /dev/null; then
        echo "安装 $package..."
        pip install $package
    else
        echo "$package 已安装"
    fi
done

# 检查Node.js
echo "检查 Node.js 版本..."
if ! command -v node &> /dev/null; then
    echo "安装 Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
    sudo apt-get install -y nodejs
elif [ $(node -v | cut -d. -f1 | tr -d 'v') -lt 14 ]; then
    echo "更新 Node.js 到新版本..."
    curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    echo "Node.js 版本符合要求"
fi

# 检查npm配置
echo "检查 npm 配置..."
current_registry=$(npm config get registry)
if [ "$current_registry" != "https://registry.npmmirror.com" ]; then
    echo "配置 npm 镜像..."
    npm config set registry https://registry.npmmirror.com
else
    echo "npm 镜像已配置"
fi

# 检查npm全局目录
if [ ! -d "~/.npm-global" ]; then
    echo "配置 npm 全局目录..."
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    if ! grep -q "export PATH=~/.npm-global/bin:\$PATH" ~/.profile; then
        echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.profile
    fi
    source ~/.profile
else
    echo "npm 全局目录已配置"
fi

# 检查Vue CLI
echo "检查 Vue CLI..."
if ! command -v vue &> /dev/null; then
    echo "安装 Vue CLI..."
    rm -rf ~/.npm-global/lib/node_modules/@vue/cli
    npm install -g @vue/cli
else
    echo "Vue CLI 已安装"
fi

echo "依赖安装完成！"

# 初始化Suricata配置
echo "配置Suricata..."
if [ -f "/etc/suricata/suricata.yaml" ]; then
    mkdir -p ~/SuriVisor/config
    cp /etc/suricata/suricata.yaml ~/SuriVisor/config/suricata.yaml
    echo "已复制Suricata配置文件到项目目录"
fi

# 下载ET OPEN规则集
echo "下载ET OPEN规则集..."
mkdir -p ~/SuriVisor/config/rules

# 配置suricata-update使用ET OPEN规则集
sudo suricata-update enable-source et/open

# 下载规则到项目目录
sudo suricata-update update-sources
sudo suricata-update --no-reload --output ~/SuriVisor/config/rules

echo "ET OPEN规则集已下载到config/rules目录"

# 创建基本系统配置
cat > config/system.conf << EOF
[General]
Debug = False
LogLevel = INFO
DataDir = data/

[Suricata]
BinaryPath = /usr/bin/suricata
ConfigPath = config/suricata.yaml
RulePath = config/rules

[Analysis]
PacketReassemblyEnabled = True
AnomalyDetectionEnabled = True
TrafficAnalysisEnabled = True

[Elasticsearch]
Scheme = http
Host = localhost
Port = 9200
Url = http://localhost:9200

[UI]
WebServerPort = 8080
DashboardEnabled = True
ReportGenerationEnabled = True
EOF

echo "系统配置已创建"

# 创建启动脚本
cat > scripts/start.sh << EOF
#!/bin/bash

# 激活虚拟环境
source "$PWD/venv/bin/activate"

# 使用sudo -E保持环境变量并以root权限运行应用
sudo -E python3 src/main.py
EOF

# 设置启动脚本权限
chmod +x scripts/start.sh

echo "SuriVisor环境设置完成！"
echo "请使用 './scripts/start.sh' 启动系统"