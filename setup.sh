#!/bin/bash

# 设置颜色代码
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查虚拟环境目录是否存在
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}错误: 虚拟环境 '.venv' 不存在。${NC}"
    echo "请先运行 'python3 -m venv .venv' 来创建虚拟环境。"
    exit 1
fi

# 激活虚拟环境
echo "正在激活虚拟环境..."
source .venv/bin/activate

# 检查 requirements.txt 文件是否存在
if [ ! -f "requirements.txt" ]; then
    echo -e "${YELLOW}警告: 'requirements.txt' 文件未找到。${NC}"
    echo "将跳过依赖安装步骤。"
else
    # 使用中国区镜像源安装依赖
    echo "正在使用清华大学镜像源安装依赖..."
    pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}依赖安装成功！${NC}"
    else
        echo -e "${YELLOW}依赖安装过程中出现错误。${NC}"
    fi
fi

echo -e "\n设置完成。现在您可以在激活的虚拟环境中运行脚本，例如: ${GREEN}python main.py${NC}"
