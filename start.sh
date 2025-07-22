#!/bin/bash
clear
# 设置Python解释器名称
PYTHON_CMD="python3"

# --- FFmpeg 检查与安装向导 ---
check_ffmpeg() {
    # 默认命令
    FFMPEG_CMD="ffmpeg"
    FFPROBE_CMD="ffprobe"
    # 尝试从 config.ini 读取自定义路径
    if [ -f "config.ini" ]; then
        # 使用 grep 和 sed 安全地提取路径，移除前后空格和引号
        CONFIG_PATH=$(grep -E "^\s*ffmpeg_path\s*=" config.ini | sed -e 's/^[^=]*=\s*//' -e 's/^["'\'']//' -e 's/["'\'']$//' | tr -d '[:space:]')
        if [ -n "$CONFIG_PATH" ] && [ "$CONFIG_PATH" != "ffmpeg" ]; then
            FFMPEG_CMD=$CONFIG_PATH
            echo "从 config.ini 中读取 FFmpeg 路径: $FFMPEG_CMD"
        fi
        
        # 同样检查ffprobe路径
        FFPROBE_PATH=$(grep -E "^\s*ffprobe_path\s*=" config.ini | sed -e 's/^[^=]*=\s*//' -e 's/^["'\'']//' -e 's/["'\'']$//' | tr -d '[:space:]')
        if [ -n "$FFPROBE_PATH" ] && [ "$FFPROBE_PATH" != "ffprobe" ]; then
            FFPROBE_CMD=$FFPROBE_PATH
            echo "从 config.ini 中读取 FFprobe 路径: $FFPROBE_CMD"
        fi
    fi

    # 检查ffmpeg和ffprobe是否存在
    MISSING_TOOLS=""
    if ! [ -x "$FFMPEG_CMD" ] && ! command -v "$FFMPEG_CMD" &> /dev/null; then
        MISSING_TOOLS="$FFMPEG_CMD"
    fi
    if ! [ -x "$FFPROBE_CMD" ] && ! command -v "$FFPROBE_CMD" &> /dev/null; then
        MISSING_TOOLS="$MISSING_TOOLS $FFPROBE_CMD"
    fi
    
    if [ -n "$MISSING_TOOLS" ]; then
        echo "----------------------------------------"
        echo "⚠️  错误：未找到以下工具：$MISSING_TOOLS"
        echo "此工具需要 FFmpeg 和 FFprobe 来分析视频文件。"
        echo "----------------------------------------"
        
        # 提供操作系统特定的安装指导
        OS_TYPE=$(uname -s)
        if [ "$OS_TYPE" == "Darwin" ]; then # macOS
            if command -v brew &> /dev/null; then
                read -p "您似乎在使用 macOS，是否尝试使用 Homebrew 自动安装 FFmpeg (brew install ffmpeg)？[Y/n] " choice
                case "$choice" in 
                  y|Y|"") 
                    echo "正在尝试使用 Homebrew 安装 FFmpeg..."
                    brew install ffmpeg
                    ;;
                  * ) 
                    echo "操作已取消。请手动安装 FFmpeg，或在 config.ini 中指定其完整路径。"
                    echo "您可以从官网下载：https://ffmpeg.org/download.html"
                    exit 1
                    ;;
                esac
            else
                echo "请先安装 Homebrew (https://brew.sh)，然后运行 'brew install ffmpeg'。"
                echo "或者，您可以从官网下载并安装：https://ffmpeg.org/download.html"
                exit 1
            fi
        elif [ "$OS_TYPE" == "Linux" ]; then
            if command -v apt-get &> /dev/null; then # Debian/Ubuntu
                 read -p "您似乎在使用 Debian/Ubuntu，是否尝试使用 apt-get 自动安装 FFmpeg (sudo apt-get install ffmpeg)？[Y/n] " choice
                case "$choice" in 
                  y|Y|"") 
                    echo "正在尝试使用 apt-get 安装 FFmpeg... 这可能需要您输入管理员密码。"
                    sudo apt-get update && sudo apt-get install -y ffmpeg
                    ;;
                  * ) 
                    echo "操作已取消。请手动安装 FFmpeg，或在 config.ini 中指定其完整路径。"
                    echo "您可以从官网下载：https://ffmpeg.org/download.html"
                    exit 1
                    ;;
                esac
            else
                 echo "请使用您发行版的包管理器安装 FFmpeg (例如 'sudo yum install ffmpeg' 或 'sudo pacman -S ffmpeg')。"
                 echo "或者，您可以从官网下载：https://ffmpeg.org/download.html"
                 exit 1
            fi
        else
            echo "无法检测到您的操作系统以提供自动安装命令。"
            echo "请从官网手动安装 FFmpeg：https://ffmpeg.org/download.html"
            echo "安装后，请确保它在您的系统 PATH 中，或在 config.ini 中指定其完整路径。"
            exit 1
        fi

        # 安装后再次检查
        if ! command -v "$FFMPEG_CMD" &> /dev/null; then
            echo "❌ FFmpeg 安装失败或仍未找到。请手动解决后重试。"
            exit 1
        fi
    fi
    echo "✅ FFmpeg 和 FFprobe 已找到。"
}


# --- 虚拟环境设置 ---
setup_venv() {
    if [ ! -d ".venv" ]; then
        echo "未找到 .venv 虚拟环境，正在创建..."
        $PYTHON_CMD -m venv .venv
        if [ $? -ne 0 ]; then
            echo "❌ 创建虚拟环境失败，请检查您的 Python 3 ($PYTHON_CMD) 安装。"
            exit 1
        fi
        
        echo "正在激活虚拟环境并安装依赖..."
        source .venv/bin/activate
        
        pip install --upgrade pip > /dev/null
        pip install -r requirements.txt
        if [ $? -ne 0 ]; then
            echo "❌ 安装依赖失败，请检查 requirements.txt 文件和您的网络连接。"
            deactivate
            exit 1
        fi
    else
        echo "发现 .venv 虚拟环境，正在激活..."
        source .venv/bin/activate
    fi
}

# --- 主逻辑 ---
check_ffmpeg
setup_venv

echo "----------------------------------------"
echo "🚀 环境准备就绪，正在启动主程序..."
echo "----------------------------------------"

# 运行主程序，传递所有命令行参数
$PYTHON_CMD ./main.py "$@"

echo "----------------------------------------"
echo "✅ 程序执行完毕。"
echo "----------------------------------------"

# 停用虚拟环境
deactivate