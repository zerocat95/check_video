# 视频查重分析工具

一个功能强大的视频库健康检查和重复文件分析工具，支持本地、FTP和SMB协议的远程存储。

## 🌟 功能特性

- **多协议支持**：支持本地路径、FTP、SMB连接
- **健康检查**：使用FFmpeg检测视频文件完整性
- **重复检测**：基于感知哈希算法识别重复内容
- **智能报告**：生成Excel格式的详细分析报告
- **交互操作**：支持交互式删除重复文件
- **并发处理**：多线程并发分析，提升效率
- **断点续传**：数据库管理，支持中断恢复

## 🚀 快速开始

### 1. 安装依赖

```bash
# 一键安装
./setup.sh

# 或手动安装
pip install -r requirements.txt
```

### 2. 配置连接

编辑 `config.ini` 文件：

```ini
[NAS]
protocol = ftp
host = 192.168.1.100
port = 21
username = your_username
password = your_password
remote_dir = /videos
download_dir = ./temp_videos

[SETTINGS]
max_workers = 4
similarity_threshold = 5
video_extensions = .mp4,.mkv,.avi,.mov,.wmv,.flv,.mpg,.mpeg
```

### 3. 运行程序

```bash
# 启动程序
./start.sh

# 或直接运行
python3 main.py
```

## 📊 使用说明

### 主菜单选项

1. **管理扫描任务** - 批量管理多个扫描路径
2. **快速扫描** - 单一路径快速扫描
3. **查看已保存的连接** - 管理历史连接记录

### 扫描过程

1. 选择连接协议（local/ftp/smb）
2. 输入连接信息或选择已保存连接
3. 选择要扫描的目录
4. 程序自动分析视频文件
5. 生成Excel分析报告

### 报告内容

- **总览**：所有视频文件的健康状态
- **损坏文件**：标记为损坏或无法处理的文件
- **重复文件**：内容重复的文件组及删除建议

## 🔧 配置选项

### 视频格式支持
默认支持：.mp4, .mkv, .avi, .mov, .wmv, .flv, .mpg, .mpeg

### 并发设置
- `max_workers`：并发线程数（默认4）
- `similarity_threshold`：重复检测阈值（默认5）

### FFmpeg配置
确保系统已安装FFmpeg：
```bash
# macOS
brew install ffmpeg

# Ubuntu/Debian
sudo apt-get install ffmpeg

# Windows
# 下载：https://ffmpeg.org/download.html
```

## 📈 输出示例

生成的Excel报告包含：
- 文件完整路径
- 健康状态（Healthy/Warning/Corrupted）
- 健康值（0-100）
- 分辨率
- 比特率（kbps）
- 文件大小（MB）
- 时长（秒）

## 🛠️ 技术栈

- **Python 3.8+**
- **pandas** - 数据处理和Excel生成
- **sqlite3** - 本地数据库存储
- **concurrent.futures** - 多线程处理
- **xlsxwriter** - Excel文件生成
- **pysmb/smbprotocol** - SMB协议支持
- **cryptography** - 密码加密存储

## 🚨 注意事项

1. **首次运行**会自动创建数据库和配置文件
2. **大文件处理**时会临时下载到本地缓存目录
3. **网络连接**请确保目标存储可正常访问
4. **空间要求**需要足够的本地空间作为缓存

## 📞 问题排查

### 常见问题

**Q: 程序无法找到FFmpeg**
A: 确保FFmpeg已安装并添加到系统PATH

**Q: 连接失败**
A: 检查网络连接、用户名密码、端口号是否正确

**Q: 报告为空**
A: 确认扫描目录中确实包含视频文件

## 📄 许可证

MIT License - 详见LICENSE文件