import readline
import argparse
import configparser
import logging
from pathlib import Path
import os
import subprocess
from ftplib import FTP
import pandas as pd
from tqdm import tqdm
import imagehash
from PIL import Image
from contextlib import contextmanager
import cv2
import json
import getpass
import concurrent.futures
import threading
import queue
import shutil
import sqlite3
import hashlib
from smb.SMBConnection import SMBConnection
from io import BytesIO
import datetime
import urllib.parse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# --- 加密配置 ---
# 注意：这是一个简化的密钥管理。在生产环境中，应使用更安全的方式来存储和管理主密钥。
SECRET_KEY_FILE = ".encryption_key"

def generate_or_load_key():
    """生成或加载用于加密的密钥。"""
    if Path(SECRET_KEY_FILE).exists():
        with open(SECRET_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

ENCRYPTION_KEY = generate_or_load_key()
FERNET = Fernet(ENCRYPTION_KEY)

def encrypt_password(password):
    """加密密码。"""
    if not password:
        return None
    return FERNET.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    """解密密码。"""
    if not encrypted_password:
        return None
    return FERNET.decrypt(encrypted_password.encode()).decode()

# --- 数据库配置 ---
DB_FILE = "video_library.db"

def init_database():
    """初始化数据库，创建必要的表。"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL UNIQUE,
        scan_target TEXT NOT NULL,
        file_size INTEGER,
        duration REAL,
        resolution TEXT,
        bitrate INTEGER,
        health_status TEXT,
        health_score INTEGER,
        perceptual_hashes TEXT,
        md5 TEXT,
        keyframe_info TEXT,
        last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_exists BOOLEAN DEFAULT 1
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        protocol TEXT,
        host TEXT,
        port INTEGER,
        username TEXT,
        password TEXT, -- 加密后的密码
        remote_dir TEXT,
        last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # 检查并添加缺失的password列
    try:
        cursor.execute("SELECT password FROM connections LIMIT 1")
    except sqlite3.OperationalError:
        # password列不存在，添加它
        cursor.execute("ALTER TABLE connections ADD COLUMN password TEXT")
        logging.info("已添加缺失的password列到connections表")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS duplicate_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        resolution TEXT,
        bitrate INTEGER,
        file_size INTEGER,
        health_score INTEGER,
        keep_recommended BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()
    logging.info(f"数据库 '{DB_FILE}' 初始化完成。")


# --- 统一连接池 ---
class ConnectionPool:
    """管理网络连接（FTP或SMB）的基类。"""
    def __init__(self, max_connections, creds):
        if max_connections <= 0:
            raise ValueError("max_connections 必须大于 0")
        self.max_connections = max_connections
        self.creds = creds
        self.protocol = creds.get('protocol', 'ftp')
        self._pool = queue.Queue(maxsize=max_connections)
        self._lock = threading.Lock()
        self._total_connections_created = 0

    def _create_connection(self):
        raise NotImplementedError

    def get_connection(self):
        try:
            return self._pool.get_nowait()
        except queue.Empty:
            with self._lock:
                if self._total_connections_created < self.max_connections:
                    self._total_connections_created += 1
                    conn = self._create_connection()
                    if conn:
                        return conn
                    else:
                        self._total_connections_created -= 1
                        raise ConnectionError(f"创建新的 {self.protocol.upper()} 连接失败。")
            try:
                return self._pool.get(timeout=30)
            except queue.Empty:
                raise ConnectionError(f"无法从连接池获取 {self.protocol.upper()} 连接，等待超时。")

    def return_connection(self, conn):
        if conn:
            try:
                self._check_connection_health(conn)
                self._pool.put(conn)
            except Exception:
                logging.warning(f"返回到池中的 {self.protocol.upper()} 连接已失效，将关闭它。")
                self._close_and_decrement(conn)

    def _check_connection_health(self, conn):
        raise NotImplementedError

    def _close_and_decrement(self, conn):
        if conn:
            try:
                self._close_connection(conn)
            except Exception:
                pass
            with self._lock:
                if self._total_connections_created > 0:
                    self._total_connections_created -= 1
    
    def _close_connection(self, conn):
        raise NotImplementedError

    def close_all_connections(self):
        logging.info(f"正在关闭所有 {self.protocol.upper()} 连接...")
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                self._close_and_decrement(conn)
            except queue.Empty:
                break
        logging.info(f"所有 {self.protocol.upper()} 连接已关闭。")

class FTPConnectionPool(ConnectionPool):
    """FTP连接池。"""
    def _create_connection(self):
        host, port, user, pwd = self.creds['host'], int(self.creds['port']), self.creds['username'], self.creds['password']
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=20)
            ftp.login(user, pwd)
            ftp.encoding = 'utf-8'
            return ftp
        except Exception as e:
            logging.error(f"创建FTP连接失败: {e}", exc_info=True)
            return None
    
    def _check_connection_health(self, conn):
        conn.voidcmd("NOOP")

    def _close_connection(self, conn):
        conn.quit()

class SMBConnectionPool(ConnectionPool):
    """SMB连接池。"""
    def _create_connection(self):
        host, port, user, pwd = self.creds['host'], int(self.creds['port']), self.creds['username'], self.creds['password']
        try:
            conn = SMBConnection(user, pwd, "py-smb-client", "server-name", use_ntlm_v2=True)
            conn.connect(host, port)
            return conn
        except Exception as e:
            logging.error(f"创建SMB连接失败: {e}", exc_info=True)
            return None

    def _check_connection_health(self, conn):
        conn.echo("health_check")

    def _close_connection(self, conn):
        conn.close()

@contextmanager
def connection_pool_manager(pool):
    """通用连接池的上下文管理器。"""
    conn = None
    try:
        conn = pool.get_connection()
        yield conn
    finally:
        if conn:
            pool.return_connection(conn)


# --- 配置日志记录 ---
def setup_logging():
    """配置日志记录器，将日志输出到文件和控制台。"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("video_check.log", mode='w'),
            logging.StreamHandler()
        ]
    )

# --- 加载配置 ---
def load_config(config_file='config.ini'):
    """从 .ini 文件加载配置，如果文件不存在则返回一个空的配置对象。"""
    config = configparser.ConfigParser()
    config_path = Path(config_file)
    if config_path.exists():
        config.read(config_path)
    else:
        logging.warning(f"配置文件 {config_path} 不存在，将使用默认设置。")
    return config

def get_user_credentials(args, config):
    """
    获取用户连接凭证。
    优先级顺序: 命令行参数 > config.ini 文件 > 交互式输入/数据库。
    """
    creds = {}

    # 1. 优先使用命令行参数
    if args.host and args.username or (args.protocol == 'local' and args.dir):
        logging.info("使用命令行参数提供的凭证。")
        creds['protocol'] = args.protocol
        creds['remote_dir'] = args.dir
        if args.protocol != 'local':
            creds['host'] = args.host
            creds['port'] = args.port or ('21' if args.protocol == 'ftp' else '445')
            creds['username'] = args.username
            creds['password'] = args.password or getpass.getpass(f"请输入用户 '{args.username}' 的密码: ")
        creds['download_dir'] = './temp_videos'
        return creds

    # 2. 其次，尝试从 config.ini 的 [NAS] 部分加载
    if config and 'NAS' in config and config['NAS'].get('remote_dir'):
        logging.info("从 config.ini 文件加载凭证。")
        nas_config = config['NAS']
        creds['protocol'] = nas_config.get('protocol', 'local')
        creds['remote_dir'] = nas_config.get('remote_dir')
        if creds['protocol'] != 'local':
            creds['host'] = nas_config.get('host')
            creds['port'] = nas_config.get('port')
            creds['username'] = nas_config.get('username')
            creds['password'] = nas_config.get('password')
            if not creds['password']:
                 creds['password'] = getpass.getpass(f"请输入用户 '{creds['username']}' 的密码: ")
        creds['download_dir'] = nas_config.get('download_dir', './temp_videos')
        return creds

    # 3. 最后，回退到交互式输入
    logging.info("未在命令行或配置文件中找到凭证，进入交互模式。")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # 从数据库获取所有连接信息，包括加密的密码
    cursor.execute("SELECT id, name, protocol, host, port, username, remote_dir, password FROM connections ORDER BY last_used DESC")
    saved_conns = cursor.fetchall()
    conn.close()

    if saved_conns:
        print("\n--- 请选择一个已保存的连接 ---")
        for i, conn_data in enumerate(saved_conns):
            # conn_data: (id, name, protocol, host, port, username, remote_dir, password)
            if conn_data[2] == 'local':
                print(f"  [{i+1}] {conn_data[1]} (local: {conn_data[6]})")
            else:
                print(f"  [{i+1}] {conn_data[1]} ({conn_data[2]}://{conn_data[5]}@{conn_data[3]})")
        print("  [d] 删除一个已保存的连接")
        print("  [n] 输入新的连接信息")
        print("  [q] 退出程序")
        print("--------------------------")
        choice = input("请选择: ").lower().strip()

        if choice.isdigit() and 1 <= int(choice) <= len(saved_conns):
            selected = saved_conns[int(choice) - 1]
            creds = {
                'id': selected[0],
                'name': selected[1],
                'protocol': selected[2],
                'host': selected[3],
                'port': selected[4],
                'username': selected[5],
                'remote_dir': selected[6],
                'password': decrypt_password(selected[7]) if selected[7] else None
            }
            # 如果解密后的密码是 None (对于非local连接)，则提示输入
            if creds['protocol'] != 'local' and not creds['password']:
                 creds['password'] = getpass.getpass(f"请输入用户 '{creds['username']}' 的密码: ")
            creds['download_dir'] = './temp_videos'
            print("---------------------------\n")
            return creds
        elif choice == 'd':
            del_choice_str = input("请输入要删除的连接编号: ").strip()
            if del_choice_str.isdigit() and 1 <= int(del_choice_str) <= len(saved_conns):
                conn_to_delete = saved_conns[int(del_choice_str) - 1]
                conn_name_to_delete = conn_to_delete[1]
                
                confirm = input(f"确定要删除连接 '{conn_name_to_delete}'吗? [y/N] ").lower().strip()
                if confirm == 'y':
                    conn = sqlite3.connect(DB_FILE)
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM connections WHERE name = ?", (conn_name_to_delete,))
                    conn.commit()
                    conn.close()
                    logging.info(f"连接 '{conn_name_to_delete}' 已被删除。")
                    return get_user_credentials(args, config)
                else:
                    print("删除操作已取消。")
                    return get_user_credentials(args, config)
            else:
                print("无效的编号。")
                return get_user_credentials(args, config)
        elif choice == 'q':
            return None # 返回 None 表示用户选择退出

    # ... (输入新连接信息的逻辑)
    print("\n--- 请输入新的连接信息 ---")
    creds['protocol'] = input("连接协议 (local/ftp/smb) [local]: ").lower().strip() or 'local'
    
    if creds['protocol'] == 'local':
        raw_path = input("要扫描的本地路径 (可将文件夹拖拽至此): ").strip()
        # 清理用户拖拽路径时可能产生的引号
        creds['remote_dir'] = raw_path.strip('\'"')
    else:
        creds['host'] = input("主机 IP 地址: ").strip()
        default_port = '21' if creds['protocol'] == 'ftp' else '445'
        creds['port'] = input(f"端口号 [{default_port}]: ").strip() or default_port
        creds['username'] = input("用户名: ").strip()
        creds['password'] = getpass.getpass("密码: ")
        creds['remote_dir'] = input("要扫描的远程目录 (例如 NAS_syn/videos): ").strip()

    creds['download_dir'] = './temp_videos'
    
    save_choice = input("是否保存此连接信息? [Y/n] ").lower().strip()
    if save_choice in ['y', 'yes', '']:
        conn_name = input("为此连接指定一个名称: ").strip()
        creds['name'] = conn_name
    
    print("---------------------------\n")
    return creds

def save_credentials(creds):
    """保存连接凭证（密码加密）到数据库。"""
    if 'name' not in creds or not creds['name']:
        return

    encrypted_pass = encrypt_password(creds.get('password')) if creds.get('password') else None

    save_data = {
        'name': creds['name'],
        'protocol': creds.get('protocol'),
        'host': creds.get('host'),
        'port': creds.get('port'),
        'username': creds.get('username'),
        'password': encrypted_pass,
        'remote_dir': creds.get('remote_dir')
    }
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO connections (name, protocol, host, port, username, password, remote_dir)
        VALUES (:name, :protocol, :host, :port, :username, :password, :remote_dir)
    ''', save_data)
    conn.commit()
    conn.close()
    logging.info(f"连接信息 '{creds['name']}' 已保存到数据库。")

# --- 功能模块 ---

def check_dependencies(config):
    """检查核心依赖（如 FFmpeg, FFprobe）是否可用。"""
    logging.info("正在检查核心依赖...")
    settings = config['SETTINGS'] if 'SETTINGS' in config else {}
    ffmpeg_cmd = settings.get('ffmpeg_path', 'ffmpeg')
    ffprobe_cmd = settings.get('ffprobe_path', 'ffprobe')
    
    for cmd_name, cmd_path in [("FFmpeg", ffmpeg_cmd), ("FFprobe", ffprobe_cmd)]:
        try:
            # 使用 -version 命令来检查程序是否可执行
            subprocess.run([cmd_path, '-version'], check=True, capture_output=True, text=True)
            logging.info(f"✅ {cmd_name} 依赖检查通过 ({cmd_path})。")
        except FileNotFoundError:
            logging.critical(f"致命错误: {cmd_name} 命令 ('{cmd_path}') 未找到。")
            logging.critical("请确保 FFmpeg 已安装并已添加到系统 PATH，或者在 config.ini 中正确指定了其可执行文件路径。")
            logging.critical("对于 macOS (arm64) 用户, 可以尝试使用 'brew install ffmpeg' 命令进行安装。")
            return False
        except subprocess.CalledProcessError as e:
            logging.critical(f"致命错误: {cmd_name} 命令 ('{cmd_path}') 执行失败。")
            logging.critical(f"错误信息: {e.stderr}")
            return False
    return True


def get_video_files(conn, remote_dir, settings, protocol):
    """根据协议类型，递归遍历远程目录并收集视频文件。"""
    ext_str = settings.get('video_extensions', '.mp4,.mkv,.avi,.mov,.wmv,.flv,.mpg,.mpeg')
    video_extensions = {f".{ext.strip().lstrip('.')}" for ext in ext_str.split(',')}
    
    if protocol == 'local':
        return _get_local_video_files(remote_dir, video_extensions)
    elif protocol == 'ftp':
        return _get_ftp_video_files(conn, remote_dir, video_extensions)
    elif protocol == 'smb':
        # SMB需要服务名，通常是共享文件夹的名称。我们假设它在remote_dir的第一部分。
        parts = [p for p in remote_dir.split('/') if p]
        if not parts:
            raise ValueError("SMB路径必须包含共享文件夹名称，例如 'share/videos'")
        service_name = parts[0]
        path_inside_share = '/'.join(parts[1:])
        return _get_smb_video_files(conn, service_name, path_inside_share, video_extensions)
    else:
        raise ValueError(f"不支持的协议: {protocol}")

def _get_ftp_video_files(ftp, remote_dir, video_extensions):
    video_files = []
    path_list = [remote_dir]
    pbar = tqdm(desc="正在扫描FTP服务器文件", unit=" dir")
    
    while path_list:
        current_path = path_list.pop(0)
        pbar.set_postfix_str(current_path)
        try:
            items = ftp.nlst(current_path)
        except Exception as e:
            logging.warning(f"无法访问FTP目录 {current_path}: {e}")
            continue

        for item in items:
            item_path = item if item.startswith('/') else f"{current_path.rstrip('/')}/{item}"
            try:
                original_cwd = ftp.pwd()
                ftp.cwd(item_path)
                path_list.append(item_path)
                ftp.cwd(original_cwd)
                pbar.update(1)
            except Exception:
                if Path(item_path).suffix.lower() in video_extensions:
                    video_files.append(item_path)
    
    pbar.close()
    logging.info(f"FTP扫描完成，共发现 {len(video_files)} 个视频文件。")
    return video_files

def _get_smb_video_files(smb_conn, service_name, start_path, video_extensions):
    video_files = []
    path_list = [start_path]
    pbar = tqdm(desc="正在扫描SMB服务器文件", unit=" dir")

    while path_list:
        current_path = path_list.pop(0)
        pbar.set_postfix_str(f"{service_name}/{current_path}")
        try:
            items = smb_conn.listPath(service_name, current_path)
        except Exception as e:
            logging.warning(f"无法访问SMB目录 {service_name}/{current_path}: {e}")
            continue

        for item in items:
            if item.filename in ['.', '..']: continue
            item_path = os.path.join(current_path, item.filename).replace('\\', '/')
            full_remote_path = f"/{service_name}/{item_path}"

            if item.isDirectory:
                path_list.append(item_path)
                pbar.update(1)
            else:
                if Path(item.filename).suffix.lower() in video_extensions:
                    video_files.append(full_remote_path)
    
    pbar.close()
    logging.info(f"SMB扫描完成，共发现 {len(video_files)} 个视频文件。")
    return video_files

def _get_local_video_files(local_dir, video_extensions):
    """递归遍历本地目录并收集视频文件。"""
    video_files = []
    root_path = Path(local_dir)
    if not root_path.is_dir():
        logging.error(f"本地路径 '{local_dir}' 不是一个有效的目录。")
        return []
    
    pbar = tqdm(desc="正在扫描本地文件", unit=" file")
    for file_path in root_path.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() in video_extensions:
            video_files.append(str(file_path))
            pbar.update(1)
            
    pbar.close()
    logging.info(f"本地扫描完成，共发现 {len(video_files)} 个视频文件。")
    return video_files

def calculate_md5(file_path):
    """计算本地文件的MD5哈希值。在流式处理中不被使用。"""
    logging.warning("MD5计算需要全量下载文件，在流式分析模式下已跳过。")
    return None

def get_video_quality_metrics(video_url, ffprobe_cmd='ffprobe'):
    """使用 ffprobe 从远程URL获取视频质量指标。"""
    try:
        command = [
            ffprobe_cmd, '-v', 'quiet', '-print_format', 'json',
            '-show_format', '-show_streams', video_url
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        
        video_stream = next((s for s in data['streams'] if s['codec_type'] == 'video'), None)
        if not video_stream:
            return {"resolution": "N/A", "bitrate": 0, "duration": 0, "file_size": 0}

        width = video_stream.get('width', 0)
        height = video_stream.get('height', 0)
        duration = float(data['format'].get('duration', 0.0))
        file_size = int(data['format'].get('size', 0))
        bitrate = int(data['format'].get('bit_rate', 0))
        
        if bitrate == 0 and duration > 0:
            bitrate = int((file_size * 8) / duration)

        return {
            "resolution": f"{width}x{height}" if width and height else "N/A",
            "bitrate": bitrate,
            "duration": duration,
            "file_size": file_size
        }
    except subprocess.CalledProcessError as e:
        logging.error(f"使用 ffprobe 分析URL {video_url} 失败: {e.stderr}")
        return {"resolution": "Error", "bitrate": 0, "duration": 0, "file_size": 0}
    except Exception as e:
        logging.error(f"无法从URL {video_url} 获取元数据: {e}")
        return {"resolution": "Error", "bitrate": 0, "duration": 0, "file_size": 0}

def check_video_health(video_url, ffmpeg_cmd):
    """使用 ffmpeg 检查远程视频URL的健康状况。"""
    try:
        command = [ffmpeg_cmd, '-v', 'error', '-i', video_url, '-f', 'null', '-']
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        error_output = result.stderr.lower()
        
        health_score = 100
        warning_keywords = ['warning', 'deprecated', 'non-monotonous', 'invalid', 'corrupt', 'error']
        error_count = sum(1 for keyword in warning_keywords if keyword in error_output)
        
        if error_count > 5:
            health_score = max(0, 100 - error_count * 15)
            status = "Warning"
        elif error_count > 0:
            health_score = max(80, 100 - error_count * 10)
            status = "Healthy"
        else:
            health_score = 100
            status = "Healthy"
            
        return status, health_score
    except subprocess.CalledProcessError as e:
        logging.error(f"URL {video_url} 指向的文件可能已损坏: {e.stderr.strip()}")
        return "Corrupted", 0
    except FileNotFoundError:
        logging.error(f"ffmpeg 命令 '{ffmpeg_cmd}' 未找到。")
        raise

def calculate_perceptual_hash(video_url, ffmpeg_cmd='ffmpeg', hash_method='dhash', keyframe_count=10):
    """
    使用 FFmpeg 从远程URL提取真正的I-frame（关键帧）并计算感知哈希。
    """
    hashes = []
    keyframe_info = {"method": "I-frame-stream"}

    try:
        command = [
            ffmpeg_cmd,
            '-i', video_url,
            '-vf', f"select='eq(pict_type,I)',fps=1",
            '-vsync', 'vfr',
            '-f', 'image2pipe',
            '-pix_fmt', 'rgb24',
            '-c:v', 'png',
            'pipe:1'
        ]
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            error_msg = stderr.decode('utf-8', errors='ignore')
            if "Output file is empty" not in error_msg:
                 logging.warning(f"FFmpeg 在为 {video_url} 提取关键帧时出错: {error_msg.strip()}")
            return [], []

        image_stream = BytesIO(stdout)
        frame_count = 0
        while image_stream.tell() < len(stdout) and frame_count < keyframe_count:
            try:
                image = Image.open(image_stream)
                
                if hash_method == 'ahash': hash_val = imagehash.average_hash(image)
                elif hash_method == 'phash': hash_val = imagehash.phash(image)
                elif hash_method == 'whash': hash_val = imagehash.whash(image)
                else: hash_val = imagehash.dhash(image)
                
                hashes.append(str(hash_val))
                frame_count += 1
                
                next_soi = stdout.find(b'\x89PNG\r\n\x1a\n', image_stream.tell())
                if next_soi == -1: break
                image_stream.seek(next_soi)

            except Exception as e:
                logging.warning(f"处理来自 {video_url} 的关键帧流时出错: {e}")
                break

    except FileNotFoundError:
        logging.error(f"ffmpeg 命令 '{ffmpeg_cmd}' 未找到。")
        raise
    except Exception as e:
        logging.error(f"为 {video_url} 计算感知哈希时发生未知错误: {e}", exc_info=True)
        return [], []

    return hashes, [keyframe_info] * len(hashes)

def compare_hashes(hashes1, hashes2, threshold):
    """比较两组感知哈希的相似度。"""
    if not hashes1 or not hashes2: return False
    try:
        # 反序列化哈希字符串
        hashes1_list = json.loads(hashes1) if isinstance(hashes1, str) else hashes1
        hashes2_list = json.loads(hashes2) if isinstance(hashes2, str) else hashes2
        if not hashes1_list or not hashes2_list: return False
        
        img_hashes1 = [imagehash.hex_to_hash(h) for h in hashes1_list]
        img_hashes2 = [imagehash.hex_to_hash(h) for h in hashes2_list]
    except (TypeError, ValueError, json.JSONDecodeError) as e:
        logging.warning(f"无法转换或解析哈希字符串: {e}")
        return False
        
    total_distance = sum(h1 - h2 for h1 in img_hashes1 for h2 in img_hashes2)
    comparisons = len(img_hashes1) * len(img_hashes2)
    if comparisons == 0: return False
    return (total_distance / comparisons) <= threshold

def generate_report(scan_target, similarity_threshold):
    """从数据库读取数据，生成 Excel 报告和待删除文件列表。"""
    conn = sqlite3.connect(DB_FILE)
    try:
        query = "SELECT * FROM videos WHERE scan_target = ? AND file_exists = 1"
        df = pd.read_sql_query(query, conn, params=(scan_target,))
    finally:
        conn.close()

    if df.empty:
        logging.warning("数据库中没有找到与当前目标匹配的视频数据，无法生成报告。")
        return [], None

    corrupted_files = df[df['health_status'].isin(['Corrupted', 'Processing Error'])]
    
    healthy_videos = df[df['health_status'].isin(['Healthy', 'Warning'])].copy()
    healthy_videos['perceptual_hashes'] = healthy_videos['perceptual_hashes'].apply(lambda x: json.loads(x) if x else [])
    healthy_videos = healthy_videos[healthy_videos['perceptual_hashes'].apply(len) > 0]
    healthy_videos.reset_index(drop=True, inplace=True)
    
    # --- 优化重复检测算法 ---
    # 1. 使用文件大小和第一个哈希值作为预筛选的键
    from collections import defaultdict
    potential_duplicates = defaultdict(list)
    for idx, row in healthy_videos.iterrows():
        # 只有当文件大小和第一个哈希都相同时，才被认为是潜在重复
        if row['perceptual_hashes']:
            group_key = (row['file_size'], row['perceptual_hashes'][0])
            potential_duplicates[group_key].append(idx)

    # 2. 只在这些预筛选出的、小规模的组内进行两两比较
    processed_indices = set()
    duplicate_groups = []
    for group_key, indices in potential_duplicates.items():
        if len(indices) < 2: continue # 如果组内只有一个文件，跳过

        # 在这个小得多的组内进行暴力比较
        while indices:
            i = indices.pop(0)
            if i in processed_indices: continue
            
            current_group_indices = [i]
            # 创建一个新的列表副本进行迭代，以安全地修改原始列表
            remaining_indices = list(indices)
            
            for j in remaining_indices:
                if j in processed_indices: continue
                
                # 在这里进行昂贵的哈希比较
                if compare_hashes(healthy_videos.at[i, 'perceptual_hashes'], healthy_videos.at[j, 'perceptual_hashes'], similarity_threshold):
                    current_group_indices.append(j)
                    processed_indices.add(j)
                    # 从原始列表中移除已配对的项，减少后续比较
                    if j in indices:
                        indices.remove(j)

            if len(current_group_indices) > 1:
                processed_indices.add(i)
                duplicate_groups.append(healthy_videos.loc[current_group_indices])

    report_sheets = {}
    
    # 创建总览表，包含所有文件
    df_summary = df[['file_path', 'health_status', 'health_score', 'resolution', 'bitrate', 'file_size', 'duration']].copy()
    
    # 处理空值和0值，确保显示为有效数据
    df_summary['bitrate (kbps)'] = (df_summary['bitrate'] / 1000).round(2)
    df_summary['bitrate (kbps)'] = df_summary['bitrate (kbps)'].apply(lambda x: 'N/A' if x == 0 else x)
    
    df_summary['file_size (MB)'] = (df_summary['file_size'] / (1024*1024)).round(2)
    df_summary['file_size (MB)'] = df_summary['file_size (MB)'].apply(lambda x: 'N/A' if x == 0 else x)
    
    df_summary['duration (s)'] = df_summary['duration'].round(2)
    df_summary['duration (s)'] = df_summary['duration (s)'].apply(lambda x: 'N/A' if x == 0 else x)
    
    # 处理分辨率
    df_summary['resolution'] = df_summary['resolution'].replace({'Error': 'N/A', '': 'N/A', 0: 'N/A'})
    
    # 处理健康值
    df_summary['健康值'] = df_summary['health_score'].astype(int)
    
    # 重命名列
    df_summary = df_summary[['file_path', 'health_status', '健康值', 'resolution', 'bitrate (kbps)', 'file_size (MB)', 'duration (s)']]
    df_summary.rename(columns={'health_status': '健康状态', 'resolution': '分辨率'}, inplace=True)
    
    report_sheets['总览'] = df_summary

    if not corrupted_files.empty:
        # 为损坏的文件也生成完整报告
        corrupted_summary = corrupted_files[['file_path', 'health_status', 'health_score', 'resolution', 'bitrate', 'file_size', 'duration']].copy()
        corrupted_summary['bitrate (kbps)'] = 'N/A'
        corrupted_summary['file_size (MB)'] = 'N/A'
        corrupted_summary['duration (s)'] = 'N/A'
        corrupted_summary['resolution'] = 'N/A'
        corrupted_summary['健康值'] = corrupted_summary['health_score'].astype(int)
        corrupted_summary = corrupted_summary[['file_path', 'health_status', '健康值', 'resolution', 'bitrate (kbps)', 'file_size (MB)', 'duration (s)']]
        report_sheets['损坏或处理失败的文件'] = corrupted_summary

    if duplicate_groups:
        all_duplicates_data = []
        for i, group_df in enumerate(duplicate_groups):
            group_id = f"重复组 {i+1}"
            group_df = group_df.copy()
            group_df['resolution_pixels'] = group_df['resolution'].apply(lambda x: int(x.split('x')[0]) * int(x.split('x')[1]) if isinstance(x, str) and 'x' in x else 0)
            
            sorted_group = group_df.sort_values(by=['resolution_pixels', 'bitrate', 'health_score'], ascending=[False, False, False])
            
            recommendations = ['保留 (质量最佳)'] + ['删除 (推荐)'] * (len(sorted_group) - 1)
            sorted_group['建议操作'] = recommendations
            sorted_group['重复组ID'] = group_id
            
            sorted_group['bitrate (kbps)'] = (sorted_group['bitrate'] / 1000).round(2)
            sorted_group['容量(MB)'] = (sorted_group['file_size'] / (1024*1024)).round(2)
            
            all_duplicates_data.append(sorted_group)

        if all_duplicates_data:
            # 更新 duplicate_groups 列表为排序和添加了建议操作后的版本
            duplicate_groups = all_duplicates_data
            df_duplicates = pd.concat(all_duplicates_data)
            df_duplicates['bitrate (kbps)'] = (df_duplicates['bitrate'] / 1000).round(2)
            df_duplicates['容量(MB)'] = (df_duplicates['file_size'] / (1024*1024)).round(2)
            df_duplicates['健康值'] = df_duplicates['health_score'].astype(int)
            
            # 使用原始列名
            final_columns = ['重复组ID', 'file_path', 'resolution', 'bitrate (kbps)', '容量(MB)', '健康值', '建议操作']
            report_sheets['内容重复的文件'] = df_duplicates[final_columns]

    # --- 生成 Excel 报告 ---
    try:
        # 使用xlsxwriter引擎处理特殊字符
        with pd.ExcelWriter('video_analysis_report.xlsx', engine='xlsxwriter') as writer:
            for sheet_name, data_frame in report_sheets.items():
                # 确保文件路径列是字符串类型
                data_frame = data_frame.copy()
                if 'file_path' in data_frame.columns:
                    data_frame['file_path'] = data_frame['file_path'].astype(str)
                elif '文件路径' in data_frame.columns:
                    data_frame['文件路径'] = data_frame['文件路径'].astype(str)
                data_frame.to_excel(writer, sheet_name=sheet_name, index=False)
        logging.info("报告已生成: video_analysis_report.xlsx")
    except Exception as e:
        logging.error(f"生成 Excel 报告失败: {e}")
        # 如果Excel生成失败，生成CSV作为备选
        try:
            if '总览' in report_sheets:
                report_sheets['总览'].to_csv('video_analysis_report.csv', index=False, encoding='utf-8-sig')
                logging.info("已生成CSV格式报告: video_analysis_report.csv")
        except Exception as csv_error:
            logging.error(f"生成CSV报告也失败: {csv_error}")

    return duplicate_groups, df

def download_file(conn, remote_path, local_path, protocol):
    """根据协议下载文件。"""
    if protocol == 'ftp':
        file_size = conn.size(remote_path)
        with open(local_path, 'wb') as f, tqdm(
            total=file_size, unit='B', unit_scale=True, desc=f"下载 {local_path.name}", leave=False
        ) as pbar:
            def callback(data):
                f.write(data)
                pbar.update(len(data))
            conn.retrbinary(f'RETR {remote_path}', callback)
    elif protocol == 'smb':
        parts = [p for p in remote_path.split('/') if p]
        service_name = parts[0]
        path_inside_share = '/'.join(parts[1:])
        file_obj = BytesIO()
        file_attributes, file_size = conn.retrieveFile(service_name, path_inside_share, file_obj)
        with open(local_path, 'wb') as f:
            f.write(file_obj.getvalue())

def delete_file(conn, remote_path, protocol):
    """根据协议删除文件。"""
    if protocol == 'ftp':
        conn.delete(remote_path)
    elif protocol == 'smb':
        parts = [p for p in remote_path.split('/') if p]
        service_name = parts[0]
        path_inside_share = '/'.join(parts[1:])
        conn.deleteFiles(service_name, path_inside_share)

def run_processing_loop(nas_creds, settings):
    """运行核心的文件处理循环，使用数据库进行状态管理。"""
    protocol = nas_creds.get('protocol', 'ftp')
    
    if protocol == 'local':
        scan_target = f"local://{nas_creds['remote_dir']}"
    else:
        scan_target = f"{protocol}://{nas_creds['host']}:{nas_creds['remote_dir']}"
        
    max_workers = settings.getint('max_workers', 4)
    pool = None # local模式不需要连接池

    if protocol != 'local':
        # 1. 根据协议初始化连接池
        pool_class = FTPConnectionPool if protocol == 'ftp' else SMBConnectionPool
        pool = pool_class(max_connections=max_workers + 1, creds=nas_creds)

    try:
        # 2. 扫描文件
        all_video_files_set = set()
        if protocol == 'local':
            logging.info(f"开始扫描本地路径: {nas_creds['remote_dir']}")
            all_video_files_set = set(get_video_files(None, nas_creds.get('remote_dir'), settings, protocol))
        else:
            with connection_pool_manager(pool) as scan_connection:
                logging.info(f"开始通过 {protocol.upper()} 扫描服务器文件...")
                all_video_files_set = set(get_video_files(scan_connection, nas_creds.get('remote_dir', '/'), settings, protocol))
        logging.info("文件扫描完成。")

        # 3. 同步数据库状态，清理幽灵记录
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("SELECT file_path FROM videos WHERE scan_target = ? AND file_exists = 1", (scan_target,))
        db_files_set = {row[0] for row in cursor.fetchall()}
        
        ghost_files = db_files_set - all_video_files_set
        if ghost_files:
            logging.info(f"发现 {len(ghost_files)} 个已从NAS删除的文件，正在更新数据库...")
            update_query = "UPDATE videos SET file_exists = 0 WHERE scan_target = ? AND file_path = ?"
            cursor.executemany(update_query, [(scan_target, f) for f in ghost_files])
            conn.commit()
            logging.info("数据库中的幽灵记录已清理。")

        # 4. 确定需要处理的新文件
        files_to_process = list(all_video_files_set - db_files_set)
        conn.close()

        if not all_video_files_set and not db_files_set:
            logging.warning("在指定目录中未找到任何视频文件，且数据库中无相关记录。")
            return

        if not files_to_process:
            logging.info("所有文件均已在数据库中，无需处理新文件。")
        else:
            processed_count = len(db_files_set - ghost_files)
            logging.info(f"NAS文件总数: {len(all_video_files_set)}, 数据库中已存在: {processed_count}, 新增待处理: {len(files_to_process)}")

            # 5. 并发处理新文件
            logging.info(f"将使用 {max_workers} 个并发线程进行处理。")
            
            # 确保下载目录存在
            # 仅在非 local 模式下创建缓存目录并显示提示
            if protocol != 'local':
                download_dir = Path(nas_creds.get('download_dir', './temp_videos'))
                download_dir.mkdir(parents=True, exist_ok=True)
                logging.info(f"临时文件将缓存到: {download_dir.resolve()}")

            def process_video_task(remote_path, nas_creds, settings, scan_target, pool):
                """根据协议类型，智能选择流式分析或下载后分析。"""
                protocol = nas_creds['protocol']
                
                # --- 为 local 模式或 SMB/FTP 模式准备分析路径 ---
                # local 模式直接使用路径；FTP/SMB 模式则先下载
                analysis_path = remote_path
                temp_local_path = None # 用于确保删除临时文件

                try:
                    if protocol in ['ftp', 'smb']:
                        # 下载模式
                        temp_dir = Path(nas_creds.get('download_dir', './temp_videos'))
                        thread_id = threading.get_ident()
                        file_hash = hashlib.md5(remote_path.encode()).hexdigest()[:8]
                        temp_local_path = temp_dir / f"temp_{thread_id}_{file_hash}_{Path(remote_path).name}"
                        
                        with connection_pool_manager(pool) as conn:
                            download_file(conn, remote_path, temp_local_path, protocol)
                        analysis_path = str(temp_local_path)
                    
                    # --- 开始分析 (无论是本地路径还是临时文件路径) ---
                    ffmpeg_cmd = settings.get('ffmpeg_path', 'ffmpeg')
                    ffprobe_cmd = settings.get('ffprobe_path', 'ffprobe')
                    md5_hash = None # MD5 成本高，统一跳过

                    quality_metrics = get_video_quality_metrics(analysis_path, ffprobe_cmd)
                    health_status, health_score = check_video_health(analysis_path, ffmpeg_cmd)
                    
                    perceptual_hashes_list, keyframe_info_list = [], []
                    if health_status in ["Healthy", "Warning"]:
                        hashes, indices = calculate_perceptual_hash(
                            analysis_path,
                            ffmpeg_cmd,
                            settings.get('hash_method', 'dhash'),
                            settings.getint('keyframe_count', 10)
                        )
                        perceptual_hashes_list = hashes
                        keyframe_info_list = indices
                    
                    return {
                        "file_path": remote_path,
                        "scan_target": scan_target,
                        "md5": md5_hash,
                        "health_status": health_status,
                        "health_score": health_score,
                        "perceptual_hashes": json.dumps(perceptual_hashes_list),
                        "keyframe_info": json.dumps(keyframe_info_list),
                        **quality_metrics
                    }
                except Exception as e:
                    logging.error(f"处理文件 {Path(remote_path).name} 时发生错误: {e}", exc_info=True)
                    return None
                finally:
                    # 确保临时文件被删除
                    if temp_local_path and temp_local_path.exists():
                        try:
                            temp_local_path.unlink()
                        except OSError as e:
                            logging.warning(f"删除临时文件 {temp_local_path} 失败: {e}")

            # 提交任务到线程池并收集结果
            # 为保证中断后可恢复，每处理完一个文件就写入一次数据库
            db_conn = sqlite3.connect(DB_FILE, timeout=10)
            db_cursor = db_conn.cursor()
            
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_path = {
                        executor.submit(process_video_task, path, nas_creds, settings, scan_target, pool): path
                        for path in files_to_process
                    }
                    
                    pbar_files = tqdm(concurrent.futures.as_completed(future_to_path), total=len(files_to_process), desc="正在并发处理视频")
                    for future in pbar_files:
                        remote_path = future_to_path[future]
                        pbar_files.set_postfix_str(Path(remote_path).name)
                        try:
                            result_data = future.result()
                            if result_data:
                                # 6. 实时写入数据库
                                tuple_to_insert = (
                                    result_data['file_path'], result_data['scan_target'], result_data['file_size'], result_data['duration'],
                                    result_data['resolution'], result_data['bitrate'], result_data['health_status'], result_data['health_score'],
                                    result_data['perceptual_hashes'], result_data['keyframe_info'], result_data['md5']
                                )
                                db_cursor.execute('''
                                    INSERT OR REPLACE INTO videos (file_path, scan_target, file_size, duration, resolution, bitrate, health_status, health_score, perceptual_hashes, keyframe_info, md5)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                ''', tuple_to_insert)
                                db_conn.commit()
                        except Exception as exc:
                            logging.error(f'文件 {remote_path} 在执行期间产生了严重异常: {exc}', exc_info=True)
            finally:
                db_conn.close()
                logging.info("数据库连接已关闭，处理进度已保存。")
    finally:
        # 确保连接池中的所有连接都被关闭
        if pool:
            pool.close_all_connections()

def interactive_delete_files(duplicate_groups_dfs, delete_pool):
    """
    交互式地向用户展示重复文件组，并根据用户的选择进行删除。
    """
    if not duplicate_groups_dfs:
        logging.info("没有发现可供删除的重复文件。")
        return

    # 从 group dataframes 中提取所有推荐删除的文件
    all_recommended_to_delete = []
    total_potential_savings = 0
    for group_df in duplicate_groups_dfs:
        deletable = group_df[group_df['建议操作'] == '删除 (推荐)']
        all_recommended_to_delete.extend(deletable.to_dict('records'))
        total_potential_savings += deletable['file_size'].sum()

    if not all_recommended_to_delete:
        logging.info("分析完成，没有发现可推荐删除的重复文件。")
        return

    print("\n--- 发现内容重复的文件 ---")
    print(f"共找到 {len(all_recommended_to_delete)} 个可删除的重复文件，可释放约 {total_potential_savings / (1024*1024):.2f} MB 空间。")
    print("注意：删除操作不可逆，请谨慎操作。")

    files_to_actually_delete = []

    while True:
        choice = input("\n请选择操作模式: [A]全部删除, [G]按组确认, [I]逐个确认, [S]跳过删除, [Q]退出: ").upper().strip()

        if choice == 'A':
            confirm = input(f"确定要删除所有 {len(all_recommended_to_delete)} 个推荐文件吗? [y/N]: ").lower().strip()
            if confirm == 'y':
                files_to_actually_delete = all_recommended_to_delete
                break
        
        elif choice == 'G':
            for i, group_df in enumerate(duplicate_groups_dfs):
                print(f"\n--- 重复组 {i+1} ---")
                # 使用 to_string() 避免 pandas 自动截断
                print(group_df[['file_path', 'resolution', 'bitrate (kbps)', '容量(MB)', '建议操作']].to_string(index=False))
                group_choice = input("删除此组中的推荐文件吗? [Y/n/s(kip all)]: ").lower().strip()
                if group_choice in ['y', 'yes', '']:
                    deletable = group_df[group_df['建议操作'] == '删除 (推荐)']
                    files_to_actually_delete.extend(deletable.to_dict('records'))
                elif group_choice == 's':
                    print("跳过所有剩余的组。")
                    break
            break

        elif choice == 'I':
            for file_info in all_recommended_to_delete:
                file_path = file_info['file_path']
                file_size_mb = file_info['file_size'] / (1024*1024)
                individual_choice = input(f"删除文件 '{file_path}' ({file_size_mb:.2f} MB)? [Y/n/a(ll)/s(kip all)]: ").lower().strip()
                if individual_choice in ['y', 'yes', '']:
                    files_to_actually_delete.append(file_info)
                elif individual_choice == 'a':
                    # 将当前文件及所有剩余文件加入删除列表
                    current_index = all_recommended_to_delete.index(file_info)
                    files_to_actually_delete.extend(all_recommended_to_delete[current_index:])
                    print("已将剩余所有推荐文件加入删除列表。")
                    break
                elif individual_choice == 's':
                    print("跳过所有剩余文件。")
                    break
                elif individual_choice == 'n':
                    continue
            break

        elif choice == 'S' or choice == 'Q':
            print("已跳过删除操作。")
            return
        
        else:
            print("无效输入，请重新选择。")

    if not files_to_actually_delete:
        logging.info("没有选择任何文件进行删除。")
        return

    logging.info(f"准备删除 {len(files_to_actually_delete)} 个文件...")
    
    # 使用线程池并发删除
    with concurrent.futures.ThreadPoolExecutor(max_workers=delete_pool.max_connections) as executor:
        def delete_task(file_info):
            remote_path = file_info['file_path']
            try:
                with connection_pool_manager(delete_pool) as conn:
                    delete_file(conn, remote_path, delete_pool.protocol)
                return remote_path, True, None
            except Exception as e:
                logging.error(f"删除文件 {remote_path} 失败: {e}")
                return remote_path, False, str(e)

        future_to_path = {executor.submit(delete_task, f): f for f in files_to_actually_delete}
        
        pbar_delete = tqdm(concurrent.futures.as_completed(future_to_path), total=len(files_to_actually_delete), desc="正在删除文件")
        for future in pbar_delete:
            path, success, error = future.result()
            if success:
                pbar_delete.set_postfix_str(f"已删除: {Path(path).name}")
            else:
                pbar_delete.set_postfix_str(f"失败: {Path(path).name}")

    logging.info("文件删除流程结束。")
def main():
    """主执行函数。"""
    parser = argparse.ArgumentParser(description="视频库健康检查和重复文件分析工具。")
    parser.add_argument('--host', type=str, help="NAS 的主机名或 IP 地址。")
    parser.add_argument('--port', type=str, help="连接端口号。")
    parser.add_argument('--username', type=str, help="登录用户名。")
    parser.add_argument('--password', type=str, help="登录密码（如果省略，将提示输入）。")
    parser.add_argument('--protocol', type=str, default='ftp', choices=['ftp', 'smb', 'local'], help="连接协议 (默认为 ftp)。")
    parser.add_argument('--dir', type=str, default='/', help="要扫描的远程根目录 (默认为 /)。")
    parser.add_argument('-y', '--yes', action='store_true', help="自动确认所有提示。")
    args = parser.parse_args()

    setup_logging()
    init_database() # 初始化数据库
    logging.info("程序启动。")

    try:
        config = load_config()
        if not check_dependencies(config):
            return
            
        settings = config['SETTINGS'] if 'SETTINGS' in config else {}
        
        def manage_tasks():
            """任务管理界面，允许用户选择要执行的任务"""
            tasks = []
            
            while True:
                print("\n=== 任务管理 ===")
                print("[1] 添加新路径到任务列表")
                print("[2] 查看当前任务列表")
                print("[3] 执行任务")
                print("[4] 清空任务列表")
                print("[q] 返回主菜单")
                
                choice = input("请选择操作: ").strip()
                
                if choice == '1':
                    # 添加新任务
                    current_config = None  # 强制进入交互模式
                    nas_creds = get_user_credentials(args, current_config)
                    if nas_creds is not None:
                        save_credentials(nas_creds)
                        
                        if nas_creds['protocol'] == 'local':
                            scan_target = f"local://{nas_creds['remote_dir']}"
                        else:
                            scan_target = f"{nas_creds['protocol']}://{nas_creds['host']}:{nas_creds['remote_dir']}"
                        
                        # 检查是否已存在
                        conn = sqlite3.connect(DB_FILE)
                        cursor = conn.cursor()
                        cursor.execute("SELECT COUNT(*) FROM videos WHERE scan_target = ?", (scan_target,))
                        existing_records = cursor.fetchone()[0]
                        conn.close()
                        
                        task_info = {
                            'creds': nas_creds,
                            'scan_target': scan_target,
                            'existing_records': existing_records
                        }
                        
                        # 检查是否重复添加
                        if any(t['scan_target'] == scan_target for t in tasks):
                            print("该路径已在任务列表中！")
                        else:
                            tasks.append(task_info)
                            print(f"已添加任务: {scan_target}")
                            if existing_records > 0:
                                print(f"  (该路径有 {existing_records} 条历史记录)")
                
                elif choice == '2':
                    if not tasks:
                        print("当前没有待执行的任务")
                    else:
                        print("\n=== 当前任务列表 ===")
                        for i, task in enumerate(tasks, 1):
                            print(f"[{i}] {task['scan_target']}")
                            if task['existing_records'] > 0:
                                print(f"    历史记录: {task['existing_records']} 条")
                
                elif choice == '3':
                    if not tasks:
                        print("请先添加任务！")
                        continue
                    
                    # 执行任务
                    for task in tasks:
                        nas_creds = task['creds']
                        scan_target = task['scan_target']
                        existing_records = task['existing_records']
                        
                        print(f"\n=== 准备执行任务: {scan_target} ===")
                        
                        # 处理历史记录
                        if existing_records > 0:
                            print(f"发现 {existing_records} 条历史记录")
                            action = input("请选择: [C]继续扫描, [R]重新扫描, [S]跳过此任务: ").upper().strip()
                            if action == 'R':
                                conn = sqlite3.connect(DB_FILE)
                                cursor = conn.cursor()
                                cursor.execute("DELETE FROM videos WHERE scan_target = ?", (scan_target,))
                                conn.commit()
                                conn.close()
                                print("历史记录已清空")
                            elif action == 'S':
                                print("跳过此任务")
                                continue
                        
                        # 执行任务
                        try:
                            with tqdm(total=3, desc="总体进度") as pbar:
                                pbar.set_description("步骤 1/3: 分析文件")
                                run_processing_loop(nas_creds, settings)
                                pbar.update(1)

                                pbar.set_description("步骤 2/3: 生成报告")
                                logging.info("正在生成报告...")
                                duplicate_groups, _ = generate_report(scan_target, settings.getfloat('similarity_threshold', 5))
                                pbar.update(1)
                                
                                pbar.set_description("步骤 3/3: 文件删除")
                                if duplicate_groups:
                                    protocol = nas_creds.get('protocol', 'local')
                                    if protocol != 'local':
                                        delete_pool_class = FTPConnectionPool if protocol == 'ftp' else SMBConnectionPool
                                        delete_pool = delete_pool_class(max_connections=settings.getint('max_workers', 4), creds=nas_creds)
                                        try:
                                            interactive_delete_files(duplicate_groups, delete_pool)
                                        finally:
                                            delete_pool.close_all_connections()
                                    else:
                                        logging.warning("本地文件删除功能尚未实现，请手动删除。")
                                pbar.update(1)
                            
                            print(f"任务 {scan_target} 完成！")
                            
                        except KeyboardInterrupt:
                            print("\n任务被用户中断")
                            break
                        except Exception as e:
                            print(f"任务执行失败: {e}")
                            logging.error(f"任务执行失败: {e}", exc_info=True)
                    
                    # 清空已完成的任务
                    tasks.clear()
                    print("所有任务已完成")
                
                elif choice == '4':
                    tasks.clear()
                    print("任务列表已清空")
                
                elif choice.lower() == 'q':
                    return
                
                else:
                    print("无效的选择")

        # 主循环
        while True:
            print("\n=== 视频库管理主菜单 ===")
            print("[1] 管理扫描任务")
            print("[2] 快速扫描（单一路径）")
            print("[3] 查看已保存的连接")
            print("[q] 退出程序")
            
            main_choice = input("请选择操作: ").strip()
            
            if main_choice == '1':
                manage_tasks()
            
            elif main_choice == '2':
                # 快速扫描模式（原来的行为）
                current_config = config if args.host or (args.protocol == 'local' and args.dir) else None
                nas_creds = get_user_credentials(args, current_config)
                
                if nas_creds is None:
                    continue
                
                save_credentials(nas_creds)
                
                if nas_creds['protocol'] == 'local':
                    scan_target = f"local://{nas_creds['remote_dir']}"
                else:
                    scan_target = f"{nas_creds['protocol']}://{nas_creds['host']}:{nas_creds['remote_dir']}"
                
                # 检查历史记录
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM videos WHERE scan_target = ?", (scan_target,))
                existing_records = cursor.fetchone()[0]
                conn.close()

                if existing_records > 0:
                    print(f"\n--- 发现 '{scan_target}' 的历史扫描记录 ---")
                    print(f"数据库中已存在 {existing_records} 条相关记录。")
                    action = input("请选择操作: [C]继续扫描, [R]重新扫描 (清空历史), [A]中止操作: ").upper().strip()
                    if action == 'R':
                        logging.info(f"用户选择重新扫描，将清空 '{scan_target}' 的所有历史记录。")
                        conn = sqlite3.connect(DB_FILE)
                        cursor = conn.cursor()
                        cursor.execute("DELETE FROM videos WHERE scan_target = ?", (scan_target,))
                        conn.commit()
                        conn.close()
                        logging.info("历史记录已清空。")
                    elif action != 'C':
                        logging.info("用户中止了当前任务。")
                        continue

                # 执行快速扫描
                try:
                    with tqdm(total=3, desc="总体进度") as pbar:
                        pbar.set_description("步骤 1/3: 分析文件")
                        run_processing_loop(nas_creds, settings)
                        pbar.update(1)

                        pbar.set_description("步骤 2/3: 生成报告")
                        logging.info("所有文件处理完成，正在从数据库生成最终报告...")
                        duplicate_groups, _ = generate_report(scan_target, settings.getfloat('similarity_threshold', 5))
                        pbar.update(1)
                        
                        pbar.set_description("步骤 3/3: 文件删除")
                        if duplicate_groups:
                            protocol = nas_creds.get('protocol', 'local')
                            if protocol != 'local':
                                delete_pool_class = FTPConnectionPool if protocol == 'ftp' else SMBConnectionPool
                                delete_pool = delete_pool_class(max_connections=settings.getint('max_workers', 4), creds=nas_creds)
                                try:
                                    interactive_delete_files(duplicate_groups, delete_pool)
                                finally:
                                    delete_pool.close_all_connections()
                            else:
                                logging.warning("本地文件删除功能尚未实现，请手动删除。")
                        pbar.update(1)

                    logging.info(f"任务 '{scan_target}' 完成。")
                
                except KeyboardInterrupt:
                    logging.warning("任务被用户中断")
                except Exception as e:
                    logging.error(f"任务执行失败: {e}", exc_info=True)
            
            elif main_choice == '3':
                # 查看已保存的连接
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute("SELECT id, name, protocol, host, username, remote_dir FROM connections ORDER BY last_used DESC")
                connections = cursor.fetchall()
                conn.close()
                
                if not connections:
                    print("当前没有已保存的连接")
                else:
                    print("\n=== 已保存的连接 ===")
                    for conn_data in connections:
                        if conn_data[2] == 'local':
                            print(f"  {conn_data[1]} (local: {conn_data[5]})")
                        else:
                            print(f"  {conn_data[1]} ({conn_data[2]}://{conn_data[3]} - {conn_data[4]})")
            
            elif main_choice.lower() == 'q':
                logging.info("用户选择退出程序。")
                break
            
            else:
                print("无效的选择，请重新输入")

            # 如果是通过命令行参数启动的，执行一次后退出
            if args.host or (args.protocol == 'local' and args.dir):
                break

    except (ConnectionError, FileNotFoundError, KeyboardInterrupt) as e:
        logging.warning(f"程序已终止: {e}")
    except Exception as e:
        logging.error(f"程序执行期间发生未预料的错误: {e}", exc_info=True)
    finally:
        logging.info("程序执行完毕。")

if __name__ == "__main__":
    main()