import os
import re
import sys
import json
import hashlib
import time
import platform
from jose import jwt
from functools import lru_cache

def sha256(data):
    hash_object = hashlib.sha256()
    hash_object.update(json.dumps(data).replace(' ', '').encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

# ----------------------------------------------------------------------------------------------------------

def get_file_content(file_name):
    if not os.path.exists(file_name):
        print(f"ERROR: {file_name} file does not exist")
        sys.exit()
    with open(file_name, 'r') as f:
        data = [line.strip() for line in f.readlines()]
    return data

def get_data_for_token(name):
    # print("name: ",name)
    if name == '':
        file = f'data/token.txt'
    else:
        file = f'data/token-{name}.txt'
    datas = get_file_content(file)
    return datas

# ----------------------------------------------------------------------------------------------------------

# 添加跨平台文件锁功能
def acquire_shared_lock(file_obj, timeout=10):
    """获取共享锁，跨平台兼容"""
    if platform.system() != 'Windows':
        import fcntl
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_SH)
    else:
        import msvcrt
        # 在Windows上，通过不断尝试打开文件来模拟锁机制
        start_time = time.time()
        while True:
            try:
                # 检查是否可以访问文件
                fd = os.open(file_obj.name, os.O_RDONLY)
                os.close(fd)
                break
            except OSError:
                if time.time() - start_time > timeout:
                    raise TimeoutError(f"Could not acquire shared lock on {file_obj.name} within {timeout} seconds")
                time.sleep(0.1)

def acquire_exclusive_lock(file_obj, timeout=10):
    """获取独占锁，跨平台兼容"""
    if platform.system() != 'Windows':
        import fcntl
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)
    else:
        import msvcrt
        start_time = time.time()
        while True:
            try:
                # 尝试打开文件进行独占访问
                fd = os.open(file_obj.name, os.O_RDWR | getattr(os, 'O_BINARY', 0))
                try:
                    # 尝试锁定整个文件
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # 锁定第一个字节
                    os.lseek(fd, 0, os.SEEK_SET)  # 移动到文件开头
                    break
                finally:
                    os.close(fd)
            except (OSError, IOError):
                if time.time() - start_time > timeout:
                    raise TimeoutError(f"Could not acquire exclusive lock on {file_obj.name} within {timeout} seconds")
                time.sleep(0.1)

def safe_read_file_with_lock(file_path, encoding='utf-8'):
    """安全地读取文件内容，带锁机制"""
    if platform.system() != 'Windows':
        import fcntl
        with open(file_path, 'r', encoding=encoding) as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # 共享锁
            return f.readlines()
    else: # Windows平台：简单地读取文件，因为Python的open会自动处理基本的并发问题
        with open(file_path, 'r', encoding=encoding) as f:
            return f.readlines()

def safe_write_file_with_lock(file_path, content, encoding='utf-8'):
    """安全地写入文件，带锁机制"""
    temp_file_path = file_path + '.tmp'
    
    # 写入临时文件
    with open(temp_file_path, 'w', encoding=encoding) as f:
        f.writelines(content)
    
    if platform.system() != 'Windows':
        import fcntl
        # 使用独占锁重命名临时文件到目标文件
        with open(file_path, 'r', encoding=encoding) as f_target:
            fcntl.flock(f_target.fileno(), fcntl.LOCK_EX)  # 独占锁
            os.replace(temp_file_path, file_path)  # 原子操作替换文件
    else: # Windows平台：直接替换文件，因为os.replace在Windows上也是原子操作
        try:
            os.replace(temp_file_path, file_path)
        except OSError:
            os.rename(temp_file_path, file_path)

def _update_token_line(file_path, line_id, field_index, new_value):
    """
    通用的行更新函数，用于更新指定行的特定字段
    
    Args:
        file_path: 文件路径
        line_id: 行号（从1开始）
        field_index: 字段索引（从0开始）
        new_value: 新值
    """
    # 创建临时文件名
    temp_file_path = file_path + '.tmp'
    
    try:
        # 读取原始文件内容
        lines = safe_read_file_with_lock(file_path)
        
        if line_id < 1 or line_id > len(lines):
            raise ValueError(f"Line {line_id} is out of range.")
        
        # 获取指定行并分割字段
        line = lines[line_id - 1].rstrip('\n')
        parts = line.split(',')
        
        if len(parts) < 6:  # 确保有足够的字段
            raise ValueError(f"Line {line_id} does not have enough fields.")
        
        # 更新指定字段
        parts[field_index] = str(new_value)
        
        # 重新组装行
        updated_line = ','.join(parts) + '\n'
        lines[line_id - 1] = updated_line
        
        # 安全写入更新后的内容
        safe_write_file_with_lock(file_path, lines)
            
    except FileNotFoundError:
        raise FileNotFoundError(f"File {file_path} not found")
    except Exception as e:
        # 清理临时文件
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        raise e

def set_data_for_token(name, id, token):
    """更新指定行的token字段"""
    if name == '':
        file = f'data/token.txt'
    else:
        file = f'data/token-{name}.txt'
    _update_token_line(file, id, 3, token)  # token是第4个字段(索引为3)

def set_data_for_userid(name, id, userid):
    """更新指定行的userid字段"""
    if name == '':
        file = f'data/token.txt'
    else:
        file = f'data/token-{name}.txt'
    _update_token_line(file, id, 2, userid)  # userid是第3个字段(索引为2)

# ----------------------------------------------------------------------------------------------------------

@lru_cache(maxsize=128)
def _read_emotion_file():
    """缓存deeptrain.txt文件内容以提高读取效率"""
    file = f'data/deeptrain.txt'
    if not os.path.exists(file):
        print(f"ERROR: {file} file does not exist")
        return []
    with open(file, 'r') as f:
        datas = [line.strip() for line in f.readlines()]
    return tuple(datas)  # 使用tuple以便于缓存

def get_emotion_for_txt(period_id):
    """
    读取一个period_id对应的值 (每10期为1行)
    :param period_id:
    """
    x_pos = (period_id - 1) % 10
    line_pos = (period_id - 1) // 10
    # print(f"period_id: {period_id} => line_pos: {line_pos} x_pos: {x_pos}")
    
    datas = _read_emotion_file()
    
    # 检查是否超出范围
    if line_pos >= len(datas):
        print(f"ERROR: Line {line_pos} is out of range")
        return 0
    
    # 获取指定行
    target_line = datas[line_pos]
    line_elements = target_line.split(',')  # 假设是以逗号分隔
    # print(f"line_elements: {line_elements}")
    # 获取指定列
    if x_pos >= len(line_elements):
        print(f"ERROR: Column {x_pos} is out of range in line {line_pos}")
        return 0
    return line_elements[x_pos]

@lru_cache(maxsize=128)
def _read_choice_file():
    """缓存deepchoice.txt文件内容以提高读取效率"""
    file = f'data/deepchoice.txt'
    if not os.path.exists(file):
        print(f"ERROR: {file} file does not exist")
        return []
    with open(file, 'r') as f:
        datas = [line.strip() for line in f.readlines()]
    return tuple(datas)  # 使用tuple以便于缓存

def get_choice_for_txt(period_id):
    """
    读取一个period_id对应的值 (每3期位1纪元,每10纪元为1行)
    :param period_id:
    """
    x_pos = (period_id - 1) % 30
    line_pos = (period_id - 1) // 30
    # print(f"period_id: {period_id} => line_pos: {line_pos} x_pos: {x_pos}")
    
    datas = _read_choice_file()
    
    # 检查是否超出范围
    if line_pos >= len(datas):
        print(f"ERROR: Line {line_pos} is out of range")
        return 0
    
    # 获取指定行
    target_line = datas[line_pos]
    line_elements = target_line.split(',')  # 假设是以逗号分隔
    # print(f"line_elements: {line_elements}")
    # 获取指定列
    if x_pos >= len(line_elements):
        print(f"ERROR: Column {x_pos} is out of range in line {line_pos}")
        return 0
    return line_elements[x_pos]

# ----------------------------------------------------------------------------------------------------------

def is_valid_jwt_format(token):
    """检查JWT格式是否正确"""
    if len(token) > 20 and len(token.split('.')) == 3 and (re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token)):  # token
        return True
    return False

def is_token_valid(token):
    """验证token是否有效（未过期）"""
    try:
        payload = jwt.get_unverified_claims(token)
        # print(f"payload: {payload}")
        current_timestamp = int(time.time())
        expire = payload.get("expire")
        return expire is not None and expire > current_timestamp
    except Exception as e:
        print(f"is_token_valid error: {e}")
        return False

# ----------------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    print("emotion:"+get_emotion_for_txt(20))
    print("choice:"+get_choice_for_txt(120))
    # print("emotion:"+get_emotion_for_txt(11))
    # print("emotion:"+get_emotion_for_txt(12))
    # print("emotion:"+get_emotion_for_txt(13))
    # print("choice:"+get_choice_for_txt(121))
    # print("choice:"+get_choice_for_txt(122))
    # print("choice:"+get_choice_for_txt(123))
