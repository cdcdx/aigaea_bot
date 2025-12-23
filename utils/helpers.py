import hashlib
import json
import sys
import os

def sha256(data):
    hash_object = hashlib.sha256()
    hash_object.update(json.dumps(data).replace(' ', '').encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

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

def set_data_for_token(name,id,token):
    # print("name: ",name)
    if name == '':
        file = f'data/token.txt'
    else:
        file = f'data/token-{name}.txt'
    datas = get_file_content(file)
    if id < 1 or id > len(datas):
        raise ValueError(f"Line {id} is out of range.")

    data=datas[id - 1]

    parts = data.split(',')
    if len(parts) < 4:
        raise ValueError(f"Line {id} is out of range.")
    # logger.debug(f"parts: {parts}")
    email, passwd, userid, token_old, prikey, proxy = map(str.strip, parts)

    datas[id - 1] = f"{email.ljust(23)},{passwd},{userid},{token},{prikey},{proxy}"

    with open(file, 'w') as f:
        for line in datas:
            f.write(line + '\n')

def set_data_for_userid(name,id,userid):
    # print("name: ",name)
    if name == '':
        file = f'data/token.txt'
    else:
        file = f'data/token-{name}.txt'
    datas = get_file_content(file)
    if id < 1 or id > len(datas):
        raise ValueError(f"Line {id} is out of range.")

    data=datas[id - 1]

    parts = data.split(',')
    if len(parts) < 4:
        raise ValueError(f"Line {id} is out of range.")
    # logger.debug(f"parts: {parts}")
    email, passwd, userid1, token, prikey, proxy = map(str.strip, parts)

    datas[id - 1] = f"{email.ljust(23)},{passwd},{userid},{token},{prikey},{proxy}"

    with open(file, 'w') as f:
        for line in datas:
            f.write(line + '\n')

def get_emotion_for_txt(period_id):
    """
    读取一个period_id对应的值 (每10期为1行)
    :param period_id:
    """
    x_pos = period_id%10 - 1
    y_pos = period_id//10 + 1
    # print(f"period_id: {period_id}, x_pos: {x_pos}, y_pos: {y_pos}")
    
    file = f'data/deeptrain.txt'
    if not os.path.exists(file):
        print(f"ERROR: {file} file does not exist")
        return 0
    with open(file, 'r') as f:
        datas = [line.strip() for line in f.readlines()]
    
    # 检查是否超出范围
    if y_pos >= len(datas):
        print(f"ERROR: Line {y_pos} is out of range")
        return 0
    
    # 获取指定行
    target_line = datas[y_pos]
    line_elements = target_line.split(',')  # 假设是以逗号分隔
    # 获取指定列
    if x_pos >= len(line_elements):
        print(f"ERROR: Column {x_pos} is out of range in line {y_pos}")
        return 0
    return line_elements[x_pos]

def get_choice_for_txt(period_id):
    """
    读取一个period_id对应的值 (每3期位1纪元,每10纪元为1行)
    :param period_id:
    """
    x_pos = period_id%30 - 1
    y_pos = period_id//30 + 1
    # print(f"period_id: {period_id}, x_pos: {x_pos}, y_pos: {y_pos}")
    
    file = f'data/deepchoice.txt'
    if not os.path.exists(file):
        print(f"ERROR: {file} file does not exist")
        return 0
    with open(file, 'r') as f:
        datas = [line.strip() for line in f.readlines()]
    
    # 检查是否超出范围
    if y_pos >= len(datas):
        print(f"ERROR: Line {y_pos} is out of range")
        return 0
    
    # 获取指定行
    target_line = datas[y_pos]
    line_elements = target_line.split(',')  # 假设是以逗号分隔
    # 获取指定列
    if x_pos >= len(line_elements):
        print(f"ERROR: Column {x_pos} is out of range in line {y_pos}")
        return 0
    return line_elements[x_pos]

if __name__ == '__main__':
    print(get_emotion_for_txt(123))
    print(get_choice_for_txt(123))
