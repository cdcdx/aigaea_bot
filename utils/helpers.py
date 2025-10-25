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
