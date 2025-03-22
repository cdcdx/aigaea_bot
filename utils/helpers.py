import hashlib
import json

def sha256(data):
    hash_object = hashlib.sha256()
    hash_object.update(json.dumps(data).replace(' ', '').encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig

def get_file_content(file_name):
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
    userid=parts[0]
    email=parts[1]
    passwd=parts[2]
    prikey=parts[3]
    # token=parts[4]
    proxy=parts[5]
    datas[id - 1] = f"{userid},{email},{passwd},{prikey},{token},{proxy}"

    with open(file, 'w') as f:
        for line in datas:
            f.write(line + '\n')
