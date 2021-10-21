from app.tools.interface import *

import subprocess, datetime, json


def read_module(fname):
    module_data = {}
    fpath = LOC_MODULES + fname
    with open(fpath, 'rb') as fp:
        data = fp.read()

    return data


def drop_file(module_name, options, data):
    loc_proc = "/error"
    str_now = datetime.datetime.strftime(datetime.datetime.now(), "%y%m%d_%H%M")

    # 1. 선택한 모듈의 정보 읽기
    out_name = "{}_{}".format(str_now, module_name)
    malware_code = read_module(module_name)

    # 2. 모듈의 타입별로 처리 함수로 전달; 처리 함수는 결과 파일의 위치 반환
    if data['type'] == 'C':
        ## 코드를 넘기면서 옵션 값 삽입 (insert_option)
        loc_proc = drop_file_c(code=insert_option(malware_code, options), out_name=out_name,
                               extension=data['extension'])
    if data['type'] == 'javascript':
        loc_proc = drop_file_javascript(code=insert_option(malware_code, options), out_name=out_name)
    if data['type'] == 'binary':
        loc_proc = drop_file_binary(code=insert_option(malware_code, options), out_name=out_name,
                                    extension=data['extension'])

    # 3. 제작 이력 저장
    save_malware_history(module_name, options, out_name)
        # 4. 처리 결과 파일의 위치를 반환함
    return loc_proc


# 모듈의 코드에 옵션 값 삽입
def insert_option(code, dict_option):
    res = code
    for opt in dict_option.keys():
        res = res.replace("<{}>".format(opt).encode(), dict_option[opt].encode())

    return res


def drop_file_binary(code, out_name, extension):
    print("DROP binary file")
    fname = NAME_FILE_BINARY.format(out_name)
    if extension != "":
        fname += "." + extension
    with open(LOC_TMP + fname, 'wb') as fp:
        fp.write(code)
    print("DROP Binary File End")
    return fname


def drop_file_javascript(code, out_name):
    print("DROP JAVASCRIPT HTML FILE")
    # 1. save code as html file
    fname = NAME_CODE_HTML.format(out_name)
    with open(LOC_TMP + fname, 'wb') as fp:
        fp.write(code)

    # 2. return file name
    print("DROP JAVASCRIPT HTML END")
    return fname


# C type 파일 읽기
def drop_file_c(code, out_name, extension):
    print("DROP FILE C function called")
    # 1. save code as file
    code_name = NAME_CODE_C.format(out_name)
    with open(LOC_TMP + code_name, 'wb') as fp:
        fp.write(code)

    # 2. compile C code
    compiler = ""
    if extension == "exe":
        compiler = COMPILER_WINDOWS_C
        out_name = out_name + ".exe"

    elif extension == "LINUX":
        compiler = COMPILER_LINUX_C

    command = [compiler, "-o", LOC_TMP + out_name, LOC_TMP + code_name]
    print(command)
    res = subprocess.call(command)

    return out_name


# 제적한 파일 저장
def save_malware_history(module_name, data, output_name):
    history = dict()
    with open('cve_history.json', 'r', encoding='utf-8') as file:
        history = json.load(file)
    save_data = dict()
    save_data["number"] = module_name
    save_data["date"] = datetime.datetime.now().strftime('%Y-%m-%d')
    save_data["options"] = data
    history[output_name] = save_data

    with open('cve_history.json', 'w', encoding='utf-8') as make_file:
        json.dump(history, make_file, indent="\t")
