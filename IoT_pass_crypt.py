#!/usr/bin/python3
#-----------------------------------------------------------------------------
#   IoT Pass Crypt Tools ( IoTPCT )     Create 2021.06
#   for Raspberry Pi 
#   このツールは、Raspberry Pi Wi-Fi接続を行う場合にネットワークの通信状態を
#   監視し、状態変化があった場合に通知と修復処理を行うプログラムです。  
#   ツールの動作設定は、IoTCNTconfig.json（json形式）にて定義できます。  
#   
#   Author  : GENROKU@Karakuri-musha
#   License : See the license file for the license.
#-----------------------------------------------------------------------------
import os
from posixpath import dirname
import sys
import platform
import shutil
import subprocess
import json
import base64
from argparse import ArgumentParser
from datetime import datetime
import logging
from logging import FileHandler, Formatter
from logging import INFO, DEBUG, NOTSET
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# ----------------------------------------------------------
# 定数定義部
# ----------------------------------------------------------
MSG_GET_OPTIONS_HELP    = "Specify the installation target definition file (json format). "
PASS_PHRASE             = "f5FsQ,~c(uvf"

# ----------------------------------------------------------
# 定義部
# ----------------------------------------------------------
json_data_dict = {}

# ----------------------------------------------------------
# 関数定義部
# ----------------------------------------------------------
# オプションの構成
def get_option():
    argparser = ArgumentParser()
    argparser.add_argument('file', help=MSG_GET_OPTIONS_HELP)
    return argparser.parse_args()


#---------------------------------------------
# json function
#---------------------------------------------
# json read to dict
def read_json_entry(p_input_file_name):

    # jsonファイルを開く
    json_file_path = os.path.join(dir_path, p_input_file_name)
    json_open = open(json_file_path, 'r', encoding="utf-8")
    p_json_data_dict = json.load(json_open)

    return p_json_data_dict

# Read dict(from json) 
def read_json_dict_entry(p_json_data_dict:dict, p_dict_entry_name:str):
    p_entry_data = p_json_data_dict.get(p_dict_entry_name, "")
    
    return p_entry_data

# Add dict entry
def add_dict_entry(p_json_data_dict:dict, p_dict_entry_name, p_add_entry_data):

    p_json_data_dict[p_dict_entry_name] = p_add_entry_data

    return p_json_data_dict

# dict dump to json
def dump_dict_to_json(p_json_data_dict:dict):

    p_json_data = json.dumps(p_json_data_dict, ensure_ascii=False, indent=4)

    return p_json_data


# システム情報の取得
# Rassbery PiとJetson以外のLinuxで実行された場合に実行環境を取得するための処理
def get_system_data():
    lshw_cmd = ['sudo', 'lshw', '-json']
    proc = subprocess.Popen(lshw_cmd, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
    return proc.communicate()[0]

# Rassbery PiとJetson以外のLinuxで実行された場合に実行環境を読み込むための処理
def read_data(proc_output, class_='system'):
    proc_result = []
    proc_json = json.loads(proc_output)
    for entry in proc_json:
        proc_result.append(entry.get('product', ''))
    return proc_result

# 外部コマンドの実行処理用の関数　Function for executing external commands.
def call_subprocess_run(cmd):
    try:
        res = subprocess.run(cmd, 
                            shell=True, 
                            check=False,
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            universal_newlines=True
                            )
        for line in res.stdout.splitlines():
            yield line
    except subprocess.CalledProcessError:
        logger.error('Failed to execute the external command.[' + cmd + ']', file = sys.stderr)
        sys.exit(1)

def create_aes(password, iv):
    sha = SHA256.new()
    sha.update(password.encode())
    key = sha.digest()
    return AES.new(key, AES.MODE_CFB, iv)

def encrypt(decrypted_data, password):
    iv = Random.new().read(AES.block_size)
    return iv + create_aes(password, iv).encrypt(decrypted_data)

def decrypt(encrypted_data, password):
    iv, cipher = encrypted_data[:AES.block_size], encrypted_data[AES.block_size:]
    return create_aes(password, iv).decrypt(cipher)


# 外部ファイルの更新処理用の関数（先頭行追加）　Function for updating external files.
def update_file(p_file_d, p_json_data, p_dir_path):
    try:
        #指定されたファイルパスを元に更新元ファイルをバックアップ
        mk_dir_name = os.path.join(p_dir_path,'encrypt_bk')
        p_bk_file_namepath = os.path.join(mk_dir_name, p_file_d)
        # --ログ出力用ライブラリの所在確認と作成
        if not os.path.isdir(mk_dir_name):
          os.makedirs(mk_dir_name, exist_ok = True)
          shutil.copy2(p_file_d, p_bk_file_namepath)

        logger.info('---- Update file ----')
        with open(p_file_d, "w") as fs:
            for line in p_json_data:
                fs.write(line)
        logger.info('---- Success update file ----')
        return 0
    except OSError as e:
        logger.error(e)
        return 1

# ----------------------------------------------------------
# 事前処理部（環境確認と実行パス、オプションの取得）
# ----------------------------------------------------------
# ロギングの設定（ログファイルに出力する）
# --ログ出力用ライブラリの所在確認と作成
if not os.path.isdir('./Log'):
    os.makedirs('./Log', exist_ok = True)

# --ファイル出力用ハンドラ
file_handler = FileHandler(
    f"./Log/log{datetime.now():%Y%m%d%H%M%S}_crypt.log"
)
file_handler.setLevel(DEBUG)
file_handler.setFormatter(
    Formatter("%(asctime)s@ %(name)s [%(levelname)s] %(funcName)s: %(message)s")
)

# --ルートロガーの設定
logging.basicConfig(level=NOTSET, handlers=[file_handler])

logger = logging.getLogger(__name__)

# 実行環境の取得　Get the execution environment
# 動作カレントパス取得　Get operation current path
# 実行方法（実行形式ファイル、または.pyファイル）によりカレントパスの取得方法が違うため処理を分ける
if getattr(sys, 'frozen', False):
    os_current_path = os.path.dirname(os.path.abspath(sys.executable))
else:
    os_current_path = os.path.dirname(os.path.abspath(__file__))
dir_path = os_current_path

# システム環境の判別 Determining the system environment.
system_label = ''
os_name = platform.system()
logger.info('The operating system is [' + os_name + ']')
if os_name == 'Linux':
    if os.path.exists('/proc/device-tree/model'):
        res = call_subprocess_run('cat /proc/device-tree/model')
        os_info = res.__next__()
        if 'Raspberry Pi' in os_info:
            system_label = 'raspi'
            logger.info('The model name is [' + os_info + ']')
        elif 'NVIDIA Jetson' in os_info:
            system_label = 'jetson'
            logger.info('The model name is [' + os_info + ']　This environment is not supported. Exit the tool.')
        else:
            system_label = 'other'
            logger.error('The model name is [' + os_info + ']　This environment is not supported. Exit the tool.')
            sys.exit()
    else:
        for product in read_data(get_system_data()):
            os_info = product
        logger.error('The model name is [' + os_info + ']　This environment is not supported. Exit the tool.')
        sys.exit()
        
# コマンドで指定されたインストール定義ファイル名の確認
args = get_option()
input_file_name = args.file
p_filename, p_ext = os.path.splitext(input_file_name)

if p_ext == '.json':
    logger.info('Input file is [' + input_file_name + '] I checked the configuration file. The process will start.')
else:
    logger.error('Input file is [' + input_file_name + '] The extension of the specified file is different. Please specify a .json format file.')   
    sys.exit() 

# ---------------------------------------------------------------
# execute
# ---------------------------------------------------------------
if __name__=='__main__':

    # jsonファイル内の設定情報読み込み
    json_data_dict = read_json_entry(input_file_name)

    p_user_passphrese =  read_json_dict_entry(json_data_dict, 'user_passphrase')

    enc_res = encrypt(p_user_passphrese, PASS_PHRASE)
    enc_res_base64 = base64.b64encode(enc_res)
    data_encode_str = enc_res_base64.decode('utf-8')

    add_entry_str = "user_passphrase_enc"

    json_data_dict = add_dict_entry(json_data_dict, add_entry_str, data_encode_str)
    del json_data_dict['user_passphrase']

    json_file = dump_dict_to_json(json_data_dict)

    update_file(input_file_name, json_file, dir_path)

    logger.info("Crypt Tool Exit")


