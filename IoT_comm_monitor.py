#!/usr/bin/python3
#-----------------------------------------------------------------------------
#   IoT Communication Monitoring Tools ( IoTCMT )     Create 2021.06
#   for Raspberry Pi 
#   このツールは、Raspberry Pi でWi-Fi接続を行う場合にネットワークの通信状態を
#   監視し、状態変化があった場合に通知と修復処理を行うプログラムです。  
#   ツールの動作設定は、IoTCNTconfig.json（json形式）にて定義できます。  
#   
#   Author  : GENROKU@Karakuri-musha
#   License : See the license file for the license.
#-----------------------------------------------------------------------------
import os
from posixpath import dirname
import sys
import time
import platform
import subprocess
import struct
import json
import base64
from argparse import ArgumentParser
from datetime import datetime
import logging
from logging import FileHandler, Formatter
from logging import INFO, DEBUG, NOTSET
from typing import List
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# ----------------------------------------------------------
# 定数定義部
# ----------------------------------------------------------
MSG_GET_OPTIONS_HELP         = "Specify the installation target definition file (json format). "

MSG_TOOL_E                   = "The network monitoring tool is running."
MSG_TOOL_D                   = "Exit the network monitoring tool."

MSG_ANOMALY_DETECTION_PING_F = "There is an error in communication to the default route. Retry and check."
MSG_ANOMALY_DETECTION_PING_R = "As a result of retrying communication confirmation, it was determined that communication was interrupted."
MSG_ANOMALY_DETECTION_TXT    = "[ NETWORK DOWN NOW ] PLEASE CONFIRM IT. (E001-01)"

# ネットワーク自動復旧関連メッセージ
MSG_AUTO_RECOVERY_E          = "The automatic recovery function is [ enabled ]."
MSG_AUTO_RECOVERY_D          = "The automatic recovery function is [ disabled ]."
MSG_NW_DEVICE_CHECK_RF_E     = "Wi-Fi function is enabled."
MSG_NW_DEVICE_CHECK_RF_D     = "Wi-Fi function is disabled. (E001-02)"
MSG_NW_DEVICE_CHECK_SV_E     = "Network service (dhcpcd) is enabled."
MSG_NW_DEVICE_CHECK_SV_D     = "There is a problem with the network service (dhcpcd). (E001-03)"

MSG_AUTO_RECOVERY_RF_E       = "The Wi-Fi function has been restored."
MSG_AUTO_RECOVERY_RF_D       = "An error occurred while recovering the Wi-Fi function (E001-05)"
MSG_AUTO_RECOVERY_SV_E       = "The network service has been restarted."
MSG_AUTO_RECOVERY_SV_D       = "An error occurred while restarting the network service. (E001-06)"
MSG_AUTO_RECOVERY_CMD_E      = "Since the network cannot be automatically restored, an alternative process will be performed. (E001-07)"

PASS_PHRASE                  = "f5FsQ,~c(uvf"

DHCPCD_CMDLIST               = ["sudo", "systemctl","restart", "dhcpcd"]

#RFKILL unblock 
_PY3_ = sys.version_info.major == 3
DPATH                        = "/dev/rfkill"
RFKILL_IDX                   = 0
RFKILL_HARD                  = 0
RFKILL_SOFT                  = 0
RFKILL_TYPE_WLAN             = 1
RFKILL_OP_CHANGE             = 2
RFKILL_EVENT                 ='IBBBB'
RFKILL_EVENTLEN              = struct.calcsize(RFKILL_EVENT)

# ----------------------------------------------------------
# 変数定義部
# ----------------------------------------------------------
# 監視間隔と異常検知条件
# 監視間隔を元にdefault routeへのping確認を行い、通信断閾値を超えた場合は異常検知状態へ遷移する
d_ping_retry_save_cnt = 8       # default routeへのping通信断閾値（異常回数：初期値8/10回で異常検知）
d_ping_retry_max_cnt = 10       # default routeへのping通信断閾値（確認回数：初期値10回）


# 異常検知後の動作
# --[復旧]自動復旧の条件
# ---サービス復旧：異常検知後、リトライ間隔×リトライ回数を行い、異常状態に変化がない場合に自動復旧処理を行う（自動復旧有効時）
d_auto_recovery = False         # 異常検知時に復旧動作を行うかのフラグ
d_comm_retry_intarval = 5       # 状態確認のリトライ間隔（秒）
d_comm_retry_cnt = 2            # 状態確認のリトライ回数（回）
d_comm_recovery_err_cmd = ""    # 自動復旧処理を行っても改善しない場合に実行するコマンド


# ----------------------------------------------------------
# 関数定義部
# ----------------------------------------------------------
# オプションの構成
def get_option():
    argparser = ArgumentParser()
    argparser.add_argument('file', help=MSG_GET_OPTIONS_HELP)
    return argparser.parse_args()

# システム情報の取得
# Rassbery PiとJetson以外のLinuxで実行された場合に実行環境を取得するための処理
def get_system_data(p_passphrase):
    lshw_cmd = ['sudo', 'lshw', '-json']
    proc = subprocess.Popen(lshw_cmd, 
                            stdin=p_passphrase + '/n',
                            stdout=subprocess.PIPE,
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

# 外部コマンドの実行処理用の関数　Function for executing external commands.
def call_subprocess_run_sudo(cmd, p_passphrase):
    try:
        res = subprocess.run(cmd, 
                            shell=True, 
                            check=True,
                            stdin=p_passphrase + '\n',
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            universal_newlines=True
                            )
        for line in res.stdout.splitlines():
            yield line
    except subprocess.CalledProcessError:
        logger.error('Failed to execute the external command.[' + cmd + ']', file = sys.stderr)
        sys.exit(1)


# 外部コマンドの実行処理用の関数　Function for executing external commands.
def call_subprocess_run_sudo_list(p_cmdlist, p_passphrase):
    print('start')
    try:
        res = subprocess.run(p_cmdlist, 
                            shell=True,
                            check=True,
                            stdin=p_passphrase + '\n',
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            universal_newlines=True
                            )
        for line in res.stdout.splitlines():
            yield line
    except subprocess.CalledProcessError:
        logger.error('Failed to execute the external command.[' + cmd + ']', file = sys.stderr)
        sys.exit(1)

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

def read_parameters(p_input_file_name):

    # jsonファイルを開く
    json_data_dict = read_json_entry(p_input_file_name)

    r_defaunlt_route_addr   = read_json_dict_entry(json_data_dict,'default_route_addr')
    r_ping_retry_save_cnt   = read_json_dict_entry(json_data_dict,'ping_retry_save_cnt')
    r_ping_retry_max_cnt    = read_json_dict_entry(json_data_dict,'ping_retry_max_cnt')
    r_auto_recovery         = read_json_dict_entry(json_data_dict,'auto_recovery')
    r_comm_retry_intarval   = read_json_dict_entry(json_data_dict,'comm_retry_intarval')
    r_comm_retry_cnt        = read_json_dict_entry(json_data_dict,'comm_retry_cnt')
    r_comm_recovery_err_cmd = read_json_dict_entry(json_data_dict,'comm_recovery_err_cmd')
    r_log_save_count        = read_json_dict_entry(json_data_dict,'log_save_count')
    r_passphrase            = read_json_dict_entry(json_data_dict,'user_passphrase_enc')

    return r_defaunlt_route_addr,r_ping_retry_save_cnt,r_ping_retry_max_cnt,r_auto_recovery, r_comm_retry_intarval, r_comm_retry_cnt,r_comm_recovery_err_cmd, r_log_save_count, r_passphrase

#def read_dhcpcd_entry():
#
#    # Wi-Fiに設定されているIPアドレスを取得する
#    i_ip_addr = call_subprocess_run('ip -f inet -o addr show wlan0 | awk \'{print$4}\' | cut -d \'/\' -f 1')
#    # Wi-Fiに設定されているデフォルトルートを取得する
#    i_defroute = call_subprocess_run('ip route | grep default | awk \'{print$3}\'')
#    
#    # Wi-Fiに設定されているサブネットマスクを取得する
#    i_mask = call_subprocess_run('ifconfig wlan0 | grep inet | awk NR==1\'{print$4}\'')
#
#    return next(i_ip_addr), next(i_defroute), next(i_mask)

def create_aes(password, iv):
    sha = SHA256.new()
    sha.update(password.encode())
    key = sha.digest()
    return AES.new(key, AES.MODE_CFB, iv)

def decrypt(encrypted_data, password):
    iv, cipher = encrypted_data[:AES.block_size], encrypted_data[AES.block_size:]
    return create_aes(password, iv).decrypt(cipher)

# rfkill unblock function
def rfkill_unblock(rfkill_idx = RFKILL_IDX):

    rfke = struct.pack(RFKILL_EVENT,RFKILL_IDX,RFKILL_TYPE_WLAN,RFKILL_OP_CHANGE,RFKILL_HARD,RFKILL_SOFT)

    if _PY3_: rfke = rfke.decode('ascii')
    
    file_out= open(DPATH, 'w')
    file_out.write(rfke)
    file_out.close()

# ----------------------------------------------------------
# メイン処理部
# ----------------------------------------------------------
if __name__=="__main__":

    # ----------------------------------------------------------
    # Get Current path process
    # ----------------------------------------------------------
    # 実行環境の取得　Get the execution environment
    # 動作カレントパス取得　Get operation current path
    # 実行方法（実行形式ファイル、または.pyファイル）によりカレントパスの取得方法が違うため処理を分ける
    if getattr(sys, 'frozen', False):
        os_current_path = os.path.dirname(os.path.abspath(sys.executable))
    else:
        os_current_path = os.path.dirname(os.path.abspath(__file__))
    dir_path = os_current_path

    # ----------------------------------------------------------
    # Set Logger process
    # ----------------------------------------------------------
    # ロギングの設定（ログファイルに出力する）
    # --ログ出力用ライブラリの所在確認と作成
    log_path = os.path.join(dir_path, "Log")
    if not os.path.isdir(log_path):
        os.makedirs(log_path, exist_ok = True)


    # --ファイル出力用ハンドラ
    file_handler = FileHandler(
        f"{log_path}/log{datetime.now():%Y%m%d%H%M%S}.log"
    )
    file_handler.setLevel(DEBUG)
    file_handler.setFormatter(
        Formatter("%(asctime)s@ %(name)s [%(levelname)s] %(funcName)s: %(message)s")
    )

    # --ルートロガーの設定
    logging.basicConfig(level=NOTSET, handlers=[file_handler])

    logger = logging.getLogger(__name__)

    # ---------------------------------------------------------------
    # Read json file 
    # ---------------------------------------------------------------
    # コマンドで指定されたインストール定義ファイル名の確認
    args = get_option()
    input_file_name = args.file
    p_filename, p_ext = os.path.splitext(input_file_name)

    if p_ext == '.json':
        logger.info('Input file is [' + input_file_name + '] I checked the configuration file. The process will start.')
    else:
        logger.error('Input file is [' + input_file_name + '] The extension of the specified file is different. Please specify a .json format file.')   
        sys.exit() 

    # jsonファイル内の設定情報読み込み
    p_defroute,d_ping_retry_save_cnt,d_ping_retry_max_cnt,d_auto_recovery,d_comm_retry_intarval,d_comm_retry_cnt,d_comm_recovery_err_cmd, d_log_save_count, d_passphrase_enc = read_parameters(input_file_name)

    # Older Log File delete 
    files = os.listdir(log_path)  # ディレクトリ内のファイルリストを取得
    if len(files) >= int(d_log_save_count) + 1:
        del_files = len(files)-int(d_log_save_count)
        files.sort()                                    # ファイルリストを昇順に並び替え
        for i in range(del_files):
            del_file_name = os.path.join(log_path, files[i])
            logger.info("delete log file : " + del_file_name)
            os.remove(del_file_name)              # 一番古いファイル名から削除

    # Decode passphrase
    d_passphrase_dec64 = base64.b64decode(d_passphrase_enc.encode('utf-8'))
    d_passphrase_decrypt = decrypt(d_passphrase_dec64, PASS_PHRASE)
    d_passphrase = d_passphrase_decrypt.decode('utf-8')

    # ---------------------------------------------------------------
    # Check System engironment 
    # ---------------------------------------------------------------
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
       
    # ---------------------------------------------------------------
    # Check Parametors  
    # ---------------------------------------------------------------
    # システム環境の判別 Determining the system environment.
    # 各ツール機能の有効化状態をログに出力
    # 自動復旧機能の有効化状態出力
    if bool(d_auto_recovery) == False: 
        logger.info(MSG_AUTO_RECOVERY_D)
    else:
        logger.info(MSG_AUTO_RECOVERY_E)

    # ---------------------------------------------------------------
    # Start Main Process  
    # ---------------------------------------------------------------
    logger.info(MSG_TOOL_E)

    # ネットワーク状態の初期化（正常：0)
    p_status = 0

    # 実行時のネットワーク情報の読み込み
    #p_ipadr, p_defroute, p_mask = read_dhcpcd_entry()

    # pingを1回送信した結果、エラー（1）となった場合に続き9回Pingを実行し8回失敗したら対処処理を行う
    p_unreachable = call_subprocess_run("ping -4 -c 1 " + p_defroute + " | awk NR==2\'{print$4}\' | grep -c \'" + p_defroute + "\'") 
    p_unreachable_int = int(next(p_unreachable))
    if p_unreachable_int == 1:
        logger.info('Default rtoute ping result [ ' + p_defroute + ': OK ]')
    else:
        p_unreachable_cnt = 0
        logger.error('Default rtoute ping result [ ' + p_defroute + ': NG ]')
        logger.error(MSG_ANOMALY_DETECTION_PING_F)
        for i in range(int(d_ping_retry_max_cnt)-1):
            p_unreachable_int = int(next(call_subprocess_run("ping -4 -c 1 " + p_defroute + " | awk NR==2\'{print$4}\' | grep -c \'" + p_defroute + "\'")))
            
            if p_unreachable_int == 0:
                p_unreachable_cnt += 1

            if p_unreachable_cnt == int(d_ping_retry_save_cnt):
                logger.error('Default rtoute ping result Count ' + d_ping_retry_save_cnt +' [ ' + p_defroute + ': NG ]')
                logger.error(MSG_ANOMALY_DETECTION_PING_R)
                logger.error(MSG_ANOMALY_DETECTION_TXT) 
                p_status = 1
    
    # ネットワーク障害と認識された場合の処理
    if p_status ==1 :
        # ネットワークサービスとWi-Fi機能を確認する
        p_rf_status = int(next(call_subprocess_run("rfkill list 0 | grep -c 'Soft blocked: yes'")))

        if p_rf_status == 0:
            logger.info(MSG_NW_DEVICE_CHECK_RF_E)
        else:
            # Wi-Fi機能がブロックされている場合
            logger.error(MSG_NW_DEVICE_CHECK_RF_D)

            # 自動復旧機能が有効な場合
            if bool(d_auto_recovery) == True:
                for i in range(int(d_comm_retry_cnt)):
                    rfkill_unblock()
                    
                    p_rf_status = int(next(call_subprocess_run("rfkill list 0 | grep -c 'Soft blocked: yes'")))
                    if p_rf_status == 0:
                        logger.info(MSG_AUTO_RECOVERY_RF_E)
                        time.sleep(int(d_comm_retry_intarval))
                        break
                    else:
                        logger.error(MSG_AUTO_RECOVERY_RF_D)
                    time.sleep(int(d_comm_retry_intarval))

                if p_rf_status == 1:
                    logger.error(MSG_AUTO_RECOVERY_CMD_E)
                    call_subprocess_run(d_comm_recovery_err_cmd)
                    logger.error(MSG_TOOL_D)
                    sys.exit()

        p_dhcpcd_status = str(next(call_subprocess_run("systemctl status dhcpcd | grep 'Active' | awk '{print$2$3}'")))

        if p_dhcpcd_status == "active(running)":
            logger.info(MSG_NW_DEVICE_CHECK_SV_E)
        else:
            # ネットワークサービスがActiveでない場合
            logger.error(MSG_NW_DEVICE_CHECK_SV_D)

            # 自動復旧機能が有効な場合
            if bool(d_auto_recovery) == True:
                for i in range(int(d_comm_retry_cnt)):
                    call_subprocess_run_sudo_list(DHCPCD_CMDLIST, d_passphrase) 
                    time.sleep(int(d_comm_retry_intarval))

                    p_dhcpcd_status = str(next(call_subprocess_run("systemctl status dhcpcd | grep 'Active' | awk '{print$2$3}'")))
                    if p_dhcpcd_status == "active(running)":
                        logger.info(MSG_AUTO_RECOVERY_SV_E)
                        break
                    else:
                        logger.error(MSG_AUTO_RECOVERY_SV_D)
                    time.sleep(int(d_comm_retry_intarval))

                if not p_dhcpcd_status == "active(running)": 
                    logger.error(MSG_AUTO_RECOVERY_CMD_E)
                    call_subprocess_run(d_comm_recovery_err_cmd) 
                    logger.error(MSG_TOOL_D)
                    sys.exit()

        p_unreachable = call_subprocess_run("ping -4 -c 1 " + p_defroute + " | awk NR==2\'{print$4}\' | grep -c \'" + p_defroute + "\'") 
        p_unreachable_int = int(next(p_unreachable))
        if p_unreachable_int == 1:
            logger.info('Default rtoute ping result [ ' + p_defroute + ': OK ]')
        else:
            p_unreachable_cnt = 0
            logger.error('Default rtoute ping result [ ' + p_defroute + ': NG ]')

    logger.info(MSG_TOOL_D)