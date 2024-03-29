# **IoT_comm_monitor**
## **OverView**
---
 IoT Communication Monitoring Tools ( IoTCMT ) for Raspberry Pi </br>
 Create 2021.06</br>
 Author  : GENROKU@Karakuri-musha</br>
 License : See the license file for the license.</br>
 Python ver : Python 3.7.3</br>
 Hardware : Raspberry Pi 4 Model B

 このツールは、Raspberry Pi でWi-Fi接続を行う場合に設定したデフォルトルートへの通信状態をping監視し、状態変化があった場合に通知と修復処理を行うプログラムです。ツールの動作設定は、IoTCNTconfig.json（json形式）にて定義できます。
 復旧処理としては「rfkill」のブロック解除と「dhcpcd」のリスタートを行います。  

This tool is a program that pings the communication status to the default route set when making a Wi-Fi connection with Raspberry Pi, and notifies and repairs when there is a status change. Tool operation settings can be defined in IoTCNTconfig.json (json format).
 The recovery process is to unblock "rfkill" and restart "dhcpcd".

## **Tool file structure**
---
ツールのファイル構成は次の通りです。
</br>

|ファイル名  |形式  |説明  |
|---------|---------|---------|
|IoT_comm_monitor.py|Python3(.py)| IoTCMT 本体です。このツールを定期実行するようにcronで設定してください。</br>This is the main body of the monitoring tool. Set cron to run this tool on a regular basis.|
|IoT_pass_crypt.py|Python3(.py)| IoTCMT 内で使う管理者パスワードの暗号化ツールです。</br>An administrator password encryption tool used within IoTCMT|
|IoTCNTconfig.json|json(.json)|IoTCMT の動作設定用ファイルです。</br>This is a file for setting the operation of IoTCMT.|

## **Operation setting (entry in json file)**
---
動作設定ファイル（IoTCNTconfig.json）は次のような構成になっています。

[IoTCNTconfig.json]</br>
`{
    "default_route_addr": "192.168.1.1",
    "ping_retry_save_cnt": "8",
    "ping_retry_max_cnt": "10",
    "auto_recovery": "True",
    "comm_retry_intarval": "30",
    "comm_retry_cnt": "2",
    "comm_recovery_err_cmd": "sudo rfkill unblock 0",
    "log_save_count": "10",
    "user_passphrase": ""
}`

|item|default|Description|
|---------|---------|---------|
|default_route_addr| *192.168.1.1* | 監視する通信先（デフォルトゲートウェイ）をIPアドレスで指定</br> Specify the communication destination (default gateway) to be monitored by IP address.       |
|ping_retry_save_cnt| *8*       | 通信断と判定するリトライ失敗数</br> The number of retry failures determined to be communication interruption.       |
|ping_retry_max_cnt| *10*       | 通信断を判定するためのリトライ回数</br>Number of retries to determine communication interruption       |
|auto_recovery|  *True*         | 通信断時に自動復旧を行うか</br>Whether to perform automatic recovery when communication is interrupted        |
|comm_retry_intarval| *30*      | 自動復旧時に「rfkill」と「dhcpcd」の状態変更を確認する間隔（秒）  </br>Interval (seconds) to check the status change of "rfkill" and "dhcpcd" during automatic recovery      |
|comm_retry_cnt| *2*            | 自動復旧時に「rfkill」と「dhcpcd」の状態変更を確認する回数  </br>Number of times to check the status change of "rfkill" and "dhcpcd" during automatic recovery     |
|comm_recovery_err_cmd| *NULL*  | 自動復旧処理が失敗した場合に実行するコマンド(NULLでも動作可能)  </br>Command to be executed when the automatic recovery process fails (can operate even with NULL)      |
|log_save_count| *10*  | ツール実行結果ログの保存数  </br>Number of saved tool execution result logs   |
|user_passphrase| *NULL*        | 暗号化ツールで暗号化する管理者パスワード （初期設定時にのみ記入）</br>Administrator password to be encrypted with encryption tool (Enter only at the time of initial setting)       |
|user_passphrase_enc| *NULL*    | 暗号化ツールで暗号化した管理者パスワード </br>Administrator password encrypted with encryption tool       |

## **How to Log management**
---
本ツール実行時には、ツール格納先フォルダ配下に「Log」ディレクトリが作成され、本ツール実行時のログが格納されます。</br>
ログはツールの実行毎に出力されるため、動作設定ファイル内でログの最大保存数を設定することを推奨します。</br>
ツール実行時に最大補完数と同数のログがある場合に更新日付の古いモノから削除されます。

When this tool is executed, a "Log" directory is created under the tool storage folder, and the log when this tool is executed is stored. </br>
Since the log is output each time the tool is executed, it is recommended to set the maximum number of logs to be saved in the operation setting file. </br>
If there are as many logs as the maximum number of completions when the tool is executed, the ones with the oldest update date will be deleted.

## **How to use**
---
本ツールは次の手順で実行してください。

１．ツール配置用のディレクトリをRaspberry Pi OS上に作成します。</br>
```
sudo mkdir /opt/IoTCMT
```

２．作成したディレクトリにツールをコピーします。</br>

```
cd /opt/IoTCMT
sudo git clone https://github.com/karakuri-musha/iot_comm_mon.git
```
３．ダウンロード先にある環境設定ファイル「IoTCNTconfig.json」を編集します。</br>
「user_passphrase」に、sudoコマンドで使用している管理者パスワードを入力します。
```
cd iot_comm_mon
sudo vi IoTCNTconfig.json
```
４．「IoT_pass_crypt.py」を実行して、「IoTCNTconfig.json」に記載したパスワードを暗号化します。
```
sudo python3 IoT_pass_crypt.py IoTCNTconfig.json
```
５．「IoTCNTconfig.json」を確認し、パスワードが暗号化されていることを確認します。</br>
ファイルは保存せずに終了します。暗号化前のファイルは「encrypt_bk」に保存されていますので必要に応じて削除してください。
```
vi IoTCNTconfig.json
```
７．「IoT_comm_monitor.py」を実行するシェルを記載します。
```
sudo vi /usr/local/bin/comm_mon.sh
```
シェルの内容
```
#!/bin/sh
sudo python3 /opt/IoTCMT/iot_comm_mon/IoT_comm_monitor.py /opt/IoTCMT/iot_comm_mon/IoTCNTconfig.json
```
８．シェルに実行権限を付与します。
```
sudo chmod +x /usr/local/bin/comm_mon.sh
```
９．「crontab」を編集して先ほどのシェルを実行するスケジュールを追加します。</br>
9-1 環境変数を確認し、パスを保存しておきます。
```
echo $PATH
```
9-2 「crontab」をエディタモードで開いてスケジュールを追加します。</br>
先ほど確認したパスも合わせて記述します。
```
sudo crontab -e
```
ファイルの最後に以下のスケジュールを記述し、保存します。（例は5分間隔で実行する）</br>
```
LANG=ja_JP.UTF-8
PATH="先ほど確認したパスを記入します"
*/5 * * * * /usr/local/bin/comm_mon.sh
```
10．「cron」を再起動します。
```
sudo /etc/init.d/cron restart
```
11．スケジュールで起動された後、ツールのディレクトリに「Log」ディレクトリが作成されます。
フォルダ内に実行時のログが保存されることを確認してください。</br>
【ログ内容：例】
```
2021-07-16 11:55:03,311@ __main__ [INFO] <module>: Input file is [/opt/IoTCMT/iot_comm_mon/IoTCNTconfig.json] I checked the configuration file. The process will start.
2021-07-16 11:55:03,345@ __main__ [INFO] <module>: The operating system is [Linux]
2021-07-16 11:55:03,378@ __main__ [INFO] <module>: The model name is [Raspberry Pi Zero W Rev 1.1]
2021-07-16 11:55:03,379@ __main__ [INFO] <module>: The automatic recovery function is [ enabled ].
2021-07-16 11:55:03,381@ __main__ [INFO] <module>: The network monitoring tool is running.
2021-07-16 11:55:03,560@ __main__ [INFO] <module>: Default rtoute ping result [ 192.168.1.1: OK ]
2021-07-16 11:55:03,562@ __main__ [INFO] <module>: Exit the network monitoring tool.
```

