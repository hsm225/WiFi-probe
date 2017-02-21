#!/usr/bin/env python
# -*- coding:utf-8 -*-
__author__ = 'Administrator'

import socket, threading, os, time, sqlite3, MySQLdb

class WifiProbeParse(object):
    def __init__(self):
        '初始化实例，先把数据库连好'
        self.conn = MySQLdb.connect(host='127.0.0.1', port=3306, user='root', passwd='test', db='HQ65_20')
        self.curs = self.conn.cursor()
        try:
            self.curs.execute('''
            CREATE TABLE wifi_probe(
            gateway_id VARCHAR(20),
            wlan_mac CHAR(12),
            lan_mac CHAR(12),
            device_type INT(10),
            msg_version INT(10),
            server_id VARCHAR(20),
            mobile_mac CHAR(12),
            signal_len INT(10),
            synch_flag INT(10),
            sniffer_time DATETIME,
            add_time DATETIME,
            mac_flag INT(10));
            ''')
        except Exception, e:
            print e
            pass
        self.query = "INSERT INTO wifi_probe VALUES ('%s','%s','%s', %d, %d,'%s','%s', %d, %d,'%s','%s', %d)"

    def toHex(self, s):
        '将收集到的字符串转为十六进制'
        lst = []
        for ch in s:
            hv = hex(ord(ch)).replace('0x', '')
            if len(hv) == 1:
                # ascii对应的十六进制都是两位，即使十位数是0,也不能不写，比如0x01,0x02...
                hv = '0' + hv
            lst.append(hv)
        # reduce函数，对列表的前两个数执行func函数，然后将得到的这个数与第三个数执行func函数，以此类推，最后只有一个数。
        return reduce(lambda x,y:x+y, lst)

    def decode_to_hex(self, data_string):
        # 在linux系统当中，如果要执行一条命令然后得到结果，可以使用os.popen()
        # 这个函数，主要用于将加密的探针数据，进行解密。
        process = os.popen('decode %s' % data_string)
        string_after_trans = process.read()
        process.close()
        return string_after_trans

    def hex_transfer_to_str_and_save_db(self, data_string):
        '将decode转码的十六进制代码进行解析，转成真实的数据并存入数据库'
        info_List = data_string[16:].split('7C', 5)
        #下面的几个参数，是路由器相关的信息，这里没有存入数据库；如果想存数据库的话，可以手动修改数据表的格式。
        info_List_len = len(info_List)
        domain = info_List[0].decode('hex')
        gw_id = info_List[1].decode('hex')
        lan_mac = info_List[2]
        wlan_mac = info_List[3]
        device_type = 0
        msg_version = 1
        server_id = '127.0.0.1'
        synch_flag = 0
        # 将ascii编码转为16进制
        mac_num = info_List[4].decode('hex')
        mac_info = []
        i = 0
        while i < len(info_List[5]):
            mac_info.append(info_List[5][i:i+46])
            i += 48
        mac_info_print = []
        # 信息解析在这里，如果要进行顾虑的话，就在这里进行。
        for j in range(len(mac_info)):
            if len(mac_info[j]) == 46:
                try:
                    mac_info_list = mac_info[j][14:].split('3A')
                    # print mac_info_list
                    # print gw_id
                    # print wlan_mac
                    # print lan_mac
                    # print device_type
                    # print msg_version
                    # print server_id
                    # print mac_info[j][0:12]
                    # print int(mac_info_list[0].decode('hex'))
                    # print synch_flag
                    # print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(mac_info_list[1].decode('hex'))))
                    # print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    # print int(mac_info_list[2])
                    self.curs.execute(self.query % (gw_id, wlan_mac, lan_mac, device_type, msg_version, server_id, mac_info[j][0:12], int(mac_info_list[0].decode('hex')), synch_flag, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(mac_info_list[1].decode('hex')))), time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), int(mac_info_list[2])))
                except Exception, e:
                    print e
        self.conn.commit()

    def close_db(self):
        '关闭数据库'
        self.conn.close()

    def main(self, data):
        #第一步，通过socket收到的数据是乱码数据，所以要先转为十六进制的字符串
        recv_data = self.toHex(data)
        print recv_data
        #第二步，将十六进制进行转码，得到解码之后的数据（解密后的数据中是ASCII码对应的十进制）
        decode_data = self.decode_to_hex(recv_data)
        print decode_data
        #第三步，将解码之后的数据进行分析，然后存入数据库
        self.hex_transfer_to_str_and_save_db(decode_data)

if __name__ == '__main__':
    #先侦听192.168.11.x:6789，udp服务器
    HOST = raw_input(u"请输入服务器IP>>>")
    PORT = input(u"请输入服务器端口>>>")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, PORT))
    print u"UDP server正在侦听，%s:%d" % (HOST, PORT)

    wifiprobeparse = WifiProbeParse()
    while True:
        try:
            data, addr = s.recvfrom(1024)
            print u"收到wifi探针包..."
            try:
                wifiprobeparse.main(data)
                print u"解码成功"
                print time.time()
            except Exception, e:
                print e
                print u"解码失败"
        except Exception:
            time.sleep(1)
            pass

    wifiprobeparse.close_db()
    s.close()