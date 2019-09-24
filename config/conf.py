#!/usr/bin/python
# -*- coding:utf-8 -*-

#本机IP地址
WAF_IP = "192.168.159.139"

#WEB服务器ip及端口
WEB_IP = ""
WEB_PORT = 80

#URI白名单选项  True为开启  False为关闭 
WHITE_URI_SWITCH = False

#URI白名单  只允许访问白名单中的URI
WHITE_URI_LIST = [
    "/tools.php",
]

#URI黑名单  不允许访问的URI
BLACK_URI_LIST = [
    "",
]

#IP白名单选项  True为开启  False为关闭
WHITE_IP_SWITCH = False

#IP白名单  检测出攻击仍允许访问
WHITE_IP_LIST = [
    "",
]

#IP黑名单  不允许该IP访问
BLACK_IP_LIST = [
    "",
]

