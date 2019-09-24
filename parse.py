#!/usr/bin/env python
# -*- coding:utf-8 -*-

class Request():
    """解析http请求"""

    method = None
    uri = None
    version = None
    body = ''
    headers = dict()
    __methods = dict.fromkeys((
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
    )) 
    __proto = 'HTTP'  

    def __init__(self,buf):
        self.parse(buf)

    def parse(self,buf):
        buf.decode("ascii","ignore")
        b = buf.strip().split("\r\n",1)
        line = b[0]
        head = b[1]

        # 解析请求行
        line=line.strip().split()
        if len(line) < 2:
            raise Exception,"invalid request"
        if line[0] not in self.__methods:
            raise Exception,"invalid request"
        if len(line) == 2:
            self.version = '0.9'
        else:
            if not line[2].startswith(self.__proto):
                raise Exception,"invalid request"
            self.version = line[2][len(self.__proto)+1:]
        self.method = line[0]
        self.uri = line[1]  

        # 解析请求头及post内容
        head = head.strip().split("\r\n")
        if self.method.lower() == 'post':
            self.body=head[-1:]
            head=head[:-1]
        for hrd in head:
            if not hrd:
                break
            h = hrd.split(':',1)
            if len(h[0].split()) != 1:
                raise Exception,"invalid request"
            a = h[0].lower()
            b = len(h) !=1 and h[1].lstrip() or ''
            if a in self.headers:
                #if not type(self.headers[a]) is list:
                    #self.headers[a] = [self.headers[a]]
                #self.headers[a].append(b)
                pass
            else:
                self.headers[a] = b
