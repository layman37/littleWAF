# !/usr/bin/env python
# -*- coding:utf-8 -*-

import re
import acl


class Detect:
    """
    检测web攻击行为
    user-agent, cookies, uri, body
    匹配特征
    """

    def __init__(self, http_data):
        self.uri = http_data.uri
        user_agent_data = http_data.headers.get("user-agent", False)
        if user_agent_data:
            self.user_agent = http_data.headers["user-agent"]
        else:
            self.user_agent = "None"
        if http_data.headers.get("cookie"):
            self.cookie = http_data.headers["cookie"]
        else:
            self.cookie = False
        if http_data.body:
            self.body = http_data.body
        else:
            self.body = False

    def run(self):

        for rule in acl.url_list:
            result = re.compile(rule).findall(self.uri)
            if result:
                return {"status":True, "type":'uri'}      

        for rule in acl.args:
            result = re.compile(rule).findall(self.uri)
            if result:
                return {"status": True, "type":'arg'}

        for rule in acl.useragent:
            result = re.compile(rule).findall(self.user_agent)
            if result:
                return {"status": True, "type":'user-agent'}

        if self.cookie:
            for rule in acl.cookie_acl:
                try:
                    result = re.compile(rule).findall(self.cookie)
                    if result:
                        return {"status": True, "type":'cookie'}
                except Exception, e:
                    result = re.compile(rule).findall(','.join(self.cookie))
                    if result:
                        return {"status": True, "type":'cookie'}
                        
        if self.body:
            for rule in acl.post_acl:
                result = re.compile(rule).findall(self.body)
                if result:
                    return {"status": True, "type":'post-data'}

        return {"status": False}

