# coding: utf8
# author: AIpha

import requests
import hmac
import hashlib
import execjs
from urllib.parse import urlencode
import time
import re
from PIL import Image
import matplotlib.pyplot as plt
import base64
import json
import copy
from hyper.contrib import HTTP20Adapter
from lxml import etree
import pymongo



class ZhihuSpider():
    def __init__(self, username, password):
        self.login_url = "https://www.zhihu.com/signin"
        self.login_check = "https://www.zhihu.com/api/v3/oauth/sign_in"
        self.login_data = {
            "client_id": "c3cef7c66a1843f8b3a9e6a1e3160e20",
            "grant_type": "password",
            "timestamp": "",
            "source": "com.zhihu.web",
            "signature": "",
            "username": username,
            "password": password,
            "captcha": "",
            "lang": "cn",
            "utm_source": "",
            "ref_source": "other_https://www.zhihu.com/signin",
        }
        self.headers = {
            "Host": "www.zhihu.com",
            "Connection": "keep-alive",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
            "Accept": "*/*",
            "Referer": "https://www.zhihu.com/signin",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "zh-CN,zh;q=0.9",
        }
        self.headers_login = {
            ":authority": "www.zhihu.com",
            ":method": "GET",
            ":path": "/",
            ":scheme": "https",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
            "accept-encoding": "gzip, deflate",
            "accept-language": "zh-CN,zh;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://www.zhihu.com/signin",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36",
        }
        self.conn = pymongo.MongoClient("localhost")
        self.mydb = self.conn["zhihu_artcile"]

    def login(self, captcha_lang="en"):
        '''
        登陆
        :param captcha_lang: 验证码类型
        :return:
        '''
        xsrf = self._get_xsrf()
        timestamp = str(int(time.time() * 1000))
        self.login_data['signature'] = self._get_signature(timestamp)
        self.login_data['timestamp'] = timestamp
        self.login_data['captcha'] = self._get_captcha(captcha_lang, self.headers)[0]
        self.headers['x-xsrftoken'] = xsrf.strip()
        self.headers['x-zse-83'] = '3_2.0'
        self.headers['content-type'] = 'application/x-www-form-urlencoded'
        print(execjs.get().name)
        with open('zhihu.js', 'r', errors='ignore') as f:
            js_code = f.read()
        exejs = execjs.compile(js_code)
        encrypt_js = exejs.call('b', urlencode(self.login_data))
        print(encrypt_js)
        print(self.headers)
        response = requests.post(self.login_check, headers=self.headers, data=encrypt_js)
        print(response.text)
        if 'error' in response.text:
            print(json.loads(response.text)['error']['message'])
        if response.status_code in [200,201,202]:
            print('登录成功')
            cookies = response.headers['Set-Cookie'].split(';')
            res_cookie = []
            set_cookie = []
            for cookie in cookies:
                set_cookie.append(cookie.split(','))
            for sets in set_cookie:
                # _zap、 tgw_l7_route参数备用
                for set in sets:
                    if 'z_c0' in set:
                        res_cookie.append(set)
                    else:
                        continue
            self.headers_login['Cookie'] = self.headers['Cookie']+";"+res_cookie[0]
            # zhihu_http2 = HTTP20Connection(self.login_url)
            req_http2 = requests.Session()
            req_http2.mount(self.login_url, HTTP20Adapter())
            res_login = req_http2.get(url=self.login_url, headers=self.headers_login)
            for i in self.zhihu_parse(res_login):
                pass
            return True
        else:
            print('登录失败')
            return False


    def _get_xsrf(self):
        response = requests.head(url=self.login_url, headers=self.headers)
        cookies = response.headers['Set-Cookie'].split(';')
        res_cookie = []
        set_cookie = []
        for cookie in cookies:
            set_cookie.append(cookie.split(','))
        for sets in set_cookie:
            # _zap、 tgw_l7_route参数备用
            for set in sets:
                if '_xsrf' in set or 'tgw_l7_route' in set:
                    res_cookie.append(set)
                else:
                    continue
        print(res_cookie)
        self.headers['Cookie'] = ';'.join(res_cookie).strip()
        return res_cookie[-1]

    def _get_signature(self, timestamp):
        ha = hmac.new(b'd1b964811afb40118a12068ff74a12f4', digestmod=hashlib.sha1)
        grant_type = self.login_data['grant_type']
        client_id = self.login_data['client_id']
        source = self.login_data['source']
        ha.update(bytes((grant_type + client_id + source + timestamp), 'utf-8'))
        return ha.hexdigest()

    def _get_captcha(self, lang, headers):
        """
        请求验证码的 API 接口，无论是否需要验证码都需要请求一次
        如果需要验证码会返回图片的 base64 编码
        根据 lang 参数匹配验证码，需要人工输入
        :param lang: 返回验证码的语言(en/cn)
        :param headers: 带授权信息的请求头部
        :return: 验证码的 POST 参数
        """
        if lang == 'cn':
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=cn'
        else:
            api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'
        resp = requests.get(api, headers=headers)
        show_captcha = re.search(r'true', resp.text)
        capt_headers = copy.deepcopy(headers)
        cookies = resp.headers['Set-Cookie'].split(';')
        res_cookie = []
        set_cookie = []
        for cookie in cookies:
            set_cookie.append(cookie.split(','))
        for sets in set_cookie:
            # _zap、 tgw_l7_route参数备用
            for set in sets:
                if 'capsion_ticket' in set:
                    res_cookie.append(set)
                else:
                    continue
        print(res_cookie)
        capt_headers['Cookie'] = ';'.join(res_cookie).strip()
        self.headers['Cookie'] = self.headers['Cookie']+";"+res_cookie[0]

        if show_captcha:
            put_resp = requests.put(api, headers=capt_headers)
            json_data = json.loads(put_resp.text)
            print(put_resp.text)
            img_base64 = json_data['img_base64'].replace(r'\n', '')
            with open('./captcha.jpg', 'wb') as f:
                f.write(base64.b64decode(img_base64))
            img = Image.open('./captcha.jpg')
            if lang == 'cn':
                plt.imshow(img)
                print('点击所有倒立的汉字，按回车提交')
                points = plt.ginput(7)
                capt = json.dumps({'img_size': [200, 44],
                                   'input_points': [[i[0]/2, i[1]/2] for i in points]})
            else:
                img.show()
                capt = input('请输入图片里的验证码：')
            # 这里必须先把参数 POST 验证码接口
            requests.post(api, data={'input_text': capt}, headers=headers)
            return capt, res_cookie[-1]
        return ''

    def zhihu_parse(self, response):
        '''
        解析知乎首页
        :param response:
        :return:
        '''
        html = etree.HTML(response.text)
        node_list = html.xpath('//div[contains(@class,Card) and contains(@class,TopstoryItem) and contains(@class,TopstoryItem-isRecommend)]//div[contains(@class, "Feed")]')
        for node in node_list:
            item = {}
            item['title'] = node.xpath('normalize-space(.//h2)')
            item['article_url'] = node.xpath('normalize-space(.//h2//a/@href)')
            item['article_short'] = node.xpath('normalize-space(.//div[contains(@class, RichContent-inner)]//span[contains(@class,"RichText") and contains(@class, "CopyrightRichText-richText")])')
            item['article_Agree'] = node.xpath('normalize-space(.//div[contains(@class,"RichContent")]//div[contains(@class, "ContentItem-actions")]//span)').replace('\u200b', "").split(' ')[-1]
            print(item)
            self.mydb['zhihu_test'].insert(item)
            yield


if __name__ == '__main__':
    zhihu = ZhihuSpider(username='13795870040', password="herococo11.")
    if zhihu.login():
        print('登陆成功')
    else:
        print('登陆失败')