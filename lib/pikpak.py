import hashlib
import random
import time
import requests
import json
import imaplib
import email
#赞助链接：https://img.picui.cn/free/2024/06/14/666b4469d3de7.png
import os
#赞助链接：https://img.picui.cn/free/2024/06/14/666b4469d3de7.png

# 滑块数据加密
def r(e, t):
    n = t - 1
    if n < 0:
        n = 0
    r = e[n]
    u = r["row"] // 2 + 1
    c = r["column"] // 2 + 1
    f = r["matrix"][u][c]
    l = t + 1
    if l >= len(e):
        l = t
    d = e[l]
    p = l % d["row"]
    h = l % d["column"]
    g = d["matrix"][p][h]
    y = e[t]
    m = 3 % y["row"]
    v = 7 % y["column"]
    w = y["matrix"][m][v]
    b = i(f) + o(w)
    x = i(w) - o(f)
    return [s(a(i(f), o(f))), s(a(i(g), o(g))), s(a(i(w), o(w))), s(a(b, x))]


def i(e):
    return int(e.split(",")[0])


def o(e):
    return int(e.split(",")[1])


def a(e, t):
    return str(e) + "^⁣^" + str(t)


def s(e):
    t = 0
    n = len(e)
    for r in range(n):
        t = u(31 * t + ord(e[r]))
    return t


def u(e):
    t = -2147483648
    n = 2147483647
    if e > n:
        return t + (e - n) % (n - t + 1) - 1
    if e < t:
        return n - (t - e) % (n - t + 1) + 1
    return e


def c(e, t):
    return s(e + "⁣" + str(t))


def img_jj(e, t, n):
    return {"ca": r(e, t), "f": c(n, t)}


def uuid():
    return ''.join([random.choice('0123456789abcdef') for _ in range(32)])


def md5(input_string):
    return hashlib.md5(input_string.encode()).hexdigest()


def get_sign(xid, t):
    e = [
        {"alg": "md5", "salt": "KHBJ07an7ROXDoK7Db"},
        {"alg": "md5", "salt": "G6n399rSWkl7WcQmw5rpQInurc1DkLmLJqE"},
        {"alg": "md5", "salt": "JZD1A3M4x+jBFN62hkr7VDhkkZxb9g3rWqRZqFAAb"},
        {"alg": "md5", "salt": "fQnw/AmSlbbI91Ik15gpddGgyU7U"},
        {"alg": "md5", "salt": "/Dv9JdPYSj3sHiWjouR95NTQff"},
        {"alg": "md5", "salt": "yGx2zuTjbWENZqecNI+edrQgqmZKP"},
        {"alg": "md5", "salt": "ljrbSzdHLwbqcRn"},
        {"alg": "md5", "salt": "lSHAsqCkGDGxQqqwrVu"},
        {"alg": "md5", "salt": "TsWXI81fD1"},
        {"alg": "md5", "salt": "vk7hBjawK/rOSrSWajtbMk95nfgf3"}
    ]
    md5_hash = f"YvtoWO6GNHiuCl7xundefinedmypikpak.com{xid}{t}"
    for item in e:
        md5_hash += item["salt"]
        md5_hash = md5(md5_hash)
    return md5_hash

def get_mail(xxx):
    mail = xxx + "+" + str(random.randint(1000, 9999)) + str(random.randint(1000, 9999)) + "@outlook.com"
    print(f'获取邮箱:{mail}')
    return mail


# 获取邮箱的验证码内容
def get_code(email_user, email_pass, recipient_email):
    # 连接到邮箱服务器
    mail = imaplib.IMAP4_SSL("outlook.office365.com", 993)
    mail.login(email_user, email_pass)

    # 选择收件箱
    mail.select("inbox")
    while True:
        status, messages = mail.search(None, 'ALL')
        mail_ids = messages[0].split()
        found_code = False
        for mail_id in mail_ids:
            status, msg_data = mail.fetch(mail_id, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])

                    # 检查邮件的收件人
                    recipients = msg.get_all('to', [])
                    recipient_list = email.utils.getaddresses(recipients)
                    if any(recipient_email in r for r in recipient_list):
                        if msg.is_multipart():
                            for part in msg.walk():
                                content_type = part.get_content_type()
                                if content_type == "text/html":
                                    body = part.get_payload(decode=True).decode()
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode()

                        # 提取验证码
                        start_str = "验证码：</p><p><br></p><h2>"
                        end_str = "</h2><p><br></p><p>请及时输入验证码"
                        start_idx = body.find(start_str)
                        if start_idx != -1:
                            start_idx += len(start_str)
                            end_idx = body.find(end_str, start_idx)
                            if end_idx != -1:
                                verification_code = body[start_idx:end_idx]
                                print("获取到的验证码为: " + verification_code)
                                found_code = True
                                mail.store(mail_id, '+FLAGS', '\\Deleted')
                                mail.expunge()
                                mail.logout()
                                return verification_code



# 网络请求函数
def init(xid, mail):
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "POST:/v1/auth/verification",
        "device_id": xid,
        "captcha_token": "",
        "meta": {
            "email": mail
        }
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    if 'url' in response_data:
        print('进行初始安全验证中......')
        return response_data
    else:
        print('邮箱或者IP频繁,请更换IP或者稍后重试...')
        raise Exception(response_data.get('error_description', 'Unknown error'))

def getSize(p):
    sum_rows = p.shape[0]
    sum_cols = p.shape[1]
    channels = p.shape[2]
    return sum_rows, sum_cols, channels
def get_img(deviceid, pid, traceid):
    url = 'https://user.mypikpak.com/pzzl/image?deviceid='+deviceid+'&pid='+pid+'&traceid='+traceid
    response = requests.get(url)
    return response.content

def corp_image(img):
    img2 = img.sum(axis=2)
    (row, col) = img2.shape
    row_top = 0
    raw_down = 0
    col_top = 0
    col_down = 0
    for r in range(0, row):
        if img2.sum(axis=1)[r] < 740 * col:
            row_top = r
            break

    for r in range(row - 1, 0, -1):
        if img2.sum(axis=1)[r] < 740 * col:
            raw_down = r
            break

    for c in range(0, col):
        if img2.sum(axis=0)[c] < 740 * row:
            col_top = c
            break

    for c in range(col - 1, 0, -1):
        if img2.sum(axis=0)[c] < 740 * row:
            col_down = c
            break

    new_img = img[row_top:raw_down + 1, col_top:col_down + 1, 0:3]
    return new_img

def get_image(xid):
    url = "https://user.mypikpak.com/pzzl/gen"
    params = {
        "deviceid": xid,
        "traceid": ""
    }
    response = requests.get(url, params=params)
    json_text = response.text
    imgs_json = response.json()
    frames = imgs_json["frames"]
    pid = imgs_json['pid']
    traceid = imgs_json['traceid']
    result = {"frames": frames}
    #SELECT_ID = pass_verify(xid, pid, traceid, result)
    if 滑块模式 == 1:
        print('当前滑块模式为post')
        SELECT_ID = postid(xid, pid, traceid, json_text)
    else:
        print('当前滑块模式为get')
        SELECT_ID = getid(xid, pid, traceid, json_text)

    print('滑块ID:'+str(SELECT_ID))
    if SELECT_ID == -2:
        print("请更换网络，或者请求参数有误，请重新运行")
    json_data = img_jj(frames, int(SELECT_ID), pid)
    f = json_data['f']
    npac = json_data['ca']
    params = {
        'pid': pid,
        'deviceid': xid,
        'traceid': traceid,
        'f': f,
        'n': npac[0],
        'p': npac[1],
        'a': npac[2],
        'c': npac[3]
    }
    response1 = requests.get(f"https://user.mypikpak.com/pzzl/verify", params=params)
    response_data = response1.json()
    result = {'pid': pid, 'traceid': traceid, 'response_data': response_data}
    return result
def ipyz():
    response = requests.get("https://39cm8js83842.vicp.fun/ippp")
    print('代理IP：' + response.text +'\n代理提供者：2250817616')
    return response.text
def getid(xid, pid, traceid, json_text):
    image_link = "https://user.mypikpak.com/pzzl/image?deviceid="+xid+"&pid="+pid+"&traceid="+traceid
    json_text = json_text
    body = image_link + "@@" + json_text
    headers = {
        'Accept': 'text / plain, text / html',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36'
    }
    import base64
    temp_b = body.encode("utf-8")  # 将字符串转换为二进制
    content_b = base64.b64encode(temp_b)
    content_b = 文本_取出中间文本(str(content_b),"'","'")
    url = "https://39cm8js83842.vicp.fun/" + str(content_b)
    #url = "http://127.0.0.1:12345/" + str(content_b)
    result2 = requests.get(url)
    return int(result2.text)

def postid(xid, pid, traceid, json_text):

    image_link = "https://user.mypikpak.com/pzzl/image?deviceid=" + xid + "&pid=" + pid + "&traceid=" + traceid
    json_text = json_text
    body = image_link + "@@" + json_text
    url = "https://39cm8js83842.vicp.fun/"
    #url = "http://127.0.0.1:12345/"
    result2 = requests.post(url, data=body)
    return int(result2.text)
def 文本_取出中间文本(data, start_str, end_str):
    start_idx = data.find(start_str)
    if start_idx != -1:
        start_idx += len(start_str)
        end_idx = data.find(end_str, start_idx)
        if end_idx != -1:
            return data[start_idx:end_idx]
    return None
def get_new_token(result, xid, captcha):
    traceid = result['traceid']
    pid = result['pid']
    response2 = requests.get(
        f"https://user.mypikpak.com/credit/v1/report?deviceid={xid}&captcha_token={captcha}&type"
        f"=pzzlSlider&result=0&data={pid}&traceid={traceid}")
    response_data = response2.json()
    print('获取验证TOKEN中......')
    return response_data


def verification(captcha_token, xid, mail):
    url = 'https://user.mypikpak.com/v1/auth/verification'
    body = {
        "email": mail,
        "target": "ANY",
        "usage": "REGISTER",
        "locale": "zh-CN",
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha_token,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
    }

    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('发送验证码中......')
    return response_data


def verify(xid, verification_id, code):
    url = 'https://user.mypikpak.com/v1/auth/verification/verify'
    body = {
        "verification_id": verification_id,
        "verification_code": code,
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('验证码验证结果中......')
    return response_data


def signup(xid, mail, code, verification_token):
    url = 'https://user.mypikpak.com/v1/auth/signup'
    body = {
        "email": mail,
        "verification_code": code,
        "verification_token": verification_token,
        "password": "QWer123..",
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('验证注册结果中......')
    return response_data


def init1(xid, access_token, sub, sign, t):
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "POST:/vip/v1/activity/invite",
        "device_id": xid,
        "captcha_token": access_token,
        "meta": {
            "captcha_sign": "1." + sign,
            "client_version": "undefined",
            "package_name": "mypikpak.com",
            "user_id": sub,
            "timestamp": t
        },
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
    }

    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('通过二次安全验证中......')
    return response_data


def invite(access_token, captcha_token, xid):
    url = 'https://api-drive.mypikpak.com/vip/v1/activity/invite'
    body = {
        "apk_extra": {
            "invite_code": ""
        }
    }
    headers = {
        'host': 'api-drive.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'authorization': 'Bearer ' + access_token,
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) PikPak/2.3.2.4101 '
                      'Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha_token,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-system-language': 'zh-CN'
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('确认邀请')
    return response_data


def init2(xid, access_token, sub, sign, t):
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "post:/vip/v1/order/activation-code",
        "device_id": xid,
        "captcha_token": access_token,
        "meta": {
            "captcha_sign": "1." + sign,
            "client_version": "undefined",
            "package_name": "mypikpak.com",
            "user_id": sub,
            "timestamp": t
        },
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
    }

    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('通过三次次安全验证中.......')
    return response_data


def activation_code(access_token, captcha, xid, in_code):
    url = 'https://api-drive.mypikpak.com/vip/v1/order/activation-code'
    body = {
        "activation_code": in_code,
        "page": "invite"
    }
    headers = {
        'host': 'api-drive.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'authorization': 'Bearer ' + access_token,
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) PikPak/2.3.2.4101 '
                      'Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-system-language': 'zh-CN'
    }
    response = requests.post(url, json=body, headers=headers)
    response_data = response.json()
    print('开始填写你的邀请码......')
    print(f'邀请结果:  {json.dumps(response_data, indent=4)}')
    return response_data

def main(incode):
    try:
        start_time = time.time()
        print(f'程序开始')
        xid = uuid()
        start_time = time.time()
        mail = get_mail(xxx)
        recipient_email = mail
        Init = init(xid, mail)
        while True:
            start_time_1 = time.time()
            print(f'滑块开始验证:')
            img_info = get_image(xid)
            if img_info['response_data']['result'] == 'accept':
                print('验证通过!!!')
                print(f'滑块时间{time.time()-start_time_1}')
                break
        captcha_token_info = get_new_token(img_info, xid, Init['captcha_token'])
        Verification = verification(captcha_token_info['captcha_token'], xid, mail)
        code = get_code(email_user, email_pass, recipient_email)
        verification_response = verify(xid, Verification['verification_id'], code)
        signup_response = signup(xid, mail, code, verification_response['verification_token'])
        current_time = str(int(time.time()))
        sign = get_sign(xid, current_time)
        init1_response = init1(xid, signup_response['access_token'], signup_response['sub'], sign, current_time)
        invite(signup_response['access_token'], init1_response['captcha_token'], xid)
        init2_response = init2(xid, signup_response['access_token'], signup_response['sub'], sign, current_time)
        activation = activation_code(signup_response['access_token'], init2_response['captcha_token'], xid,
                                     incode)
        run_time = f'{(time.time() - start_time):.2f}'
        try:
            if activation['add_days'] == 5:
                print(f'邀请码: {incode} => 邀请成功, 运行时间: {run_time}秒')
                print(f'邀请邮箱: {mail}\n邮箱密码: QWer123..')
            elif activation['add_days'] == 0:
                print(f'邀请码: {incode} => 邀请失败, 运行时间: {run_time}秒')
            else:
                print(f'程序异常请重试!!!, 运行时间: {run_time}秒')
        except:
            print('检查你的邀请码是否有效!!!')
    except Exception as e:
        print('异常捕获:', e)

if __name__ == '__main__':
    print('作者：1930520970（白栀）')
    print('原作者：纸鸢、神明、我不是蛆神')
    print('此版本随时挂，因为作者没钱续费挂机宝，这个api随时凉，想一直用请请赞助作者')
    print('6元就能续命一个月')
    print('赞助链接：https://img.picui.cn/free/2024/06/14/666b4469d3de7.png')
    print('谢谢')
    xxx = "bailaodada"  # 替换为你的outlook邮箱地址前缀 例如 xxx  = "asdhyuash"
    email_user = xxx + "@outlook.com"  # 替换为你的outlook邮箱地址前缀
    email_pass = "1930520970Aa"  # 替换为你的邮箱密码 例如 email_pass  = "asdhyuash"
    滑块模式 = 1  #获取滑块ID模式，1为post，其余为get
    if xxx == "":
        print("请看代码最后几行，自己填写好outlook配置")
        time.sleep(5)
        exit()
    #这里固定邀请码 例如 incode ='请输入邀请码:'
    incode = input('请输入邀请码: ')
    if os.environ.get("http_proxy"):
            del os.environ["http_proxy"]
        # 获取并清除 https_proxy 环境变量
    if os.environ.get("https_proxy"):
            del os.environ["https_proxy"]
    time.sleep(2)
    proxy = ipyz()
    os.environ["http_proxy"] = proxy
    #os.environ["https_proxy"] = proxy
    main(incode)
        
        