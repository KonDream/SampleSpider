'''
Author: KonDream
Date: 2022-06-04 21:19:32
LastEditors:  KonDream
LastEditTime: 2022-06-30 15:25:40
Description:    
'''
import requests
import re, sys
from optparse import OptionParser 
import tqdm, ast, os, time

parser = OptionParser(usage="[OPTION]... FILE...",               
                        description="一个爬取木马样本的demo - By KonDream",
                        version="1.0")
                              
parser.add_option("-d", "--download", action="store_true", help="下载样本到本地Sample目录")
parser.add_option("-u", "--upload", action="store_true", help="上传样本到云沙箱并下载报告")
parser.add_option("-e", "--ext", action="store", help="指定爬取的木马扩展名(deault:exe)", default="exe")
# parser.add_option("-t", "--time", action="store", help="指定样本分析时间(deault:60s)", default="60")
parser.add_option("-n", "--num", type="int", action="store", help="指定下载样本数(deault:10)", default="10")
parser.add_option("--start", type="int", action="store", help="上传起始序号(deault:1)", default="1")
parser.add_option("--end", type="int", action="store", help="上传终止序号(deault:10)", default="10")

headers = {
    "sec-ch-ua": '" Not A;Brand";v="99", "Chromium";v="102", "Microsoft Edge";v="102"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "Windows",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36 Edg/102.0.1245.30",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Referer": "https://bazaar.abuse.ch/download/927e564388f0341a0f00afcab7c1fa19b27174781b9e299e45737e6a94151fbe/",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Cookie": "_ga=GA1.1.1962933561.1653723888; BAZAAR=sd2h75kspka8vh1d038lnmnrm3; _ga_5GQV3CJ17N=GS1.1.1654347725.3.1.1654347901.0"
}

white_list = ['exe']

def CheckInput(option):
    if option.ext not in white_list:
        print("支持查询的扩展", white_list)
        exit("*{}* 非法的扩展名!!".format(option.ext))
    if option.num <= 0 or options.num > 1000:
        print("支持下载数量 (0, 1000]")
        exit("*{}* 非法的下载数量!!".format(option.num))
        

def GetSampleUrl(filetype, num):
    download_url = "https://bazaar.abuse.ch/browse.php?search=file_type%3A{}".format(filetype)
    print("***尝试获取url***")
    r = requests.get(url=download_url, headers=headers)   # 抓一千条
    download_url_list = re.findall('<a href="/download(.*?)/"', r.text)
    
    if len(download_url_list) is not None:
        print("***获取url成功 开始下载***")
        try:
            os.mkdir('Sample')
            os.mkdir("Pcap")
            os.mkdir("Report")
        except FileExistsError:
            pass
    else:
        exit("***获取url列表失败! 请重试!***")
    try:
        for i in tqdm.tqdm(range(num)):
            get_value_url_list = "https://bazaar.abuse.ch/download{}".format(download_url_list[i])
            r = requests.get(url=get_value_url_list, headers=headers)
            value_url_list = re.findall('value="(.*?)"', r.text)
            real_download_url = "https://bazaar.abuse.ch/download/{}".format(value_url_list[0])
            r = requests.get(url=real_download_url, headers=headers)
            with open('Sample/Sample{}.zip'.format(i+1), 'wb') as f:
                f.write(r.content)
    except Exception:
        exit("Network Error! Please Retry!")

def Pushthreatbook(start, end):
    '''
    上传逻辑：前台上传样本文件 -> 上传成功返回一个sha256 -> 提交sha256并进行分析 -> 拼接url得到样本分析结果
    '''
    url = "https://s.threatbook.cn"
    upload_url = url + "/apis/upload/submit_file"
    submit_sha256_url = url + "/apis/upload/submit_sha256"
    upload_headers = {
        "sec-ch-ua": '" Not A;Brand";v="99", "Chromium";v="102", "Google Chrome";v="102"',
        "X-Requested-With": "XMLHttpRequest",
        "sec-ch-ua-mobile": "?0",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36",
        "sec-ch-ua-platform": "Windows",
        "Accept": "*/*",
        "Origin": "https://s.threatbook.cn",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Referer": "https://s.threatbook.cn/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
    }
    Sample_path = os.listdir(r'Sample')
    sha256_value = []

    '''Step1 上传样本 并获得sha256'''
    for i in range(start-1, end):
        time.sleep(2)
        files = {
            'file': (open('Sample/Sample{}.zip'.format(i+1), 'rb'))
            }
        r = requests.post(url=upload_url, headers=upload_headers, files=files)
        response_content = ast.literal_eval(r.text)
        try:
            sha256_value.append(response_content['data']['sha256'])
            print("Get sha256 value **{}**".format(sha256_value[i - start + 1]))
        except KeyError:
            exit('Upload failed! Please retry!')

        '''Step2 提交sha256'''
        json = {
                "user_sandbox_type":"win7_sp1_enx86_office2013",
                "run_time":60,
                "package":"zip",
                "private":'false',
                "submit_params":{},
                "sha256":sha256_value[i - start + 1]
            }
        r = requests.post(url=submit_sha256_url, json=json)
        try:
            response_state = ast.literal_eval(r.text)['data']['result']
            
            print("Submit sha256 value, response state **{}**! Sample{}.zip done".format(response_state, i+1))
        except KeyError:
            exit('Submit sha256 failed! Please retry!')

    '''Step3 wait60s 获取报告及流量包'''
    print("Please wait a long long long time for results...")
    headers = {
        "Host": "s.threatbook.cn",
        "Connection": "close",
        "Cache-Control": "max-age=0",
        "sec-ch-ua": '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cookie": "gr_user_id=591dbbb2-ba7f-4f29-b5ac-bf95cab314b2; zg_did=%7B%22did%22%3A%20%22181326b9ae1b78-0d0301aab8d06f-15373079-144000-181326b9ae2876%22%7D; rememberme=629577e23dea1d90f94d4bec5f31ef80153e81a7|0533c9cd52d743e499223010d9739fd4|1656570012972|public|w; zg_8ce95389de054b5c90bb62222cf45190=%7B%22sid%22%3A%201656570003969%2C%22updated%22%3A%201656570013343%2C%22info%22%3A%201656570003971%2C%22superProperty%22%3A%20%22%7B%5C%22%E5%BA%94%E7%94%A8%E5%90%8D%E7%A7%B0%5C%22%3A%20%5C%22passport%5C%22%7D%22%2C%22platform%22%3A%20%22%7B%7D%22%2C%22utm%22%3A%20%22%7B%7D%22%2C%22referrerDomain%22%3A%20%22s.threatbook.cn%22%2C%22cuid%22%3A%20%22fa68d34397884b3a93d7ae1bfaf5c3e3%22%2C%22zs%22%3A%200%2C%22sc%22%3A%200%2C%22firstScreen%22%3A%201656570003969%7D",
        "If-None-Match": "15ed-HVLz0UTJzwcvYFr7TMquk7/LMZE"
    }
    for i in range(start-1, end):
        get_pcap_url = url + "/apis/sample/download/{}?type=pcap".format(sha256_value[i - start + 1])
        get_report_url = url + "/apis/sample/download/{}?type=report".format(sha256_value[i - start + 1])   
        print("网页版报告转至：{}/report/file/{}".format(url, sha256_value[i - start + 1]))
        # 必须要先请求一下这个链接才能下载
        r = requests.get(url="https://s.threatbook.cn/apis/sample/basic/{}".format(sha256_value[i - start + 1]), headers=headers)
        while True:
            print("**尝试下载分析结果 请耐心等待...**")
            r = requests.get(url=get_report_url, headers=headers)
            if len(r.text) > 100:
                print("**下载成功！**")       
                try:
                    with open('Report/report{}.zip'.format(i+1), 'wb') as f:
                        f.write(r.content)
                    r = requests.get(url=get_pcap_url, headers=headers)
                    with open('Pcap/pcap{}.zip'.format(i+1), 'wb') as f:
                        f.write(r.content)
                except Exception:
                    pass
                break
            time.sleep(10)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        sys.argv.append('-h')
    (options, args) = parser.parse_args(sys.argv[1:])
    CheckInput(options)
    if options.download is True:
        GetSampleUrl(options.ext, options.num)
    if options.upload is True:
        Pushthreatbook(options.start, options.end)


