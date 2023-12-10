import requests
import requests as req
import re
import random
import logging
from time import sleep, gmtime
from bs4 import BeautifulSoup
import os
import calendar
import asyncio

from requests.exceptions import TooManyRedirects, ConnectionError, ReadTimeout
from urllib3.exceptions import InsecureRequestWarning, ReadTimeoutError, NameResolutionError, NewConnectionError
from tika import parser

logging.basicConfig(format='[%(asctime)s : %(levelname)s] %(message)s', datefmt='%d.%m.%Y %H:%M:%S', encoding='utf-8',
                    level=logging.INFO)
browser = None
failcount = 0

req.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
host = "https://malpedia.caad.fkie.fraunhofer.de"
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0'}

# break request
blacklist = ['https://ti.qianxin.com/uploads/2020/02/13/cb78386a082f465f259b37dae5df4884.pdf', 'https://noticeofpleadings.com/crackedcobaltstrike/files/ComplaintAndSummons/1%20-Microsoft%20Cobalt%20Strike%20-%20Complaint(907040021.9).pdf']

async def get_local(path, cache_time=None):
    try:
        if cache_time is not None:
            mtime = os.path.getmtime(path)
            now = calendar.timegm(gmtime())
            if now - cache_time > mtime:
                logging.debug('Load: Cache invalid for %s', path)
                raise FileNotFoundError
        mode = "rb"
        with open(path, mode) as file:
            logging.debug("Load: %s", path)
            text = file.read()
            return text
    except FileNotFoundError:
        #logging.error('Load: FileNotFound: %s', path)
        return None


async def get_remote(url):
    name = await url2name(url)
    path = await name2path(name)
    if url in blacklist:
        logging.info(f"Get {url} (BLACKLISTED)")
        return None
    logging.info(f"Get {url}")
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
    except (TooManyRedirects, NewConnectionError, NameResolutionError, ReadTimeout, ReadTimeoutError, TimeoutError, ConnectionError) as e:
        logging.error(e)
        return None
    #print(response.headers)
    content = None
    if response.status_code == 200:
        content_type = response.headers.get('Content-Type')

        if re.match("text/html|text/plain", content_type):
            content = response.content
        elif re.match("application/pdf|application/octet-stream", content_type):
            parsed_pdf = parser.from_buffer(response.content)
            content = bytearray(parsed_pdf['content'], 'utf-8')
        #elif re.match("video/mp4|image/jpeg|application/vnd.openxmlformats-officedocument.presentationml.presentation", content_type):
        else:
            with open(path, "wb") as file:
                file.write(bytearray(f'STATUS: unparseable Content-Type {content_type}', "utf-8"))
            print(f"Undefined Content-Type found {content_type}")
            return None
        with open(path, "wb") as file:
            file.write(content)
        return content
    else:
        with open(path, "w") as file:
            file.write(f'STATUS: {response.status_code}')
        print(f"Undefined Status-Code found {response.status_code}")
    return None


async def get(url, cache_time=None, wait=True, check=False):
    name = await url2name(url)
    path = await name2path(name)
    content = await get_local(path, cache_time=cache_time)  # try to get content from disk
    if check and content is not None:
        logging.info(f"Skipping {url}")
        return None
    if content is None:  # FileNotFound
        if wait:
            i = (500 + random.randint(0, 1200)) / 1000
            logging.info(f"Get {url} (in {i}s)")
            sleep(i)  # wait to be fair
        content = await get_remote(url)
    return content


async def check_stegano_on_extern_page(url):
    content = await get(url, wait=False, check=True)
    if content is not None:
        try:
            match = re.search("covert|stego|stegano|tunnel", content.decode('utf-8'))
            if match:
                #logging.info("Candidate found: %s (%s)", url, match.group(0))
                return match.group(0)
        except UnicodeError:
            logging.error(f"UnicodeError: %s", content)
    return None


async def request_malware_details(url):
    content = await get(url)
    articles = []
    if content is not None:
        soup = BeautifulSoup(content.decode('utf-8'), 'html.parser')
        trs = soup.find_all('tr', attrs={'data-href': True})[1:]
        for tr in trs:
            href = tr['data-href']
            date = int(tr.find_next('span', attrs={'class': 'date'}).text[:4])
            #print(f"{date} : {href}: {'✅' if date > 2018 else '❌'}")
            if date > 2018:
                articles.append({'date': date, 'url': href})
    count = len(articles)
    if len(articles) > 0:
        print(f"Found {count} articles for {url} ✅")
    return articles


async def request_malware_list():
    content = await get(f"{host}/families", cache_time=3600)
    if content is not None:
        soup = BeautifulSoup(content.decode('utf-8'), 'html.parser')
        hrefs = [f"{host}{link['data-href']}" for link in soup.find_all('tr', attrs={'data-href': True})]
        return hrefs
    return []


async def url2name(url):
    name = re.sub('[.:/|\\\\]', '-', url)
    name = re.sub('[^a-zA-Z0-9-]', '', name)
    name = name[:250]
    return name


async def name2path(name):
    path = f"./raw/{name}"
    return path


async def main():
    malware_urls = await request_malware_list()
    random.shuffle(malware_urls)
    for url in malware_urls:
        malware = re.sub("^.*/", "", url)
        articles = await request_malware_details(url)
        for article in articles:
            keyword = await check_stegano_on_extern_page(article['url'])
            if keyword is not None:
                with open("hits", "a") as file:
                    file.write(f"{article['date']:4d} {keyword:8s} {malware:20s} {article['url']}\n")


if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
    exit(42)
