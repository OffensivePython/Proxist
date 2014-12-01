#!/usr/bin/env python
#=========================================================#
# [+] Title: Hide My Ass Proxy Grabber - Proxist 2.0      #
# [+] Script: proxist.py                                  #
# [+] Blog: http://www.pythonforpentesting.com            #
#=========================================================#

import re
import time
import json
import socket
import urllib2
from optparse import OptionParser

__version__ = 2.0

class Grabber(object):
    def __init__(self):
        self.headers = {
            'User-Agent':'Proxist %s'%__version__,
            'Accept':'application/json',
            'Connection':'keep-alive',
            'X-Requested-With':'XMLHttpRequest'}
        self.pattern = {
            'entry':r'<tr class=".+?" rel="\d+?">(.+?)</tr>',
            'pages':r'<a href="/\d+?">(\d+?)</a>'}
        self.page = 1
        self.html = self.NextPage()
        self.count = self.GetCount(self.html) # number of pages
        self.entries = self.ExtractEntries(self.html)
    def run(self, count, fname, saveall):
        header = ('Status'
                  '|   IP Address  '
                  '|Port '
                  '|      Country     '
                  '|Protocol'
                  '|Anonymity'
                  '|Speed')
        fmt = "%-6s|%-15s|%-5s|%-18s|%-8s|%-9s|%-6s"
        print header
        hFile = open(fname, 'a')
        if hFile and saveall:
            hFile.write("-"*77)
            hFile.write("\n"+header+"\n")
            hFile.write("-"*77+"\n")
        while len(self.entries)<count:
            self.html = self.NextPage()
            self.entries += self.ExtractEntries(self.html)
        ProxyHandler = Proxy(self.entries)
        ip_port = ProxyHandler.Extract(self.entries[:count]) # returns [(ip, port), ...]
        for proxy in ip_port:
            status, country, proto, anon, speed = ProxyHandler.Check(proxy)
            log = fmt%(status, proxy[0], proxy[1], country, proto, anon, speed)
            print log
            if hFile:
                if saveall:
                    hFile.write(log+"\n")
                else:
                    hFile.write(proxy[0]+":"+proxy[1]+"\n")
        if hFile:
            hFile.close()
    def NextPage(self):
        self.request = urllib2.Request(
            "http://proxylist.hidemyass.com/"+str(self.page),
            headers=self.headers)
        page = urllib2.urlopen(self.request).read()
        return self.Unescape(page)
    def Unescape(self, html):
        unescaped = html.replace(r'\"', '"')
        unescaped = unescaped.replace(r'\/', '/')
        unescaped = unescaped.replace(r'\n', '\n')
        return unescaped
    def ExtractEntries(self, html):
        entries = re.findall(self.pattern['entry'], html, re.DOTALL)
        return entries
    def GetCount(self, html):
        pages = re.findall(self.pattern['pages'], html)
        return int(pages[-1]) # last page
    
class Proxy(object):
    def __init__(self, entry):
        self.pattern = {
            'ip':r'</style>(.+?)</span></td>',
            'port':r'<td>(\d+?)</td>',
            'country':r'"country":"(.+?)"',
            'none':r'\.(\S+?){display:none}',
            'tags':r'<(\w+?) (\w+?)="(.+?)">(.+?)</(\w+?)>',
            'info':r'({"id":.+?})'}
        self.request = (
            'POST {} HTTP/1.1\r\n'
            'Host: www.checker.freeproxy.ru\r\n'
            'User-Agent: Proxist 2.0\r\n'
            'X-Requested-With: XMLHttpRequest\r\n'
            'Connection: keep-alive\r\n'
            'Content-Type: application/x-www-form-urlencoded\r\n'
            'Content-Length: {}\r\n\r\n')
    def Extract(self, entries):
        ip_port = []
        for entry in entries:
            nones = ['display:none'] + self.FindAll(self.pattern['none'], entry)
            entry = entry.replace('<span></span>', '')
            ip_port += [(self.GetIP(entry, nones), self.GetPort(entry))]
        return ip_port
    def Check(self, proxy):
        anon_types = {
            'HIA':'Elite',
            'ANM':'Medium',
            'NOA':'None'};
        while True:
            http = socket.socket()
            http.connect(('www.checker.freeproxy.ru', 80))
            data = 'data='+proxy[0]+'%3a'+proxy[1]
            try:
                country = self.Post(http,
                                    '/engine/parser.php',
                                    len(data),
                                    self.pattern['country'],
                                    data)
                result = self.Post(http,
                                   '/engine/results.php',
                                   0,
                                   self.pattern['info'])
                http.close()
                break
            except socket.error as err:
                http.close()
                continue
        result = json.loads(result)
        status = result['status']
        if status=='valid':
            speed = result['speed']
            fail = [None, 'FAIL']
            if result['socks5'] not in fail:
                protocol = 'SOCKS5'
                anon = anon_types[result['socks5']]
            elif result['socks4'] not in fail:
                protocol = 'SOCKS4'
                anon = anon_types[result['socks4']]
            elif result['https'] not in fail:
                protocol = 'HTTPS'
                anon = anon_types[result['https']]
            elif result['http'] not in fail:
                protocol = 'HTTP'
                anon = anon_types[result['http']]
        else:
            speed = 'N/A'
            protocol = 'N/A'
            anon = 'N/A'
        return status, country, protocol, anon, speed
    def Post(self, sock, path, length, pattern, data=''):
        request = self.request.format(path, length)
        while True:
            try:
                sock.send(request+data)
                response = sock.recv(65535)
                response = re.search(pattern, response).group(1)
                break
            except AttributeError:
                if pattern == self.pattern['country']:
                    response = 'N/A'
                    break
                else:
                    time.sleep(1)
        return response
    def Search(self, pattern, string, option=0):
        return re.search(pattern, string, option).group(1)
    def FindAll(self, pattern, string):
        return re.findall(pattern, string)
    def GetIP(self, html, nones):
        ip = self.Search(self.pattern['ip'],
                            html,
                            re.DOTALL)
        tags = self.FindAll(self.pattern['tags'], ip)
        for t in tags:
            if t[2] in nones:
                ip = self._StripNone(ip, t)
            else:
                ip = self._StripTrash(ip, t)
        ip = ip.replace('</span>', '')
        return ip
    def GetPort(self, html):
        return self.Search(self.pattern['port'], html)
    def _StripNone(self, proxy, t):
        pattern = r'<{} {}="{}">{}</{}>'.format(t[0], t[1], t[2], t[3], t[4])
        return proxy.replace(pattern, '')
    def _StripTrash(self, proxy, t):
        pattern = r'<{} {}="{}">'.format(t[0], t[1], t[2])
        return proxy.replace(pattern, '')

def main():
    parser = OptionParser()
    parser.add_option("-o", "--output", dest="output",
                      type="string", help="Output file",
                      metavar="FILE", default="proxist.txt")
    parser.add_option("-n", dest="count",
                      type="int", help="Number of proxies to dump",
                      metavar="N", default=50)
    parser.add_option("-a", "--all", dest="saveall",
                      help="Store all information", action="store_true",
                      default=False)
    options, args = parser.parse_args()
    output = options.output
    count = options.count
    saveall=options.saveall

    grabber = Grabber()
    grabber.run(count, output, saveall)
if __name__ == '__main__':
    main()
