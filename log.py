#!/usr/bin/python3

from base64 import b64encode
from socket import socket, AF_INET, SOCK_STREAM

import time
import sys, os, argparse

try:
    import _thread
    import socketserver
except ImportError:
    import thread as _thread
    import SocketServer as socketserver

nginx_error = ('HTTP/1.1 400 Bad Request\r\n'
    'Server: nginx/1.10.2\r\n'
    'Content-Type: text/html\r\n'
    'Content-Length: 173\r\n'
    'Connection: close\r\n'
    '\r\n'
    '<html>\r\n'
    '<head><title>400 Bad Request</title></head>\r\n'
    '<body bgcolor="white">\r\n'
    '<center><h1>400 Bad Request</h1></center>\r\n'
    '<hr><center>nginx/1.10.2</center>\r\n'
    '</body>\r\n'
    '</html>\r\n'
    '\r\n').encode('utf-8')

nginx_homepage = ('HTTP/1.1 200 OK\r\n'
    'Server: nginx/1.10.2\r\n'
    'Content-Type: text/html\r\n'
    'Content-Length: 612\r\n'
    'Last-Modified: Mon, 5 Mar 2018 02:42:15 GMT\r\n'
    'Connection: close\r\n'
    '\r\n'
    '<!DOCTYPE html>\r\n'
    '<html>\r\n'
    '<head>\r\n'
    '<title>Welcome to nginx!</title>\r\n'
    '<style>\r\n'
    '    body {\r\n'
    '        width: 35em;\r\n'
    '        margin: 0 auto;\r\n'
    '        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n'
    '    }\r\n'
    '</style>\r\n'
    '</head>\r\n'
    '<body>\r\n'
    '<h1>Welcome to nginx!</h1>\r\n'
    '<p>If you see this page, the nginx web server is successfully installed and\r\n'
    'working. Further configuration is required.</p>\r\n'
    '\r\n'
    '<p>For online documentation and support please refer to\r\n'
    '<a href="http://nginx.org/">nginx.org</a>.<br/>\r\n'
    'Commercial support is available at\r\n'
    '<a href="http://nginx.com/">nginx.com</a>.</p>\r\n'
    '\r\n'
    '<p><em>Thank you for using nginx.</em></p>\r\n'
    '</body>\r\n'
    '</html>\r\n'
    '\r\n').encode('utf-8')

nginx_404 = ('HTTP/1.1 404 Not Found\r\n'
    'Server: nginx/1.10.2\r\n'
    'Content-Type: text/html\r\n'
    'Content-Length: 169\r\n'
    'Connection: close\r\n'
    '\r\n'
    '<html>\r\n'
    '<head><title>404 Not Found</title></head>\r\n'
    '<body bgcolor="white">\r\n'
    '<center><h1>404 Not Found</h1></center>\r\n'
    '<hr><center>nginx/1.10.2</center>\r\n'
    '</body>\r\n'
    '</html>\r\n'
    '\r\n').encode('utf-8')

nginx_405 = ('HTTP/1.1 405 Not Found\r\n'
    'Server: nginx/1.10.2\r\n'
    'Content-Type: text/html\r\n'
    'Content-Length: 173\r\n'
    'Connection: close\r\n'
    '\r\n'
    '<html>\r\n'
    '<head><title>405 Not Allowed</title></head>\r\n'
    '<body bgcolor="white">\r\n'
    '<center><h1>405 Not Allowed</h1></center>\r\n'
    '<hr><center>nginx/1.10.2</center>\r\n'
    '</body>\r\n'
    '</html>\r\n'
    '\r\n').encode('utf-8')

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def log(self, local_addr, remote_addr, content):
        f = open('network-attack-log.csv', 'a')
        f.write('{},{},{}\n'.format(local_addr, remote_addr, content))
        f.close()

    def handle(self):
        remote_addr = self.client_address[0]
        (host, port) = self.server.server_address
        print('[{}:{}] Remote connected: {}'.format(host, port, remote_addr))
        try:
            data = self.request.recv(1024)
        except OSError:
            return
        if data == b'':
            print('[{}:{}] Received data: null from {}'.format(host, port, remote_addr))
            self.log('{}:{}'.format(host, port), remote_addr, '')
            self.try_close()
        b64d = b64encode(data).decode('utf-8')
        print('[{}:{}] Received data: {} from {}'.format(host, port, b64d, remote_addr))
        self.log('{}:{}'.format(host, port), remote_addr, b64d)
        try:
            httpdata = data.decode('utf-8')
        except Exception:
            self.request.send(nginx_error)
            self.try_close()
            print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 400', 'Content cannot decode.'))
            return
        spacePath = httpdata.find(' ')
        if spacePath == -1:
            self.request.send(nginx_error)
            self.try_close()
            print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 400', 'Invalid HTTP request'))
            return
        req = httpdata[0:spacePath]
        if len(req) > 7:
            self.request.send(nginx_error)
            self.try_close()
            print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 400', 'HTTP Request too long'))
            return
        if req != 'GET' and req != 'HEAD' and req != 'POST' and req != 'PUT' and req != 'DELETE' and req != 'CONNECT' and req != 'OPTIONS' and req != 'TRACE':
            self.request.send(nginx_error)
            self.try_close()
            print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 400', 'Invalid HTTP request method'))
            return
        httpdata = httpdata[spacePath+1:]
        spacePath = httpdata.find(' ')
        if spacePath == -1:
            self.request.send(nginx_error)
            self.try_close()
            print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 400', 'Invalid path'))
            return
        url = httpdata[0:spacePath]
        if url == '/':
            if req != 'GET' and req != 'POST':
                self.request.send(nginx_405)
                self.try_close()
                print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 405', 'HTTP request method is not GET or POST'))
                return
            self.request.send(nginx_homepage)
            self.try_close()
            print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 200', 'Request sucess'))
            return
        self.request.send(nginx_404)
        self.try_close()
        print('[{}:{}] Returned: {}, Reason: {}'.format(host, port, 'Nginx 404', 'Request sucess'))
        return
    
    def try_close(self):
        try:
            self.request.close()
        except Exception as e:
            print(e)

if __name__ == '__main__':
    print('Starting...')
    bind_addresses = [
        {'address': '0.0.0.0', 'port': 21},
        {'address': '0.0.0.0', 'port': 22},
        {'address': '0.0.0.0', 'port': 23},
        {'address': '0.0.0.0', 'port': 80},
        {'address': '0.0.0.0', 'port': 81},
        {'address': '0.0.0.0', 'port': 135},
        {'address': '0.0.0.0', 'port': 139},
        {'address': '0.0.0.0', 'port': 443},
        {'address': '0.0.0.0', 'port': 445},
        {'address': '0.0.0.0', 'port': 1080},
        {'address': '0.0.0.0', 'port': 1433},
        {'address': '0.0.0.0', 'port': 1723},
        {'address': '0.0.0.0', 'port': 3128},
        {'address': '0.0.0.0', 'port': 3306},
        {'address': '0.0.0.0', 'port': 3389},
        {'address': '0.0.0.0', 'port': 5900},
        {'address': '0.0.0.0', 'port': 5901},
        {'address': '0.0.0.0', 'port': 5902},
        {'address': '0.0.0.0', 'port': 5903},
        {'address': '0.0.0.0', 'port': 5904},
        {'address': '0.0.0.0', 'port': 5905},
        {'address': '0.0.0.0', 'port': 8080},
        {'address': '0.0.0.0', 'port': 8081},
        {'address': '0.0.0.0', 'port': 11211}
    ]
    servers = []
    for i in bind_addresses:
        print('Starting server at tcp://{}:{} ...'.format(i['address'], i['port']))
        server = ThreadedTCPServer((i['address'], i['port']), ThreadedTCPRequestHandler)
        _thread.start_new_thread(server.serve_forever, (),)
        servers.append(server)
        print('Started server at tcp://{}:{}.'.format(i['address'], i['port']))
    print('Servers started. Press Ctrl+C to stop them.')
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print('Shutdown...')
        for i in servers:
            i.shutdown()
    print('Finished')
