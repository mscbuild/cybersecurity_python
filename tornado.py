import tornado.ioloop
import tornado.web
import socket

class PortScanHandler(tornado.web.RequestHandler):
    def get(self):
        hostname = self.get_argument('hostname')
        start_port = int(self.get_argument('start_port'))
        end_port = int(self.get_argument('end_port'))
        
        open_ports = []
        for port in range(start_port, end_port+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        
        self.write('Open ports: ' + str(open_ports))

def make_app():
    return tornado.web.Application([
        (r"/portscan", PortScanHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
