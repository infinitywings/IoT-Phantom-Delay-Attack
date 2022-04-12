import socket, threading, logging, asyncio, argparse, time, os
import threading
from queue import Empty
from threading import Thread
from queue import Queue
import sys
from util import *
from TLSRecon import TLSType





class Session(threading.Thread):
    def __init__(self,d_addr,d_sock,logger):
        threading.Thread.__init__(self)
        self.d_sock = d_sock
        self.d_addr = d_addr
        self.termination = Queue()
        self.server_q = Queue()
        self.device_q = Queue()
        self.s_addr = original_addr(d_sock)
        self.logger = logger

    def run(self):
        self.s_sock = self.connect_server(self.s_addr)
        t_dr = Thread(target=self.device_read, name='device read')
        t_dw = Thread(target=self.device_write, name='device write')
        t_sr = Thread(target=self.server_read, name='server read')
        t_sw = Thread(target=self.server_write, name='server write')
        t_dr.start()
        t_sr.start()
        t_dw.start()
        t_sw.start()
        self.logger.info('new session with %s is established'%(str(self.s_addr)))
        if self.termination.get():
            self.s_sock.close()
            self.d_sock.close()
            self.logger.info('session with %s is getting terminated'%(str(self.s_addr)))
        t_dr.join()
        t_sr.join()
        t_dw.join()
        t_sw.join()
        self.logger.info('session with %s has been terminated'%(str(self.s_addr)))

    def in_range(self,time_range,lengths):
        for length in lengths:
            if (length >= time_range[0]) and (length <= time_range[1]):
                return True
        return False
    
    def analyze_hk(self,msg,dst):
        if dst == "server":
            address = self.s_addr
        else:
            address = self.d_addr
        logger.info("%d bytes to %s"%(len(msg),address))
        with open('./flag.txt','rt+') as flag:
                instruct = flag.read()
                length = len(msg)
                if len(instruct) > 0:
                    length_range = instruct.split(' ')[0]
                    delay = int(instruct.split(' ')[1])
                    minimal = int(length_range.split(',')[0])
                    maximal = int(length_range.split(',')[1]) 
                    if (length >= minimal) and (length <= maximal):
                        if dst == "server":
                            self.device_q.put(delay)
                        else:
                            self.server_q.put(delay)
                        flag.truncate(0)
                        flag.flush()
                        

    def analyze(self,msg,dst):
        if dst == "server":
            address = self.s_addr
        else:
            address = self.d_addr
        records_sig = TLSType(msg)
        type_list = [x[0] for x in records_sig]
        if ('application_data' in type_list):
            lengths = [x[1] for x in records_sig]
            logger.info("record of %s bytes to %s"%(str(lengths),address))
            with open('./flag.txt','rt+') as flag:
                instruct = flag.read()
                length = len(msg)
                if len(instruct) > 0:
                    length_range = instruct.split(' ')[0]
                    delay = int(instruct.split(' ')[1])
                    minimal = int(length_range.split(',')[0])
                    maximal = int(length_range.split(',')[1]) 
                    if self.in_range((minimal,maximal),lengths):
                        if dst == "server":
                            self.device_q.put(delay)
                        else:
                            self.server_q.put(delay)
                        flag.truncate(0)
                        flag.flush()



    def device_read(self):
        while True:
            try:
                msg_f_d = self.d_sock.recv(8192)
            except:
                self.termination.put(True)
                self.device_q.put('')
                break
            if len(msg_f_d) > 0:
                self.analyze(msg_f_d,"server")
                self.device_q.put(msg_f_d)
            else:
                self.termination.put(True)
                self.device_q.put('')
                break

        
    def device_write(self):
        while True:
            msg_t_d = self.server_q.get()
            if type(msg_t_d) == int:
                    self.logger.info("---------------delay starts for %s seconds---------------"%(str(msg_t_d)))
                    time.sleep(msg_t_d)
                    self.logger.info("---------------delay ends for %s seconds---------------"%(str(msg_t_d)))
                    continue
            if len(msg_t_d) > 0:
                try:
                    self.d_sock.send(msg_t_d)
                except:
                    self.termination.put(True)
                    break
            else:
                break

    def server_read(self):
        while True:
            try:
                msg_f_s = self.s_sock.recv(8192)
            except:
                self.termination.put(True)
                self.server_q.put('')
                break
            if len(msg_f_s):
                self.analyze(msg_f_s,"device")
                self.server_q.put(msg_f_s)
            else:
                self.termination.put(True)
                self.server_q.put('')
                break
        
    def server_write(self):
        while True:
            msg_t_s = self.device_q.get()
            if type(msg_t_s) == int:
                    self.logger.info("---------------delay starts for %s seconds---------------"%(str(msg_t_s)))
                    time.sleep(msg_t_s)
                    self.logger.info("---------------delay ends for %s seconds---------------"%(str(msg_t_s)))
                    continue
            if len(msg_t_s) > 0:
                try:
                    self.s_sock.send(msg_t_s)
                except:
                    self.termination.put(True)
                    break
            else:
                break


    def connect_server(self,s_addr):
        s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s_sock.connect(s_addr)
            return s_sock
        except Exception as e:
            self.logger.error(e)
            return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Transparent proxy for TLS sessions')
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('-p', '--port',type=int, default=10000, metavar='P',help= 'port to listen')
    args = parser.parse_args()

    logger = logging.getLogger('logger')
    sh = logging.StreamHandler(stream=None)
    formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    if args.verbose: 
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_sock:
        listen_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listen_sock.bind(('0.0.0.0',args.port))
        listen_sock.listen()

        logger.info("start listening at port %d"%(args.port))
        while True:
            try:
                d_sock, d_addr = listen_sock.accept()
                session_thread = Session(d_addr,d_sock,logger)
                session_thread.start()
            except KeyboardInterrupt:
                listen_sock.close()
                del listen_sock
                sys.exit()
                
