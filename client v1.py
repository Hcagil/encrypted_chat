import random, os, logging
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes,serialization, cmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


from socket import AF_INET, SOCK_STREAM, socket
from threading import Thread,Event
from tkinter import *
from time import sleep

class ChatGui(Tk):
    '''
    MAIN CHAT GUI
    ALL COMMUNUCATION DONE IN CONNECTION CLASS
    '''
    def __init__(self) -> None:
        Tk.__init__(self)
        self.create_container()
        self.show_frame(Login)
        self.bind('<Return>',self.send_message)
        self.protocol('WM_DELETE_WINDOW',self.close)

    def create_container(self):
        self.container = Frame(self)
        self.container.pack(side='top',fill='both',expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        self.frames = dict()

        for F in (Login,Messenger):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0,column=0, sticky='nsew')

    def show_frame(self,fr):
        f = self.frames[fr]
        f.tkraise()

    def add_frame(self,F):
        frame = F(self.container, self)
        self.frames[F] = frame
        frame.grid(row=0,column=0, sticky='nsew')

    def connect(self):
        login = self.frames[Login]
        login.waiting()
        HOST = login.HOST.get()
        PORT = 49565
        self.USERNAME = login.USERNAME.get()

        logging.basicConfig(filename=F'CLIENT_{self.USERNAME}_LOG.txt',level=logging.INFO,
                    format='%(asctime)s : %(levelname)s : %(message)s')

        if self.USERNAME == '':
            self.USERNAME = f'USERNAME{random.randint(100,200)}'
        self.ADDR = (HOST,PORT)
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.connect(self.ADDR)
        self.con = Connection(self)

    def send_message(self,event=None):
        self.con.send_message()
    
    def close(self):
        self.sock.send(f'CLOSE[(//)]{self.USERNAME}'.encode('utf-8'))
        self.destroy()

    def _handshake(self):
        self.con.target_user = self.frames[UserList].user_box.get(ANCHOR)
        self.con.handshake()
        # Thread(target=self.con.handshake()).start()
        

class Connection():
    '''
    GO TO LOGIN PROTOCOL 
    '''
    def __init__(self,gui) -> None:
        self.BUFSIZ = 2048
        self.gui = gui
        # gui.show_frame(Messenger)
        self.create_rsa()
        self.server_public = None
        self.socket = self.gui.sock
        self.send_command('USERNAME',self.gui.USERNAME)
        t = Thread(target=self.login_protocol)
        t.start()
        # t.join()

    def login_protocol(self):
        '''
        FIRST CERTIFICATION STAGE 
        SECOND USER LIST ARRIVES TO USER1
        THIRD USER1 SELECTS USER2
        FORTH HANDSHAKING BEGINS
        '''
        self.certification()
        self.select_user()
        self.receive()
    
    def certification(self):
        while self.server_public == None:
            self.send_command('SENDPUBLIC')
            if self.dec(self.socket.recv(self.BUFSIZ))[0] == 'PUBLIC':
                pem = self.socket.recv(self.BUFSIZ)
                self.server_public = load_pem_public_key(pem)
        logging.info('Server Public Key Received')
        done = False
        while not done:
            rdata = self.socket.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            # logging.info(f'ctype: {ctype}')
            if ctype == 'DONE':
                done = True
            elif ctype == 'SENDPUBLIC':
                self.send_command('PUBLIC')
                self.socket.send(self.public_pem)
                logging.info('Public Key Sent..')
            elif ctype == 'CREATECERTIFICATE':
                self.certificate_pem = self.socket.recv(self.BUFSIZ)
                logging.info('Certificate Received..')
                try:
                    self.certificate = x509.load_pem_x509_certificate(self.certificate_pem)
                    self.certificate.serial_number
                except Exception as e:
                    logging.info('Certification Error..')
            
                    
    def select_user(self):
        self.userlist = list()
        self.target_user = None
        self.send_command('USERLIST')
        while True:
            rdata = self.socket.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            if ctype == 'LISTDONE':
                break
            elif ctype == 'USERS':
                self.userlist.append(data)
        if len(self.userlist) >0 :
            self.gui.add_frame(UserList)
            self.gui.show_frame(UserList)
            self.gui.frames[UserList].wait_variable(self.gui.frames[UserList].pressed)
            self.target_user = self.gui.frames[UserList].user_box.get(ANCHOR)
            self.handshake()

        else:
            self.get_handshake()


    def handshake(self):
        self.send_command('HELLO',self.target_user)
        self.send_command('SENDCERT')
        logging.info('Certification Sended to Target User')
        done = False
        while not done:
            # logging.info('Handshake Listening')
            rdata = self.socket.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            # logging.info(f'handshake ctype: {ctype}')
            if ctype == 'TARGETNONCE':
                self.target_cert = self.socket.recv(self.BUFSIZ)
                self.target_cert = x509.load_pem_x509_certificate(self.target_cert)
                self.target_public = self.target_cert.public_key()
                nonce = data
                logging.info(f'Nonce Received..')
                nonce_signed = self.key.sign(
                    nonce.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                self.send_command('VERIFYNONCE')
                sleep(0.001)
                self.socket.send(nonce_signed)
            elif ctype == 'NONCEVERIFIED':
                self.create_keys()
                # self.mastersecret = self.create_master_secret((self.masterkey,self.iv1,self.iv2))
                masterenc = self.target_public.encrypt(
                    self.master_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                ivenc = self.target_public.encrypt(
                    self.iv,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                self.cmac = cmac.CMAC(algorithms.AES(self.master_key))
                self.cmac.update(b'cs4057')
                self.cmac_final = self.cmac.finalize()
                self.send_command('MASTER')
                sleep(0.001)
                self.socket.send(masterenc)
                sleep(0.001)
                self.socket.send(ivenc)
                logging.info('Master Sent..')
                # Event().wait(1)
                sleep(0.01)
                self.send_command('DONE')
                done = True



    def get_handshake(self):
        done = False
        while not done:
            # logging.info('get_Handshake Listening')
            rdata = self.socket.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            # logging.info(f'get_handshake ctype: {ctype}')
            if ctype == 'HELLO':
                self.target_user = data
            elif ctype == 'TARGETCERT':
                self.target_cert = self.socket.recv(self.BUFSIZ)
                self.target_cert = x509.load_pem_x509_certificate(self.target_cert)
                self.target_public = self.target_cert.public_key()
                logging.info('Target Certificate Received..')
                nonce = str(random.randint(10000,30000))
                self.send_command('NONCE',self.target_user)
                sleep(0.001)
                self.socket.send(str(nonce).encode('utf-8'))
                logging.info('Nonce Sent..')
            elif ctype == 'VERIFYNONCE':
                signon = self.socket.recv(self.BUFSIZ)
                try:
                    self.target_public.verify(
                        signon,
                        nonce.encode('utf-8'),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()    
                    )
                    logging.info('Nonce Verified..')
                except:
                    logging.info('Nonce Verification Error..')
                self.send_command('NONCEVERIFIED')

            elif ctype == 'MASTER':
                masterenc = self.socket.recv(self.BUFSIZ)
                ivenc = self.socket.recv(self.BUFSIZ)
                self.master_key = self.key.decrypt(
                    masterenc,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                self.iv = self.key.decrypt(
                    ivenc,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # self.master_key, self.iv1, self.iv2 = self.split_secret(self.mastersecret)
                self.cmac = cmac.CMAC(algorithms.AES(self.master_key))
                self.cmac.update(b'cs4057')
                self.cmac_final = self.cmac.finalize()
                logging.info('Master Received..')
                self.send_command('DONE')
                done = True

    def receive(self):
        self.gui.show_frame(Messenger)
        self.cipher = Cipher(algorithms.AES(self.master_key),modes.CBC(self.iv))
        while True:
            rdata = self.socket.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            if ctype == 'MESSAGE':
                username = data
                data = self.socket.recv(self.BUFSIZ)
                data_len = self.socket.recv(self.BUFSIZ)
                rec_cmac = self.socket.recv(self.BUFSIZ)
                logging.info('MESSAGE RECEIVED')
                try:
                    cmacc = cmac.CMAC(algorithms.AES(self.master_key))
                    cmacc.update(b'cs4057')
                    cmacc.verify(rec_cmac)
                    logging.info('MAC VERIFIED')
                    data_len = int(data_len.decode('utf-8'))
                    data = self.aes_decode(data)
                    data = data.decode('utf-8')
                    self.gui.frames[Messenger].msg_box.insert(END,f'{username}: {data[:data_len]}')
                except Exception as e:
                    logging.info(e)
    def send_message(self):
        data = self.gui.frames[Messenger].msg_text.get('1.0',END)
        data_len = str(len(data)).encode('utf-8')
        self.gui.frames[Messenger].msg_text.delete('1.0',END)
        data = self.aes_encode(data.encode('utf-8'))
        self.send_command('MESSAGE',self.gui.USERNAME)
        sleep(0.01)
        self.socket.send(data)
        sleep(0.01)
        self.socket.send(data_len)
        sleep(0.01)
        self.socket.send(self.cmac_final)
        logging.info('MESSAGE SENT')
        # self.socket.send(f'{self.gui.USERNAME}/{data}'.encode('utf-8'))

    def send_command(self,ctype,data=''):
        self.socket.send(f'{ctype}[(//)]{data}'.encode('utf-8'))
        # sleep(0.3)

    def dec(self,data):
        # Decode Data
        return data.decode('utf-8').split('[(///)]')

    def create_rsa(self):
        self.key = rsa.generate_private_key(65537,1024)
        self.private_pem = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.public_pem = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def create_master_secret(self,keys):
        master_secret = ''.encode('utf8')
        splitter = '[(/\/\)]'.encode('utf-8')
        for key in keys:
            master_secret += key + splitter
        # logging.info(f'master secret = {master_secret}')
        return master_secret

    def split_secret(self,key):
        return key.split('[(/\/\)]'.encode('utf-8'))

    def create_keys(self):
        # self.masterkey = Fernet.generate_key()
        self.master_key = os.urandom(32)
        self.iv = os.urandom(16)
        # self.iv2 = os.urandom(16)

    def aes_decode(self,data):  
        dec = self.cipher.decryptor()
        plain = dec.update(data) + dec.finalize()
        return plain

    def aes_encode(self,data):
        data = self.fix_length(data)
        enc = self.cipher.encryptor()
        cip = enc.update(data) + enc.finalize()
        return cip

    def fix_length(self,data):
        binary_length = 32
        padding_length = len(data) + (binary_length - len(data)) % binary_length
        return data.ljust(padding_length, b"\0")

class Login(Frame):
    def __init__(self, parent, controller):
        Frame.__init__(self,parent)
        Label(self,text='CSE 4057 Programming Assignment', font=('Verdana',15)).grid(row=0,column=0,columnspan=3,pady=10)
        Label(self,text='Enter Destination IP:').grid(row=1,column=0,pady=5)
        Label(self,text='Username').grid(row=2,column=0,pady=3)

        self.HOST = StringVar()
        self.HOST.set(HOST)
        dest_ip_entry = Entry(self,textvariable=self.HOST,width=20)
        dest_ip_entry.grid(row=1,column=1)

        self.USERNAME = StringVar()
        username_entry = Entry(self,textvariable=self.USERNAME,width=15)
        username_entry.grid(row=2,column=1)

        conn_button = Button(self,text='Start Connection',command=lambda: controller.connect())
        conn_button.grid(row=3,column=0,columnspan=3,pady=8)

    def waiting(self):
        Label(self,text='Waiting for Server Connection...').grid(row=4,column=0,columnspan=3,pady=8)

class UserList(Frame):
    def __init__(self, parent, controller):
        self.controller = controller
        Frame.__init__(self,parent)
        Label(self,text='USER LIST', font=('Verdana',15)).grid(row=0,column=0,columnspan=3,pady=10)
        self.pressed = IntVar()
        chat_button = Button(self,text='Chat',command=lambda: self.pressed.set(1))
        chat_button.grid(row=2,column=1)

        # btnOK = Button(self, text="Submit", pady=5, font=("Arial Bold", 10),bg='lightgray', command=lambda: self.pressed.set(1)).grid(row=14, column=0)


    # def create_box(self):
        self.user_selected = StringVar(value=self.controller.con.userlist)
        self.user_box = Listbox(self,selectmode='browse',listvariable=self.user_selected)
        self.user_box.grid(row=1,column=0,columnspan=3)
        # self.user_box.bind('<<ListboxSelect>>', self.selected)

    # def selected(self,event):
    #     self.controller.con.target_user = self.user_box.get(ANCHOR)
    #     self.controller.handshake()

class Messenger(Frame):   
    def __init__(self,parent,controller):     
        self.controller = controller
        Frame.__init__(self,parent)
        
        scrollbar = Scrollbar(self,orient=VERTICAL)
        self.msg_box = Listbox(self,height=15, width=50, yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0,column=3,sticky='NS')
        scrollbar.config(command=self.msg_box.yview)
        self.msg_box.grid(row=0,column=0,columnspan=3)

        self.msg_text = Text(self,width=30,height=5)
        self.msg_text.grid(row=2,column=0)

        send_but = Button(self,text='SEND', height=5, command=lambda: self.controller.send_message())
        send_but.grid(row=2,column=1,sticky=W)

        Label(self).grid(row=1, column=1, pady=10)


if __name__ == '__main__':
    HOST = '192.168.1.106'
    a = ChatGui()
    a.mainloop()