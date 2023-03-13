import datetime, pickle
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from socket import AF_INET, SOCK_STREAM, socket
from threading import Thread
from time import sleep
import logging

logging.basicConfig(filename='SERVER_LOG.txt',level=logging.INFO,
                    format='%(asctime)s : %(levelname)s : %(message)s')

one_day = datetime.timedelta(1, 0, 0)

class Server():
    def __init__(self,socket,BUFSIZ):
        self.clients = dict()
        self.soc = socket
        self.BUFSIZ = BUFSIZ
        self.create_rsa()


    def accept_conns(self):
        '''
        ACCEPTING CONNECTIONS AND STARTING PROTOCOLS
        '''
        while True:
            client, address = self.soc.accept()
            self.clients[client] = Client()
            self.clients[client].address = address
                                    
            logging.info(f'Total connected user: {len(self.clients)}')
            Thread(target=self.accept_protocols,args=(client,)).start()

    def accept_protocols(self,client):
        '''
        PROTOCOL PROCEDURES
        1. PUBLIC KEY CERTIFICATION
        2. HANDSHAKING
        3. KEY GENERATION
        '''
        self.certification(client)
        logging.info(f'{self.clients[client].username} Certicifation DONE ...')
        self.user_selection(client)
        self.users_handshake(client)
        logging.info(f'{self.clients[client].username} USERS HANDSHAKE DONE ...')

        self.receive(client)


    def certification(self,client):
        '''
        CERTIFICATION STAGE:
        1.USER SENDS USERNAME AND RECEIVES SERVER PUBLIC KEY
        2.USER SENDS HIS PUBLIC KEY
        3.SERVER SENDS USER'S CERTIFICATE TO USER

        '''
        done = False
        while not done:
            msg = client.recv(self.BUFSIZ)
            ctype, data = self.dec(msg)
            if ctype == 'USERNAME':
                self.clients[client].username = data
                logging.info(f'Username : {data} Received..')
            elif ctype == 'SENDPUBLIC':
                self.send_command(client,'PUBLIC')
                client.send(self.public_pem)
                logging.info(f'Public Key Sended to {self.clients[client].username}..')
                self.send_command(client,'SENDPUBLIC')
            elif ctype == 'PUBLIC':
                self.clients[client].public_pem = client.recv(self.BUFSIZ)
                self.clients[client].public_key = load_pem_public_key(self.clients[client].public_pem)
                logging.info(f'Public Key Received from {self.clients[client].username}')
                self.build_certificate(client)
                self.send_command(client,'CREATECERTIFICATE')
                client.send(self.clients[client].certificate_pem)
                logging.info(f'Certificate Sent to {self.clients[client].username}..')
                self.send_command(client,'DONE')
                done = True


    def user_selection(self,client):
        '''
        THIS PART IS FOR SHOWING ACTIVE USERS 
        (MULTIPLE CHATS ARE NOT WORKING AT THE MOMENT BUT THIS IS THE BEGGINING STAGE)
        '''
        done = False
        while not done:
            rdata = client.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            if ctype == 'USERLIST':
                for c in self.clients:
                    if c != client:
                        self.send_command(client,'USERS',self.clients[c].username)
                self.send_command(client,'LISTDONE')
                done = True
            logging.info(f'User List Sent to {self.clients[client].username}..')

    def users_handshake(self,client):
        '''
        USERS HANDSHAKE OVER SERVER
        (USER1: WHO SELECTS WHO TO CHAT)
        (USER2: SELECTED USER)
        1.USER1 SENDS HELLO and CERTIFICATE (CERTIFICATE SEND COMMAND WILL BE SENT FROM USER1, SERVER SENDING USER1's CERTIFICATE TO USER 2)
        2.USER2 WILL SEND NONCE AND HIS CERTIFICATE (SAME ABOVE)
        3.USER1 SIGNS NONCE AND SENDS TO USER2
        4.USER2 SENDS ACKNOWLEGMENT
        5.USER1 SENDS MASTER KEY
        '''
        done = False
        while not done:
            rdata = client.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            # logging.info(f'{self.clients[client].username} ctype: {ctype}')
            
            if ctype == 'HELLO':
                for c in self.clients:
                    if data == self.clients[c].username:
                        target_client = c
                self.send_command(target_client,'HELLO',self.clients[client].username)
                logging.info(f'HELLO Sent from {self.clients[client].username} to {self.clients[target_client].username}')

            elif ctype == 'SENDCERT':
                self.send_command(target_client,'TARGETCERT')
                sleep(0.001)
                target_client.send(self.clients[client].certificate_pem)
                logging.info(f'Certificate Sent from {self.clients[client].username} to {self.clients[target_client].username}')
            
            elif ctype == 'NONCE':
                target_user = data
                nonce = client.recv(self.BUFSIZ)
                nonce = nonce.decode('utf-8')
                for c in self.clients:
                    if self.clients[c].username == target_user:
                        target_client = c
                self.send_command(target_client,'TARGETNONCE',nonce)
                target_client.send(self.clients[client].certificate_pem)
                logging.info(f'Nonce transferred from {self.clients[client].username} to {self.clients[target_client].username}') 

            elif ctype == 'VERIFYNONCE':
                signonce = client.recv(self.BUFSIZ)
                self.send_command(target_client,'VERIFYNONCE')
                sleep(0.001)
                target_client.send(signonce)
                logging.info(f'Signed Nonce sent from {self.clients[client].username} to {self.clients[target_client].username}')

            elif ctype == 'NONCEVERIFIED':
                self.send_command(target_client,'NONCEVERIFIED')
                logging.info(f'Signed Nonce sent from {self.clients[client].username} to {self.clients[target_client].username}')

            elif ctype == 'MASTER':
                masterkey = client.recv(self.BUFSIZ)
                iv = client.recv(self.BUFSIZ)
                self.send_command(target_client,'MASTER')
                sleep(0.001)
                target_client.send(masterkey)
                sleep(0.001)
                target_client.send(iv)
                logging.info(f'Encrypted Master Sent to {self.clients[target_client].username}..')

            elif ctype == 'DONE':
                # logging.info(f'{self.clients[client].username}, DONE')
                done = True
                


    def build_certificate(self,client):
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.clients[client].username),]))
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.clients[client].username),]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.clients[client].public_key)
        self.clients[client].certificate = builder.sign(
            private_key=self.key, algorithm=hashes.SHA256(),
        )
        self.clients[client].certificate_pem = self.clients[client].certificate.public_bytes(serialization.Encoding.PEM)


    def receive(self,client):
        while True:
            rdata = client.recv(self.BUFSIZ)
            ctype, data = self.dec(rdata)
            if ctype == 'CLOSE':
                self.broadcast(f'SERVER/{data} is disconnected..'.encode('utf-8'))
                self.clients.pop(client)
                break
            elif ctype == 'MESSAGE':
                logging.info(f'Message received from {self.clients[client].username}..')
                username = data
                data = client.recv(self.BUFSIZ)
                data_len = client.recv(self.BUFSIZ)
                cmac = client.recv(self.BUFSIZ)
                self.broadcast_command('MESSAGE',username)
                sleep(0.001)
                self.broadcast(data)
                sleep(0.001)
                self.broadcast(data_len)
                sleep(0.001)
                self.broadcast(cmac)                

    def broadcast(self,data):
        logging.info('Sending Message..')
        for client in self.clients:
            # soc.send(bytes(data,'utf-8'))
            # username = self.clients[client][1]
            # logging.info(f'sending to {username}')
            client.send(data)

    def broadcast_command(self,command,data):
        for client in self.clients:
            self.send_command(client,command,data)

    def send_command(self,client,command,data=''):
        client.send(f'{command}[(///)]{data}'.encode('utf-8'))
        # sleep(0.3)

    def dec(self,data):
        return data.decode('utf-8').split('[(//)]')

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

class Client():
    def __init__(self) -> None:
        self.address = None
        self.username = None
        self.public_key = None
        self.public_pem = None
        self.certificate = None
        self.certificate_pem = None

if __name__ == '__main__':
    HOST = '0.0.0.0'
    PORT = 49565
    BUFSIZ = 2048
    ADDR = (HOST,PORT)
    soc = socket(AF_INET,SOCK_STREAM)
    soc.bind(ADDR)
    soc.listen(10)
    a = Server(soc,BUFSIZ)
    acpt = Thread(target=a.accept_conns)
    acpt.start()
    acpt.join()
    

