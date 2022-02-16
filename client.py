
import socket
import time
import shutil
import tqdm
import os
# from crypt import Cyrpt

host = '127.0.0.1'  # or 'localhost'
port = 5001

# tcpCliSock = socket(AF_INET, SOCK_STREAM)




# signature from sign
signature_in = 'doc.txt.sig'
# same doc
plaintext_in = 'doc.txt'
# pgp private key
publickey_in = 'yw_public.pgp'



# start sending the file
def sendFile(filename):
    # receive 4096 bytes each time
    BUFFER_SIZE = 4096
    SEPARATOR = "<SEPARATOR>"

    # Cyrpt(filename)

    # get the file size
    filesize = os.path.getsize(filename)


    # create the client socket
    s = socket.socket()


    print(f"[+] Connecting to {host}:{port}")
    s.connect((host, port))
    print("[+] Connected.")


    # send the filename and filesize
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())


    # start sending the file
    progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                # file transmitting is done
                break
            # we use sendall to assure transimission in
            # busy networks
            s.sendall(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))

    # close the socket

    s.close()


def sendSig():
    sendFile(signature_in)
    time.sleep(1)
    sendFile(plaintext_in)
    time.sleep(1)
    sendFile(publickey_in)


def checkvaild():
    pass
    # try:
    #     data1 = s.recv(BUFFER_SIZE)
    #     print(data1.decode('utf-8'))
    #
    # except:
    #     pass


if __name__ == '__main__':
    sendSig()
    time.sleep(1)
    # shutil.rmtree('server/tem', ignore_errors=True)
    # os.mkdir('server/tem')