import shutil
import socket
import time

import tqdm
import os
from Record import Record
# from decrypt import Decrypt

# a list record the name of the file received
receivedFile = []

def cleanTem():
    shutil.rmtree('tem')
    os.mkdir('tem')
    receivedFile.clear()


from pgpy import PGPKey, PGPSignature

def verify():
    signature_in = receivedFile[0]
    plaintext_in = receivedFile[1]
    publickey_in = receivedFile[2]
    # signature_in = '../doc.txt.sig'
    # # same doc
    # plaintext_in = '../doc.txt'
    # # pgp private key
    # publickey_in = '../yw_public.pgp'

    # get key
    publickey = PGPKey()
    with open(publickey_in, "r") as certfile:
        publickey.parse(certfile.read())

    # get message
    with open(plaintext_in, "r") as plainfile:
        file_message = plainfile.read()

    # get signature
    signature = PGPSignature.from_file(signature_in)

    # verify
    verifications = publickey.verify(file_message, signature)
    for signature in verifications.good_signatures:
        if signature.verified:
            Record(signature_in, plaintext_in)
            print("Verified")
            time.sleep(0.5)
            cleanTem()






# device's IP address
SERVER_HOST = "localhost"
SERVER_PORT = 5001

# def receiveFile(SERVER_HOST, SERVER_PORT):
# receive 4096 bytes each time
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"



while True:
    try:
        os.mkdir('tem')
    except:pass
    if(len(receivedFile)>3):
        cleanTem()
        print("clean")

    # create the server socket
    # TCP socket
    s = socket.socket()


    # bind the socket to our local address
    s.bind((SERVER_HOST, SERVER_PORT))


    # enabling our server to accept connections
    # 5 here is the number of unaccepted connections that
    # the system will allow before refusing new connections
    s.listen(5)
    # print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")


    # accept connection if there is any
    client_socket, address = s.accept()
    # if below code is executed, that means the sender is connected
    # print(f"[+] {address} is connected.")


    # receive the file infos
    # receive using client socket, not server socket
    received = client_socket.recv(BUFFER_SIZE).decode()
    filename, filesize = received.split(SEPARATOR)
    # remove absolute path if there is
    filename = os.path.basename(filename)
    # convert to integer
    filesize = int(filesize)


    # start receiving the file from the socket
    # and writing to the file stream
    # progress = tqdm.tqdm()
    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    saveTo = 'tem/' +filename
    receivedFile.append(saveTo)
    with open(saveTo, "wb") as f:
        while True:
            # read 1024 bytes from the socket (receive)
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            f.write(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))

    time.sleep(0.1)
    # Decrypt(saveTo)

    try:
        verify()
    except:
        # print(receivedFile)
        pass

    # close the client socket
    client_socket.close()
    # close the server socket
    s.close()
