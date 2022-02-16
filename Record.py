import hashlib
from OpenSSL import crypto
from pgpy import PGPKey, PGPMessage, PGPSignature
import pickle

cert_store = crypto.X509Store()

# Check whether the files are the same
def CalcSha1(filepath):
    with open(filepath,'rb') as f:
        sha1obj = hashlib.sha1()
        sha1obj.update(f.read())
        hash = sha1obj.hexdigest()
        # print(hash)
        return hash



# def Record(pgpSign, docpath, pubKey):
def Record(pgpSign, docpath):
    '''
    add signature to Signatories
    :param pgpSign:
    :param docpath:
    :return:
    '''
    try:
        load_file = open("signatories.bin", "rb")
        signatures = pickle.load(load_file)
    except:
        signatures = {}

    doc = CalcSha1(docpath)
    signature = PGPSignature.from_file(pgpSign)

    print("sha1: "+doc)
    # signaturesList = []
    try:
        signaturesList = signatures[doc]
        # print('this doc exist, add to sig list')
        # print(signaturesList)
        signaturesList.append(signature)
        signatures[doc] = signaturesList
    except:
        # print("this doc doesn't exist, create a new sig list")
        signaturesList = [signature]
        signatures[doc] = signaturesList
        # print('add success!')

    save_file = open("signatories.bin", "wb")
    pickle.dump(signatures, save_file)
    save_file.close()

    showSignaturesList(signatures)

# issue an X.509 signed list of the signatories of the document.
def showSignaturesList(signatures):
    print('have following doc: ')
    for key in signatures:
        print(key)




if __name__ == '__main__':
    Record('../doc.txt.sig', '../doc.txt')


