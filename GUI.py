#Imports
import tkinter as tk
from tkinter.filedialog import askopenfile
from future.moves.tkinter import filedialog
from pgpy import PGPKey, PGPMessage, PGPSignature
from client import sendFile


def selectPath():
    path = filedialog.askopenfilename()
    sendFile(path)

########## tkinter gui ##########
#Start of window
window = tk.Tk()

#Canvas to position widgets on
canvas = tk.Canvas(window, width=1300, height=1000)
canvas.grid(columnspan=40, rowspan=20) #Initalise canvas to 3 columns

#Record heading label
record_label = tk.Label(window, text="Record", font="Arial")
record_label.grid(columnspan=1, column=1, row=0)

#Divider
divider1_label = tk.Label(window, text="--------------------------------------------", font="Arial")
divider1_label.grid(columnspan=1, column=1, row=1)

#Upload document label
upload_document_label = tk.Label(window, text="(1) Upload document", font="Arial")
upload_document_label.grid(columnspan=1, column=1, row=2)

#Upload document button
upload_document_text = tk.StringVar()
upload_document_btn = tk.Button(window, textvariable=upload_document_text, font="Arial", bg="Blue", fg="White", command=lambda:open_doc_file())
upload_document_text.set("Upload")
upload_document_btn.grid(column=1, row=3)

#Input password label
input_key_passphrase_label = tk.Label(window, text="(2) Private key passphrase", font="Arial")
input_key_passphrase_label.grid(columnspan=1, column=1, row=4)

#Input password input box
input_key_passphrase = tk.Entry(window) 
input_key_passphrase.grid(column=1, row=5)

#Input filename label
input_filename_label = tk.Label(window, text="(3) Name of signed file to be", font="Arial")
input_filename_label.grid(columnspan=1, column=1, row=6)

#Input password input box
input_filename = tk.Entry(window) 
input_filename.grid(column=1, row=7)

#Sign signaure list label
sign_document_label = tk.Label(window, text="(4) Sign document", font="Arial")
sign_document_label.grid(columnspan=1, column=1, row=8)

#Sign signature list button
sign_document_text = tk.StringVar()
sign_document_btn = tk.Button(window, textvariable=sign_document_text, font="Arial", bg="Blue", fg="White", command=lambda:sign_document(input_key_passphrase.get()))
sign_document_text.set("Sign")
sign_document_btn.grid(column=1, row=9)

#Divider
divider2_label = tk.Label(window, text="--------------------------------------------", font="Arial")
divider2_label.grid(columnspan=1, column=1, row=10)

#Upload signature label
upload_sign_label = tk.Label(window, text="Manually upload signature for given document", font="Arial")
upload_sign_label.grid(columnspan=1, column=1, row=11)

#Upload signature button
upload_sign_text = tk.StringVar()
upload_sign_btn = tk.Button(window, textvariable=upload_sign_text, font="Arial", bg="Blue", fg="White", command=lambda:open_sign_file())
upload_sign_text.set("Upload")
upload_sign_btn.grid(column=1, row=12)



#Divider
divider3_label = tk.Label(window, text="--------------------------------------------", font="Arial")
divider3_label.grid(columnspan=1, column=1, row=13)

#Input password label
input_passphrase_label = tk.Label(window, text="(1) Private key passphrase", font="Arial")
input_passphrase_label.grid(columnspan=1, column=1, row=14)

#Input password input box
input_passphrase = tk.Entry(window) 
input_passphrase.grid(column=1, row=15)

#Input filename label
input_list_filename_label = tk.Label(window, text="(2) Name of signed file to be", font="Arial")
input_list_filename_label.grid(columnspan=1, column=1, row=16)

#Input password input box
input_list_filename = tk.Entry(window) 
input_list_filename.grid(column=1, row=17)

#Sign signaure list label
sign_signature_list_label = tk.Label(window, text="(3) Sign signature list", font="Arial")
sign_signature_list_label.grid(columnspan=1, column=1, row=18)

#Sign signature list button
sign_signature_list_text = tk.StringVar()
sign_signature_list_btn = tk.Button(window, textvariable=sign_signature_list_text, font="Arial", bg="Blue", fg="White", command=lambda:sign_signature_list(input_passphrase.get()))
sign_signature_list_text.set("Sign")
sign_signature_list_btn.grid(column=1, row=19)




#Verify label
verify_label = tk.Label(window, text="Verify", font="Arial")
verify_label.grid(columnspan=1, column=3, row=0)

#Divider
divider4_label = tk.Label(window, text="--------------------------------------------", font="Arial")
divider4_label.grid(columnspan=1, column=3, row=1)

#Check signature label
check_signature_label = tk.Label(window, text="Check signature", font="Arial")
check_signature_label.grid(columnspan=1, column=3, row=2)

#Check signature button
check_signature_text = tk.StringVar()
check_signature_btn = tk.Button(window, textvariable=check_signature_text, font="Arial", bg="Blue", fg="White", command=lambda:verify_signatures())
check_signature_text.set("Check")
check_signature_btn.grid(column=3, row=3)


# Signature status box
signature_status_box = tk.Text(window, height=1, width=30)
signature_status_box.grid(column=3, row=4)

#Generate Keys label
generate_keys_label = tk.Label(window, text="Generate Keys", font="Arial")
generate_keys_label.grid(columnspan=1, column=5, row=0)

#Divider
divider5_label = tk.Label(window, text="--------------------------------------------", font="Arial")
divider5_label.grid(columnspan=1, column=5, row=1)

#name label
name_label = tk.Label(window, text="name", font="Arial")
name_label.grid(columnspan=1, column=5, row=2)

#Input name input box
input_name = tk.Entry(window) 
input_name.grid(column=5, row=3)

#email label
email_label = tk.Label(window, text="email", font="Arial")
email_label.grid(columnspan=1, column=5, row=4)

#Input email input box
input_email = tk.Entry(window) 
input_email.grid(column=5, row=5)

#passphrase label
passphrase_keys_label = tk.Label(window, text="passphrase", font="Arial")
passphrase_keys_label.grid(columnspan=1, column=5, row=6)

#Input password input box
input_passphrase_keys = tk.Entry(window) 
input_passphrase_keys.grid(column=5, row=7)

#Client label
generate_keys_label = tk.Label(window, text="Client", font="Arial")
generate_keys_label.grid(columnspan=1, column=7, row=0)

#Divider
divider5_label = tk.Label(window, text="--------------------------------------------", font="Arial")
divider5_label.grid(columnspan=1, column=7, row=1)

#Signature file label
client_upload_signature_label = tk.Label(window, text="(1) Signature File", font="Arial")
client_upload_signature_label.grid(columnspan=1, column=7, row=2)

#Sign signature list button
client_upload_signature_text = tk.StringVar()
client_upload_signature_btn = tk.Button(window, textvariable=client_upload_signature_text, font="Arial", bg="Blue", fg="White", command=selectPath)
client_upload_signature_text.set("Upload Signature")
client_upload_signature_btn.grid(column=7, row=3)

#Plaintext document label
client_upload_document_label = tk.Label(window, text="(2) Plaintext Document", font="Arial")
client_upload_document_label.grid(columnspan=1, column=7, row=4)

#Plaintext document button
client_upload_document_text = tk.StringVar()
client_upload_document_btn = tk.Button(window, textvariable=client_upload_document_text, font="Arial", bg="Blue", fg="White", command=selectPath)
client_upload_document_text.set("Upload Document")
client_upload_document_btn.grid(column=7, row=5)

#Public key pgp label
client_public_key_label = tk.Label(window, text="(3) PGP Public Key", font="Arial")
client_public_key_label.grid(columnspan=1, column=7, row=6)

#Public key pgp button
client_public_key_text = tk.StringVar()
client_public_key_btn = tk.Button(window, textvariable=client_public_key_text, font="Arial", bg="Blue", fg="White", command=selectPath)
client_public_key_text.set("Upload PGP Public Key")
client_public_key_btn.grid(column=7, row=7)

# #Delete files label
# client_delete_files_label = tk.Label(window, text="(4) Delete Uploaded Files", font="Arial")
# client_delete_files_label.grid(columnspan=1, column=7, row=8)
#
# #Delete files button
# client_delete_files_text = tk.StringVar()
# client_delete_files_btn = tk.Button(window, textvariable=client_delete_files_text, font="Arial", bg="Blue", fg="White", command=clean)
# client_delete_files_text.set("Clear Cache")
# client_delete_files_btn.grid(column=7, row=9)

########## end tkinter gui ##########

signature_list = [] #List for storing signatures to file in
doc_and_signatures_dict = {} #Dictionary, key=filepath: value=signatures to that file

#Function for opening a signature file, user presses upload button and this function is called
def open_sign_file():
    file = askopenfile(parent=window, mode='rb', title="Select a signature file", filetype=[("Signature File", ".sig")])
    if file: #If the user chooses a file
        signature = PGPSignature.from_file(file.name) #Get the signature form the file
        signature_list.append(signature) #Add the signature to the signatures list
        save_file = open("doc.bin", "rb") #Save the file path to the bin so we can find it in the dictionary
        doc_path = save_file.read()
        save_file.close()
        doc_and_signatures_dict[doc_path] = signature_list #Update the signautre list value of the file in the dictionary
        print(doc_and_signatures_dict)


#Function for signing a given document
def sign_document(priv_passphrase): #Takes in user inputted password for the private key
    with open('doc.bin', "rb") as sigfile:
        doc_path = sigfile.name
        sigfile.close()

    #Prompt user to provide a private key
    with askopenfile(parent=window, mode='rb', title="Select a private key file", filetype=[("Private Key", ".gpg")]) as privatekeyfile:
        pkdata = privatekeyfile.read()
    privkey = PGPKey()
    privkey.parse(pkdata)

    message = PGPMessage.new(doc_path, file=True)
    with privkey.unlock(priv_passphrase): #Use the password on the private key
        signature = privkey.sign(message) #Sign the document
    
    with open(input_filename.get() + ".txt"+'.sig', "w") as sigfile:
        sigfile.write(str(signature))
        sigfile.close()
    

# def open_cer_file():
#     file = askopenfile(parent=window, mode='rb', title="Select a certificate file", filetype=[("Certificate File", ".cer")])
#     if file:
#         if display_box.index("end")!=0:
#             display_box.delete("1.0", tk.END)
#         certdata = file.read()
#         certificate = x509.load_pem_x509_certificate(certdata)
#         display_box.insert(2.0, str(certificate.version) + " Valid: " + str(certificate.not_valid_before) + " until " + str(certificate.not_valid_after) + "\nissuer:" + str(certificate.issuer) + "\nsubject:" + str(certificate.subject))
#         print(str(certificate.version))
#         print("Valid: " + str(certificate.not_valid_before), end='')
#         print(" until " + str(certificate.not_valid_after))
#         print("issuer:" + str(certificate.issuer))
#         print("subject:" + str(certificate.subject))

# def print_pem(cert_bytes):
#     cert_string=""
#     display_box.insert(2.0, "-----BEGIN CERTIFICATE-----\n")
#     print("-----BEGIN CERTIFICATE-----")
#     encoded = base64.b64encode(cert_bytes).decode('ascii')
#     wrapped = textwrap.wrap(encoded, 76)
#     for line in wrapped:
#         cert_string+=line
#     display_box.insert(2.0, "-----END CERTIFICATE-----")
#     print("-----END CERTIFICATE-----")
#     print(cert_string)

#Method for opening a document file
def open_doc_file():
    doc_path = "" #Clear the path
    file = askopenfile(parent=window, mode='rb', title="Select a document file", filetype=[("File", "")]) #Prompt user to choose file to upload documenmts for
    if file: #If they choose a file rather than cancelling
        doc_path = file.name
        save_file = open("doc.bin", "a")
        save_file.truncate(0) #Clear the save file to allow for new document path
        save_file.write(doc_path) #Update the doc.bin to have the new document path
        save_file.close()
        doc_and_signatures_dict[doc_path] = signature_list #Add the document path to the dictionary



pub_key=[]
signature_to_verify = ""

#Function for getting the public key from the user
def get_publickey():
    publickey = PGPKey()
    with askopenfile(parent=window, mode='rb', title="Select a key file", filetype=[("Public key file", ".gpg")]) as certfile:
        pub_key.append(publickey.parse(certfile.read())) #Store the public key in the public key list


#Function for verifying the provided signature of a document
def verify_signatures():
    file = askopenfile(parent=window, mode='rb', title="Select a signature file", filetype=[("Signature File", ".sig")])
    if file:
        signature_to_verify = PGPSignature.from_file(file.name)
        publickey = PGPKey()
        with askopenfile(parent=window, mode='rb', title="Select a key file", filetype=[("Public key file", ".gpg")]) as certfile:
            publickey.parse(certfile.read())
        with open('signature_list.txt', "rb") as plainfile:
            file_message = plainfile.read() #Read the text file
        verifications = publickey.verify(file_message, signature_to_verify) #Verify whether the signature provided is in the signature list
        signature_status_box.delete("1.0", tk.END) #Clear the status box to allow for new status
        for signature_to_verify in verifications.good_signatures:
            if signature_to_verify.verified:
                signature_status_box.insert(1.0, "Verified") #Good signature case
                print("Verified")
            else:
                signature_status_box.insert(1.0, "Not Verified") #Bad signature case
                print("Not Verified!")

#Function for signing the list of signatures
def sign_signature_list(priv_passphrase): #Takes password for private key as only arg
    with askopenfile(parent=window, mode='rb', title="Select a key file", filetype=[("Private Key", ".gpg")]) as privatekeyfile:
        pkdata = privatekeyfile.read()
    privkey = PGPKey()
    privkey.parse(pkdata)

    save_file = open("signature_list.txt", "a") #Open the list to read from

    for signature in signature_list:
        save_file.write(str(signature) + "\n") #Write the signatures to a new file
    save_file.close()

    message = PGPMessage.new("signature_list.txt", file=True)
    with privkey.unlock(priv_passphrase):
        signature = privkey.sign(message) #Sign the new file of signatures
    
    with open("signature_list.txt"+'.sig', "w") as sigfile:
        sigfile.write(str(signature))



window.mainloop()
#End of window
