from tkinter import messagebox
from tkinter import *
from tkinter import simpledialog
import tkinter
from tkinter import filedialog
from tkinter.filedialog import askopenfilename
import matplotlib.pyplot as plt
import pyaes, pbkdf2, binascii, os, secrets
import base64
import timeit
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
import pickle
import socket
import json
from tkinter import messagebox
import numpy as np

main = tkinter.Tk()
main.title("Security using Elliptic Curve Cryptography (ECC) in Cloud") #designing main screen
main.geometry("1300x1200")

global filename
execution_time = []
global data
global secret_key, private_key, public_key

def getAESKey(): #generating key with PBKDF2 for AES
    password = "s3cr3t*c0d3"
    passwordSalt = '76895'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

def encryptAES(plaintext): #AES data encryption
    aes = pyaes.AESModeOfOperationCTR(getAESKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decryptAES(self,enc): #AES data decryption
    aes = pyaes.AESModeOfOperationCTR(getAESKey(), pyaes.Counter(31129547035000047302952433967654195398124239844566322884172163637846056248223))
    decrypted = aes.decrypt(enc)
    return decrypted

def upload(): #function to upload tweeter profile
    global filename
    global data
    filename = filedialog.askopenfilename(initialdir="Dataset")
    text.delete('1.0', END)
    text.insert(END,filename+" loaded\n\n");
    fout = open(filename, 'rb')
    data = fout.read()
    fout.close()
    text.insert(END,str(data))
    
def AESEncrypt():
    global data
    text.delete('1.0', END)
    start = timeit.default_timer()
    encrypted_data = encryptAES(str(base64.b64encode(data),'utf-8'))
    end = timeit.default_timer()
    aes_time = end - start
    execution_time.append(aes_time)
    text.insert(END,"AES encryption time: "+str(aes_time)+"\n\n")
    text.insert(END,"AES Encrypted Data: "+str(encrypted_data)+"\n\n")
    

#function to generate ECC public, private and secret keys
def generateKeys():
    global secret_key, private_key, public_key
    if os.path.exists('public.pckl'):
        f = open('public.pckl', 'rb')
        public_key = pickle.load(f)
        f.close()
        f = open('private.pckl', 'rb')
        private_key = pickle.load(f)
        f.close()
    else:
        secret_key = generate_eth_key()
        private_key = secret_key.to_hex()  # hex string
        public_key = secret_key.public_key.to_hex()
        f = open('public.pckl', 'wb')
        pickle.dump(public_key, f)
        f.close()
        f = open('private.pckl', 'wb')
        pickle.dump(private_key, f)
        f.close()

def ECCEncrypt(): #ECC data encryption
    global data
    global secret_key, private_key, public_key
    text.delete('1.0', END)
    start = timeit.default_timer()
    generateKeys()
    data = encrypt(public_key, data)
    end = timeit.default_timer()
    ecc_time = end - start
    execution_time.append(ecc_time)
    text.insert(END,"ECC encryption time: "+str(ecc_time)+"\n\n")
    text.insert(END,"ECC Encrypted Data: "+str(data)+"\n\n")


def outsourceFile():
    global filename
    global data
    text.delete('1.0', END)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    client.connect(('localhost', 2222))
    features = []
    features.append("upload")
    features.append(os.path.basename(filename))
    features.append(data)
    features = pickle.dumps(features)
    client.send(features) #now sending encrypted file data to cloud
    data = client.recv(10000)#now receive response from cloud
    data = pickle.loads(data)
    data = data[0]
    text.insert(END,data+"\n")



def downloadFile():
    text.delete('1.0', END)
    fname = simpledialog.askstring(title = "Enter filename to download", prompt = "Enter filename to download")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    client.connect(('localhost', 2222))
    features = []
    features.append("download")
    features.append(fname)
    features = pickle.dumps(features)
    client.send(features) #now sending features to cloud
    data = client.recv(10000)#now receive labels from cloud after clustering
    data = pickle.loads(data)
    data = data[0]
    decryptData = decrypt(private_key, data)
    fout = open(fname, 'wb')
    fout.write(decryptData)
    fout.close()
    text.insert(END,"file downloaded and saved inside "+fname+"\n")

def graph():
    height = execution_time
    bars = ('AES Encryption Time','ECC Encryption Time')
    y_pos = np.arange(len(bars))
    plt.bar(y_pos, height)
    plt.xticks(y_pos, bars)
    plt.title("AES VS ECC Encryption Time Graph")
    plt.show()


font = ('times', 16, 'bold')
title = Label(main, text='Security using Elliptic Curve Cryptography (ECC) in Cloud')
title.config(bg='darkviolet', fg='gold')  
title.config(font=font)           
title.config(height=3, width=120)       
title.place(x=0,y=5)

font1 = ('times', 12, 'bold')
text=Text(main,height=20,width=150)
scroll=Scrollbar(text)
text.configure(yscrollcommand=scroll.set)
text.place(x=50,y=120)
text.config(font=font1)


font1 = ('times', 12, 'bold')
uploadButton = Button(main, text="Upload File", command=upload)
uploadButton.place(x=50,y=550)
uploadButton.config(font=font1)  

aesButton = Button(main, text="Encrypt File Using AES", command=AESEncrypt)
aesButton.place(x=430,y=550)
aesButton.config(font=font1) 

eccButton = Button(main, text="Encrypt File Using ECC", command=ECCEncrypt)
eccButton.place(x=50,y=600)
eccButton.config(font=font1) 

outsourceButton = Button(main, text="Outsource File to Cloud", command=outsourceFile)
outsourceButton.place(x=430,y=600)
outsourceButton.config(font=font1)

downloadButton = Button(main, text="Download File", command=downloadFile)
downloadButton.place(x=50,y=650)
downloadButton.config(font=font1)

graphButton = Button(main, text="Comparison Graph", command=graph)
graphButton.place(x=430,y=650)
graphButton.config(font=font1)

main.config(bg='sea green')
main.mainloop()
