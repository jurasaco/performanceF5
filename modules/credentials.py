import base64
import csv
import os
import getpass
import appdirs
import hashlib

from termcolor import colored
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def readDevicesFile(filePath,useKeyFile=False):
    encIdStr='$256$64$' #sha256,base64
    strOk=colored('OK','green')
    strErr=colored('ERROR','red')
    if not os.path.exists(filePath):
        print(f"{strErr}: Device file {filePath} doesn't exists.")
        return None

 
    if useKeyFile :
        masterKey=getMasterKey(filePath)
        if masterKey==None:
            #el master key file no existe aun asi es que necesitamos que el usuario la ingrese para crearlo
            encryptionPassword = getpass.getpass(prompt='Enter encryption password: ')
            encryptionPasswordConfirm = getpass.getpass(prompt='Confirm encryption password: ')
        else:
            #el master key file existe lo asignamos a las password para no afectar el resto de la logica
            encryptionPassword = masterKey
            encryptionPasswordConfirm = masterKey
    else:
        #no usamos el archivo de master key se lo pedimos al usuario
        encryptionPassword = getpass.getpass(prompt='Enter encryption password: ')
        encryptionPasswordConfirm = getpass.getpass(prompt='Confirm encryption password: ')

    if encryptionPassword != encryptionPasswordConfirm:
        print(f"{strErr}: Encryption passwords doesn't match.")
        return None
    if len(encryptionPassword)<5:
        print(f"{strErr}: Encryption password minimum length is 6 characters.")
        return None
    
    devices=[]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'0123456789abcdef',
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encryptionPassword.encode()))
    f = Fernet(key)
    #token = f.encrypt(b"welcome to geeksforgeeks")
    #d = f.decrypt(token)
    print(f"Reading device file {filePath}...",end="")
    file=open(filePath, 'r')
    lines=file.readlines()
    print(strOk)
    updateFile=False
    for device in csv.reader(lines, quotechar='"', delimiter=',', quoting=csv.QUOTE_ALL, skipinitialspace=True):
        if len(device)==0:
            continue
        if len(device)!=3:
            print('Invalid line format. It must be "<ip|fqdn>","<username>","<plaintext_password|encrypted_password>"')
            continue
        (host,username,password)=device
    
        if encIdStr==password[:len(encIdStr)]:
            print(f"Decrypting password for {username}@{host}")
            passwordEE=password
            try:
                password=f.decrypt(base64.urlsafe_b64decode(passwordEE[len(encIdStr):])).decode()
            except :
                print(f'{strErr}: Something went wrong decoding the password for {username}@{host}. Bad encryption password?')
                continue
        else:
            print(f"Encrypting password for {username}@{host}")
            updateFile=True
            passwordEE=encIdStr+base64.urlsafe_b64encode(f.encrypt(password.encode())).decode()
        devices.append({'host':host,'username':username,'password':password,'passwordEE':passwordEE})
    file.close()
    #print(json.dumps(devices,indent=2))
    if useKeyFile:
        #si llegamos a estepunto ya desencriptamos las credenciales, entonces guardamos la mas master key aka encryptionPassword
        saveMasterKey(filePath,encryptionPassword)
    if updateFile:
        print(f"Updating {filePath} with encrypted passwords...",end="")
        file=open(filePath,'w')
        fileContent=""
        for device in devices:
            fileContent+=f"\"{device['host']}\",\"{device['username']}\",\"{device['passwordEE']}\"\n"
        file.write(fileContent)
        file.close()
        print(strOk)
    return devices

def getMasterKey(filePath):
    filePath=os.path.abspath(filePath)
    appDataFolder=appdirs.user_data_dir("perfF5")
    masterKeyFileName = f".{hashlib.sha256(filePath.encode()).hexdigest()}"
    masterKeyFilePath = os.path.join(appDataFolder, masterKeyFileName)
    if not os.path.exists(masterKeyFilePath):
        print(f"Master Key file {masterKeyFileName} doesn't exists.")
        return None
    with open(masterKeyFilePath,'r') as f:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'pfF5obfusc230303',
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive("pfF5.obfuscation.key".encode()))
        fNet = Fernet(key)
        masterKey = fNet.decrypt(base64.urlsafe_b64decode(f.read())).decode()
    return masterKey
    
def saveMasterKey(filePath,masterKey):
    filePath=os.path.abspath(filePath)
    appDataFolder=appdirs.user_data_dir("perfF5")
    os.makedirs(appDataFolder, exist_ok=True)
    masterKeyFileName = f".{hashlib.sha256(filePath.encode()).hexdigest()}"
    masterKeyFilePath = os.path.join(appDataFolder, masterKeyFileName)
    print(f"Updating master Key file {masterKeyFileName}.")
    with open(masterKeyFilePath,'w') as f:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'pfF5obfusc230303',
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive("pfF5.obfuscation.key".encode()))
        fNet = Fernet(key)
        f.write(base64.urlsafe_b64encode(fNet.encrypt(masterKey.encode())).decode())

