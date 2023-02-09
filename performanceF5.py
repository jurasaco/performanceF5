#!/usr/bin/env python3.9
from paramiko import SSHClient, AutoAddPolicy
from datetime import datetime
from datetime import date
from datetime import timedelta
from termcolor import colored
import argparse
import re
import uuid
import sys
import getpass
import json
import os
import stat
import base64
import colorama #for windows terminal colors
import csv

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

colorama.init()
__version__='1.2.0' #mayor(breaking changes).minor(new features).patch(fixes)
#import logging

#logging.basicConfig()
#logging.getLogger("paramiko").setLevel(logging.DEBUG) # for example

workingDir = "f5Reports/"
def convert_bps(size):
    for x in ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0
    return "%.1f Pbps" % (size / 1024)

def convert_bytes(size):
    for x in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0
    return "%.1f PB" % (size / 1024)

def readDevicesFile(filePath):

    encIdStr='$256$64$' #sha256,base64
    strOk=colored('OK','green')
    strErr=colored('ERROR','red')
    encryptionPassword = getpass.getpass(prompt='Enter encryption password: ')
    encryptionPasswordConfirm = getpass.getpass(prompt='Confirm encryption password: ')

    if encryptionPassword != encryptionPasswordConfirm:
        print(f"{strErr}: Encryption passwords doesn't match.")
        return None
    if len(encryptionPassword)<5:
        print(f"{strErr}: Encryption password minimum length is 6 characters.")
        return None
    if not os.path.exists(filePath):
        print(f"{strErr}: Device file {filePath} doesn't exists.")
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

def getLtmLogsStats(ltmLogs):
    ltmLogStats=[]
    return ltmLogStats
def imgToBase64ForHtml(image):
    return  base64.b64encode(open(image, 'rb').read()).decode() 
def generateHtmlReport(devicesInfo):
    if not len(devicesInfo) > 0: 
        print(colored("Empty device performance dictionary. The report was not generated.",'yellow'))
        return None
    strOk=colored('OK','green')
    strErr=colored('STDERR','red')
    css="""
    <style> 
   body {font-style: normal; font-family: Arial, Helvetica, sans-serif  ; font-size: 11pt;}
    span.subtitle {font-size: 12pt; font-weight: bold;}
    span.subtitle2 {font-size: 11pt; font-weight: bold;}
    table, table td , table th { border: 1px solid black; border-collapse: collapse; padding: 2px; font-family: Arial, Helvetica, sans-serif  ; font-size: 8pt;} 
    table.overview { width: 16.5cm; margin-left: auto; margin-right: auto;}
    table.overview > thead > tr > th {min-width: 50px; background-color: rgb(49, 96, 183);color: white; font-size: 8pt;}
    table.overview > thead > tr > th:nth-child(1){width: 60px;}
    table.overview > thead > tr > th:nth-child(2){width: 150px;}
    table.overview > thead > tr > th:nth-child(3){width: 60px;}
    table.overview > thead > tr > th:nth-child(4){width: 110px;}
    table.overview > thead > tr > th:nth-child(5){width: 100px;}
    table.overview > thead > tr > th:nth-child(6){width: 60px;}
    table.overview > thead > tr > th:nth-child(7){width: 50px;}
    table.overview > thead > tr > th:nth-child(8){width: 50px;}
    table.overview > thead > tr > th:nth-child(9){width: 50px;}
    table.overview > thead > tr > th:nth-child(10){width: 50px;}

    table.overview > tbody > tr > td {min-width: 50px; font-size: 8pt;}
    table.overview > tbody > tr > td:nth-child(1){text-align: center;}
    table.overview > tbody > tr > td:nth-child(2){text-align: left;}
    table.overview > tbody > tr > td:nth-child(3){text-align: center;}
    table.overview > tbody > tr > td:nth-child(4){text-align: center;}
    table.overview > tbody > tr > td:nth-child(5){text-align: center;}
    table.overview > tbody > tr > td:nth-child(6){text-align: center;}
    table.overview > tbody > tr > td:nth-child(7){text-align: center;}
    table.overview > tbody > tr > td:nth-child(8){text-align: center;}
    table.overview > tbody > tr > td:nth-child(9){text-align: center;}
    table.overview > tbody > tr > td:nth-child(10){text-align: center;}

    p.perfGraphContents1 { margin-left: 0cm;  }
    p.perfGraphContents2 { margin-left: 1cm;  }
    p.perfGraphContents3 { margin-left: 2cm;  }
    page {
        background: white;
        display: block;
        margin: 0 auto;
        margin-bottom: 0.5cm;
        box-shadow: 0 0 0.5cm rgba(0,0,0,0.5);
        padding: 1cm 2.5cm 1cm 2.5cm;
        
    }
    page[size="A4"] {  
        width: 166mm; /* 21.6cm - 2.5cm x 2 */
    }
    img.graph {
        width: 16.5cm;display: block;margin: 0 auto;
    }
    @media print {

        page {
            background: white;
            display: block;
            margin: 0 auto;
            box-shadow: none;
            padding: 1cm 2.5cm 1cm 2.5cm;
        }

    }
    </style>
    """
    html=""
    deviceInfoHtml=""
    deviceInfoHtmlOverview=""
    print("Generating HTML report...")
    for deviceIp,deviceInfo in devicesInfo.items():
        print(f'{" "*1}Converting {deviceIp} information to html...')
        #print(json.dumps(deviceInfo, indent=2,default=str))
        deviceInfoHtml+=f"""
        <p class=perfGraphContents1>
        <span class=subtitle >Gráficos de rendimiento {deviceInfo['hostname']}</span>
        </p>
        <p class=perfGraphContents2>
        Periodo {deviceInfo['rangeStart']} - {deviceInfo['rangeEnd']}.
        </p>     
        """
        for graph in deviceInfo['graphs']:
            maxValueInfo=[]
            for serie in graph['series']:
                if 'format-values' in serie and not serie['format-values']==None:
                    maxValueInfo.append(f"{serie['label']} = {serie['format-values'](int(serie['maxValue']))}")
                else:
                    maxValueInfo.append(f"{serie['label']} = {serie['maxValue']}")
            maxValueInfoStr=f'Valores máximos del periodo: {", ".join(maxValueInfo)}.'
            deviceInfoHtml+=f"""
        <p class=perfGraphContents2>
        <span class=subtitle2 >{graph['title']}</span>
        </p>
        <p class=perfGraphContents3 >
        {maxValueInfoStr}
        </p>
        <p class=perfGraphContents1 style="text-align:center">
        <img width=605 height=179 src="data:image/png;base64,{imgToBase64ForHtml(graph['filename'])}" class=graph >
        </p>
        <br>
        """
            os.remove(graph['filename']) 
        deviceInfoHtmlOverview+=f"""
        <tr>
            <td>{deviceInfo['failoverStatus']}</td>
            <td>{deviceInfo['hostname']}</td>
            <td>{deviceInfo['tmosVersion']}</td>
            <td>{deviceInfo['sysManagementIp']}</td>
            <td>{", ".join(map(lambda tuple : tuple[0], deviceInfo['sysProvision']))}</td>
            <td>{deviceInfo['sysUptime']}</td>
            <td>{deviceInfo['ltmLogs']}</td>
            <td>{deviceInfo['syncStatus'][0][1]}</td>
            <td>{deviceInfo['sysPlatformName']}</td>
            <td>{deviceInfo['sysChassisSerial']}</td>            
        </tr>
        """
    deviceInfoHtml+="""
    """
    deviceInfoHtmlOverview=f"""
    <p class=perfGraphContents1>
    <span class=subtitle >Visión general</span>
    </p>
    <p class=perfGraphContents2 >
    Periodo {deviceInfo['rangeStart']} - {deviceInfo['rangeEnd']}.
    </p>
    <p class=perfGraphContents1 style="text-align:center" >
        <table class=overview >
        <thead>
            <tr>
                <th style="color: white;background-color: rgb(49, 96, 183);" >Estado</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Nombre de host</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Versión TMOS</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Dirección IP</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Provisión</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Uptime</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Logs<br>> Warn </th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Sincro.</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Plataforma.</th>
                <th style="color: white;background-color: rgb(49, 96, 183);">Serial.</th>
            </tr>
        </thead>
        <tbody>
        {deviceInfoHtmlOverview}
        </tbody>
        </table>
    </p>
    """
    html=f"""
    
    <html>
    <head>
        <meta http-equiv="content-type" content="text/html;charset=utf-8" />    
    {css}
    </head>
    <body>
    <page size="A4">
    {deviceInfoHtmlOverview}
    <br>
    {deviceInfoHtml}
    </page>
    </body>
    </html>
    """
    nowStr=datetime.today().strftime('%Y%m%d%H%M%S')
    reportFileOutput=f'{workingDir}{args.name}_{nowStr}.html'
    print(f'{" "*1}Saving report to {reportFileOutput}...',end='',flush=True)
    with open(reportFileOutput, 'w',encoding='utf-8') as file:
        file.write(html)
    print(strOk)
    return True
def rrdtoolCmd(rrdGraph,rrdRange,remoteTmpPath):
    cmd = f"rrdtool graph {remoteTmpPath}{rrdGraph['filename']} -D -w 909 -h 269 --font DEFAULT:11: " \
    f"--start {rrdRange['start']} --end {rrdRange['end']}  "
    if 'x-grid' in rrdRange:
        cmd+=f"--x-grid \"{rrdRange['x-grid']}\" "
    if 'lower-limit' in rrdGraph:
        cmd+=f"-l {rrdGraph['lower-limit']} "
    if 'upper-limit' in rrdGraph:
        cmd+=f"-u {rrdGraph['upper-limit']} "
    #if 'lower-limit' in rrdGraph or 'upper-limit' in rrdGraph:
    #    cmd+=f"-r "
    if 'base' in rrdGraph:
        cmd+=f"--base \"{rrdGraph['base']}\" "
    cmd+=f'-v "{rrdGraph["vertical-label"]}" '
    for serie in rrdGraph['series']:
        cmd += f"DEF:{serie['name']}={serie['rrd']}:{serie['name']}:{serie['cf']} "
        suffix=''
        if 'bytestobits' in serie:
            cmd += f"CDEF:{serie['name']}bits={serie['name']},8,* "
            suffix='bits'
        cmd += f"LINE1:{serie['name']}{suffix}{serie['color']}:\"{serie['label']}\" "
    return cmd

def rddtoolMaxCmd(serie,rrdRange):
    #print(serie)
    cmd="rrdtool graph /var/tmp/borrame.png " \
        f"--start {rrdRange['start']} --end {rrdRange['end']} " \
        f"DEF:{serie['name']}={serie['rrd']}:{serie['name']}:{serie['cf']} "
    suffix=''
    if 'bytestobits' in serie:
            cmd += f"CDEF:{serie['name']}bits={serie['name']},8,* "
            suffix='bits'
    cmd+=f"VDEF:max={serie['name']}{suffix},MAXIMUM PRINT:max:\"%.0lf\""
    return cmd
def split(string):
    return [s.strip() for s in string.split(',')]


def getPerformanceReport(bigipIpAddress, bigipUsername, bigipPassword,rrdGraphs,rrdRange,remoteTmpPath):
    strOk=colored('OK','green')
    strErr=colored('STDERR','red')
    deviceInfo={}
    deviceInfo['rangeStart']=datetime.fromtimestamp( rrdRange['start'] )
    deviceInfo['rangeEnd']=datetime.fromtimestamp( rrdRange['end'] )
    if not os.path.exists(workingDir):
        os.makedirs(workingDir)
    print('Connecting to {}...'.format(bigipIpAddress),end='',flush=True)
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())

    # DateTime=datetime.today().strftime('%Y%m%d%H%M%S')
    try:
        client.connect(bigipIpAddress, username=bigipUsername,
                       password=bigipPassword, timeout=10)
    except Exception as err:
        print(colored(f"Unexpected {err=}, {type(err)=}",'red'))
        print(colored(f"Wrong password for user {bigipUsername} at {bigipIpAddress}?",'red'))
        return None
    print(strOk)
    print('Getting hostname...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command("echo $HOSTNAME")
    if stdout.channel.recv_exit_status() == 0:
        remoteHostName = stdout.read().decode("utf8").strip()
        print(remoteHostName + ' '+ strOk)
        deviceInfo['hostname']=remoteHostName
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None
    print('Getting tmos version...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command("tmsh show sys version  | grep \" Version\"")
    if stdout.channel.recv_exit_status() == 0:
        remoteHostTmosVersion = stdout.read().decode("utf8").replace('Version','').strip()
        print(remoteHostTmosVersion + ' '+ strOk)
        deviceInfo['tmosVersion']=remoteHostTmosVersion
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None
    print('Getting hardware information...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command("tmsh show sys hardware | grep -A20 Platform")
    if stdout.channel.recv_exit_status() == 0:
        execCommandOutput=stdout.read().decode("utf8")
        sysPlatformName=re.search(r'Name\s+(.+)', execCommandOutput ).group(1)
        sysChassisSerial=re.search(r'Chassis Serial\s+(.+)', execCommandOutput ).group(1)
        print(sysPlatformName + ' ' + sysChassisSerial + ' ' + strOk)
        deviceInfo['sysPlatformName']=sysPlatformName
        deviceInfo['sysChassisSerial']=sysChassisSerial
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None   
    #viprions bug tmsh list sys management-ip returns empty
    print('Getting management ip address...',end='',flush=True)
    #stdin, stdout, stderr = client.exec_command("tmsh list sys management-ip  | grep \"sys management-ip\"")
    stdin, stdout, stderr = client.exec_command('ip address show mgmt | grep " inet "')
    if stdout.channel.recv_exit_status() == 0:
        sysManagementIp = re.search(r'\d+\.\d+\.\d+\.\d+\/\d+', stdout.read().decode("utf8")).group()       
        print(sysManagementIp + ' '+ strOk)
        deviceInfo['sysManagementIp']=sysManagementIp
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None
    print('Getting provisioned modules list...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command("tmsh list sys provision one-line | grep level ")
    if stdout.channel.recv_exit_status() == 0:
        sysProvision=re.findall(r'sys provision (.+) { level (.+) }', stdout.read().decode("utf8"))
        sysProvisionStr = ", ".join(map(lambda tuple : "=".join(tuple), sysProvision))
        print(sysProvisionStr + ' '+ strOk)
        deviceInfo['sysProvision']=sysProvision
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None   
    print('Getting failover status...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command("tmsh show cm failover-status | grep \"Status  \"")
    if stdout.channel.recv_exit_status() == 0:
        failoverStatus = stdout.read().decode("utf8").replace('Status','').strip()
        print(failoverStatus + ' '+ strOk)
        deviceInfo['failoverStatus']=failoverStatus
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None
    print('Getting sync status...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command("tmsh show cm sync-status")
    if stdout.channel.recv_exit_status() == 0:
        syncStatus=re.findall(r'^(Status|Mode)\s+(.+)$', stdout.read().decode("utf8"),re.MULTILINE)
        syncStatusStr = ", ".join(map(lambda tuple : "=".join(tuple), syncStatus))
        print(syncStatusStr + ' '+ strOk)
        deviceInfo['syncStatus']=syncStatus
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None   
    print('Getting ltm logs...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command('ls -r /var/log/ltm.*.gz | xargs -n 1 zcat | cat - /var/log/ltm.1 /var/log/ltm | grep -P " (warning|err|crit|alert|emerg) " || [[ $? == 1 ]]',get_pty=True,timeout=120)
    #workaorund para salidas de comando muy grandes, sino se lee antes de revisar el exit status, el buffer se llena.
    ltmLogs = stdout.read().decode("utf8")
    if stdout.channel.recv_exit_status() == 0:
        print( str(ltmLogs.count('\n')) + ' records '+ strOk)
        deviceInfo['ltmLogs']=str(ltmLogs.count('\n'))
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None
    print('Getting system uptime...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command('awk \'{m=$1/60; h=m/60; printf "%sd %sh %sm\\n", int(h/24), int(h%24), int(m%60), int($1%60) }\' /proc/uptime')
    if stdout.channel.recv_exit_status() == 0:
        sysUptime = stdout.read().decode("utf8").strip()
        print(sysUptime + ' '+ strOk)
        deviceInfo['sysUptime']=sysUptime
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None

    print(f'Creating remote tmp directory {remoteTmpPath}...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command(f'mkdir -p {remoteTmpPath}')
    if stdout.channel.recv_exit_status() == 0:
        print(strOk)
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None

    print('Generating graphs and stats...',datetime.fromtimestamp( rrdRange['start'] ),'->',datetime.fromtimestamp( rrdRange['end'] ))
    deviceInfo['graphs']=[]
    
    for rrdGraph in rrdGraphs:
        #print('Convertiong dict to rrdtool command...',end='',flush=True)
        cmd=rrdtoolCmd(rrdGraph,rrdRange,remoteTmpPath)
        #print(strOk)
        #print(cmd)
        graphInfo={}
        stdin, stdout, stderr = client.exec_command(cmd)
        graphInfo['title']=rrdGraph['title']
        
        if stdout.channel.recv_exit_status() == 0:
            result = stdout.read().decode("utf8").strip()
            print(f"Graph '{rrdGraph['title']}' {rrdGraph['filename']} {result} {strOk}")
        else:
            print(f'{strErr}: {stderr.read().decode("utf8")}')
            return None
        graphInfo['series']=[]
        print(f'{" "*1}Getting MAX values for every Serie...')    
        for serie in rrdGraph['series']:
            cmd=rddtoolMaxCmd(serie,rrdRange)
            stdin, stdout, stderr = client.exec_command(cmd)
            print(f'{" "*2}Serie "{serie["label"]}" {serie["name"]}...',end='',flush=True)
            if stdout.channel.recv_exit_status() == 0:
                if 'format-values' in serie:
                    formatValuesFunction=serie['format-values']
                else:
                    formatValuesFunction=None
                graphInfo['series'].append({
                    "name": serie['name'],
                    "label": serie['label'],
                    "maxValue": stdout.read().decode("utf8").replace("0x0",'').strip(),
                    "format-values": formatValuesFunction
                })
                print(strOk)
            else:
                print(f'{strErr}: {stderr.read().decode("utf8")}')
                return None

        print(f'{" "*1}Starting sftp client...',end='',flush=True)
        try:
            sftpClient = client.open_sftp()
            print(strOk)
            print(f"{' '*2}Transfering Remote:{remoteTmpPath}{rrdGraph['filename']}  -> Local:{workingDir}{bigipIpAddress}_{rrdGraph['filename']} ...",end='',flush=True)
            sftpClient.get(f"{remoteTmpPath}{rrdGraph['filename']}", f"{workingDir}{bigipIpAddress}_{rrdGraph['filename']}")
            print(strOk)

            graphInfo['filename']=f"{workingDir}{bigipIpAddress}_{rrdGraph['filename']}"        

            print('Closing sftp client...',end='',flush=True)
            sftpClient.close()
            print(strOk)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            return None
        deviceInfo['graphs'].append(graphInfo)
    print(f'Deleting remote temp directory {remoteTmpPath}...',end='',flush=True)
    stdin, stdout, stderr = client.exec_command(f'rm -Rf {remoteTmpPath}')
    if stdout.channel.recv_exit_status() == 0:
        print(strOk)
    else:
        print(f'{strErr}: {stderr.read().decode("utf8")}')
        return None

    print('Closing ssh session...',end='',flush=True)
    stdin.close()
    stdout.close()
    stderr.close()
    client.close()
    print(strOk)

   # print(devicesInfo)
    return deviceInfo

def validate_args(args):
    strErr=colored('ERROR: ','red')
    if args.range:
        if args.range[0]>args.range[1]:
            parser.print_help()
            print(strErr+'En la opcion -r|--range La primera FECHA debe ser menor a la segunda FECHA.')
            sys.exit(1)                     
    if not args.name:
            parser.print_help()
            print(strErr+'La opción -n debe ser proporcionada.')
            sys.exit(1)       
    if args.file:
        if args.username or args.devices:
            parser.print_help()
            print(strErr+'La opción -f no puede ser usada con -u or -d.')
            sys.exit(1)
    elif args.username:
        if not args.devices:
            parser.print_help()
            print(strErr+'La opción -u debe ser usada con -d.')
            sys.exit(1)
    elif args.devices:
        if not args.username:
            parser.print_help()
            print(strErr+'La opción -d debe ser usada con -u.')
            sys.exit(1)
    else:
        parser.print_help()
        print(strErr+'Al menos se debe proveer la opción -f o las opciones -u y -d.')
        sys.exit(1)
################ MAIN CODE ###################


parser = argparse.ArgumentParser(
 prog="performanceF5",
 description='Generador de informe de rendimiento de equipos f5 via ssh/sftp. Escrito por '+ colored('Juan Salinas', 'yellow') + '.')
group = parser.add_argument_group('argumentos requeridos')
group.add_argument('-n', '--name', type=str,
                    help='El nombre que se usara para crear el archivo de reporte.')
group.add_argument('-u', '--username', type=str,
                    help='El usuario para iniciar session.')
group.add_argument('-d', '--devices', type=split,
                    help='Listado de dispositivos separados por coma. Puede ser ip o fqdn.')
group.add_argument('-f', '--file', type=str,
                    help='Lee el archivo FILE con formato "<ip|fqdn>","<usuario>","<contraseña>" y la utiliza para generar los reportes.\nAl utilizar esta opcion se solicitara una contraseña para usarla como llave en el cifrado de las contraseñas.\nLas contraseñas cifradas seran escritas al archivo. No debe olvidar esta contraseña.')
group.add_argument('-r', '--range', type=lambda d : datetime.strptime(d, '%Y/%m/%d %H:%M:%S') ,nargs=2,
                    help='Rango de fechas en el formato "<yyyy/mm/dd hh:mm:ss>" "<yyyy/mm/dd hh:mm:ss>". Si no se especifica rango se generara el resporte del mes anterior a la ejecuccion. Ejemplo: Mes de ejecucción Enero-2023 <2022/12/1 00:00:00>-<2023/1/1 00:00:00>')
group.add_argument('-v', '--version', action='store_true',
                    help='Imprime la version y termina la ejecucción. Anula todas las otras opciones.')


args = parser.parse_args()
if args.version:
    print(colored(f"Version: {__version__}",'yellow') )
    sys.exit(0)
print(f"performanceF5 Version: {__version__}" )
validate_args(args)

rrdGraphs = [
    {
        "title": "Plane CPU Usage",
        "filename" : "planesStatsGraph.png",
        "lower-limit": 0,
        "upper-limit": 100,
        "vertical-label":"% Utilization",
        "series": [
            {
                "name": "DataPlaneCPUUsage",
                "label": "Data Plane",
                "rrd": "/var/rrd/planestat",
                "cf": "AVERAGE",
                "color": "#FF0000"
            },
            {
                "name": "CtlPlaneCPUUsage",
                "label": "Control Plane",
                "rrd": "/var/rrd/planestat",
                "cf": "AVERAGE",
                "color": "#00FF00"
            },
            {
                "name": "AnaPlaneCPUUsage",
                "label": "Analisys Plane",
                "rrd": "/var/rrd/planestat",
                "cf": "AVERAGE",
                "color": "#0000FF"
            }
        ]
    },
    {
        "title": "System CPU Usage",
        "filename" : "rollupCpu.png",
        "lower-limit": 0,
        "upper-limit": 100,
        "vertical-label":"Usage %",
        "series": [
            {
                "name": "Rratio",
                "label": "Utilization",
                "rrd": "/var/rrd/rollupcpu",
                "cf": "AVERAGE",
                "color": "#FF0000"
            }
        ]
    },
    {
        "title": "Active Connections",
        "filename" : "connections.png",
        "lower-limit": 0,
        "upper-limit": 50,
        "vertical-label":"Active Conns",
        "series": [
            {
                "name": "curclientconns",
                "label": "Connections",
                "rrd": "/var/rrd/connections",
                "cf": "AVERAGE",
                "color": "#FF0000"
            }
        ]
    },
    {
        "title": "Memory Used",
        "filename" : "memory.png",
        "lower-limit": 0,
        "upper-limit": 50,
        "vertical-label":"Percent Used",
        "base": 1024,
        "series": [
            {
                "name": "Rtmmused",
                "label": "TMM Memory Used",
                "rrd": "/var/rrd/memory",
                "cf": "AVERAGE",
                "color": "#FF0000",
                "format-values": convert_bytes
            },
            {
                "name": "Rotherused",
                "label": "Other Memory Used",
                "rrd": "/var/rrd/memory",
                "cf": "AVERAGE",
                "color": "#00FF00",
                "format-values": convert_bytes
            },
            {
                "name": "Rusedswap",
                "label": "Swap Used",
                "rrd": "/var/rrd/memory",
                "cf": "AVERAGE",
                "color": "#0000FF",
                "format-values": convert_bytes
            }
        ]
    },
    {
        "title": "Throughput",
        "filename" : "throughput.png",
        "lower-limit": 0,
        "upper-limit": 50,
        "vertical-label":"Bits/sec",
        "base": 1024,
        "series": [
            {
                "name": "servicebytes",
                "label": "Service",
                "rrd": "/var/rrd/throughput",
                "cf": "AVERAGE",
                "color": "#FF0000",
                "format-values": convert_bps,
                "bytestobits" : True
            },
            {
                "name": "tput_bytes_in",
                "label": "In",
                "rrd": "/var/rrd/throughput",
                "cf": "AVERAGE",
                "color": "#00FF00",
                "format-values": convert_bps,
                "bytestobits" : True
            },
            {
                "name": "tput_bytes_out",
                "label": "Out",
                "rrd": "/var/rrd/throughput",
                "cf": "AVERAGE",
                "color": "#0000FF",
                "format-values": convert_bps,
                "bytestobits" : True
            }

        ]
    }
]
if  args.range :
    rrdRange={
        'start': int(args.range[0].timestamp()),
        'end': int(args.range[1].timestamp())
    }
    if (args.range[1]-args.range[0])>timedelta(days=14):
        rrdRange['x-grid']="DAY:1:WEEK:1:WEEK:1:0:%y/%m/%d"
else:
    d=datetime.fromisoformat(date.today().isoformat())
    rrdRange={
        'start': int((d - timedelta(days=d.day)).replace(day=1).timestamp()),
        'end': int(d.replace(day=1).timestamp()),
        'x-grid': "DAY:1:WEEK:1:WEEK:1:0:%y/%m/%d"
    }
    no_rrdRange={
        'start': int((d - timedelta(days=30)).timestamp()),
        'end': int(d.timestamp()),
        'x-grid': "DAY:1:WEEK:1:WEEK:1:0:%y/%m/%d"
    }
    no_rrdRange={
        'start': int((d - timedelta(days=7)).timestamp()),
        'end': int(d.timestamp()),
    }
uniqueId=uuid.uuid4().hex
remoteTmpPath=f"/var/tmp/perfF5_{uniqueId}/" #siempre debe terminar con /
performanceReportDict={}
showWarning=None
if args.username: 
    bigipPassword = getpass.getpass(prompt='Enter {} password: '.format(args.username))
    bigipPasswordConfirm = getpass.getpass(prompt='Confirm {} password: '.format(args.username))
    if bigipPassword != bigipPasswordConfirm:
        print("Passwords doesn't match")
        sys.exit()
    for deviceIp in args.devices:
        result=getPerformanceReport(deviceIp, args.username, bigipPassword,rrdGraphs,rrdRange,remoteTmpPath)
        if result is not None:
            performanceReportDict[deviceIp]=result
        else:
            showWarning=True
elif args.file:
    devices=readDevicesFile(args.file)
    if devices == None:
        sys.exit(1)
    for device in devices:
        result=getPerformanceReport(device['host'], device['username'], device['password'],rrdGraphs,rrdRange,remoteTmpPath)
        if result is not None:
            performanceReportDict[device['host']]=result
        else:
            showWarning=True

generateHtmlReport(performanceReportDict)

if showWarning :
    print(colored('We were unable to get performance information from at least one device, please check the terminal log for more details.','yellow'))
print(f"Show some love for Juanito Da Engineer's work at {colored('https://www.linkedin.com/in/juansalinasc/','yellow')}")
print('Done!')

