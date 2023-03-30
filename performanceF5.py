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

import colorama #for windows terminal colors

import tempfile
import shutil

import modules.logging as logging
import modules.f5 as f5
import modules.version as version
import modules.report as report
import modules.credentials as credentials


colorama.init()



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
    if not args.directory:
            parser.print_help()
            print(strErr+'La opción -d debe ser proporcionada.')
            sys.exit(1)  
    else:
        args.directory=args.directory.rstrip('/')
        if os.path.normpath(args.directory)!=args.directory:
            print(f"{strErr}{args.directory} es una sintaxis de directorio no valida")
            sys.exit(1)
        args.directory=os.path.abspath(args.directory)
    if args.file:
        if args.username or args.hosts:
            parser.print_help()
            print(strErr+'La opción -f no puede ser usada con -u or -h.')
            sys.exit(1)
    elif args.username:
        if not args.hosts:
            parser.print_help()
            print(strErr+'La opción -u debe ser usada con -h.')
            sys.exit(1)
    elif args.hosts:
        if not args.username:
            parser.print_help()
            print(strErr+'La opción -h debe ser usada con -u.')
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
group.add_argument('-d', '--directory', type=str,
                    help='La ruta del directorio para almacenar el reporte')
group.add_argument('-u', '--username', type=str,
                    help='El usuario para iniciar session.')
group.add_argument('-l', '--hosts', type=lambda s : [s.strip() for s in s.split(',')],
                    help='Listado de hosts separados por coma. Puede ser ip o fqdn.')
group.add_argument('-f', '--file', type=str,
                    help='Especifica el archivo de dispositivos y credenciales FILE con formato "<ip|fqdn>","<usuario>","<contraseña>" y que se utiliza para conectarse a los dispositivos F5 y extraer la informacion.\nAl utilizar esta opcion se solicitara una contraseña para usarla como llave en el cifrado de las contraseñas.\nLas contraseñas cifradas seran escritas al archivo. No debe olvidar esta contraseña.')
group.add_argument('-t', '--template', type=str,
                    help='Especifica el archivo Mako TEMPLATE que se utilizara para generar el informe.')
group.add_argument('-k', '--keyfile', action='store_true',
                    help='Habilita el uso de un keyfile para guardar y/o recuperar la contraseña de cifrado del archivo especificado con -f. Escencial para usar el script en modo no interactivo, como por ejemplo como tarea crontab. Se debe ejecutar almenos una vez en modo interactivo para que el usuario ingrese la contraseña.')
group.add_argument('-r', '--range', type=lambda d : datetime.strptime(d, '%Y/%m/%d %H:%M:%S') ,nargs=2,
                    help='Rango de fechas en el formato "<yyyy/mm/dd hh:mm:ss>" "<yyyy/mm/dd hh:mm:ss>". Si no se especifica rango se generara el resporte del mes anterior a la ejecuccion. Ejemplo: Mes de ejecucción Enero-2023 <2022/12/1 00:00:00>-<2023/1/1 00:00:00>')
group.add_argument('-v', '--version', action='store_true',
                    help='Imprime la version y termina la ejecucción. Anula todas las otras opciones.')


args = parser.parse_args()
if args.version:
    version.show()
    sys.exit(0)
version.show()
validate_args(args)
os.makedirs(args.directory, exist_ok=True)
logging.info(f"The report will be created in {args.directory}")
tempDir = tempfile.mkdtemp() #"f5Reports/"
logging.info(f"The temp directory is {tempDir}")

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

performanceReportDict={}
showWarning=None
if args.username: 
    bigipPassword = getpass.getpass(prompt='Enter {} password: '.format(args.username))
    bigipPasswordConfirm = getpass.getpass(prompt='Confirm {} password: '.format(args.username))
    if bigipPassword != bigipPasswordConfirm:
        print("Passwords doesn't match")
        sys.exit()
    devices=[]
    for host in args.hosts:
        devices.append({
            'host':host,
            'username': args.username,
            'password': bigipPassword
            })
elif args.file:
    devices=credentials.readDevicesFile(args.file,useKeyFile=args.keyfile)
    if devices == None:
        sys.exit(1)
for device in devices:
    try:
        result=f5.getDeviceInfo(device['host'], device['username'], device['password'],rrdRange,tempDir)
        performanceReportDict[device['host']]=result
    except Exception as err:
        logging.error(err)
        logging.info('Failed to get information from f5 device. Let\'s move on to the next task')

        showWarning=True

report.generateHtml2(performanceReportDict,args.name,args.directory,args.template)
logging.infoAndHold(f'Deleting temp directory {tempDir}...')
shutil.rmtree(tempDir)
logging.infoUnholdOk('OK')
if showWarning :
    print(colored('We were unable to get performance information from at least one device, please check the terminal log for more details.','yellow'))
print(f"Show some love for Juanito Da Engineer's work at {colored('https://www.linkedin.com/in/juansalinasc/','yellow')}")
print('Done!')

