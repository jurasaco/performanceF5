from paramiko import SSHClient, AutoAddPolicy
import os
import re
from datetime import datetime
from datetime import date
from datetime import timedelta
import uuid
import modules.logging as logging

import json
from modules.f5Var import cmdsToRun, rrdGraphs

#'ls -r /var/log/ltm.*.gz | xargs -n 1 zcat | cat - /var/log/ltm.1 /var/log/ltm | grep -P " (warning|err|crit|alert|emerg) " | wc -l'


def getGraphs(client,rrdGraphs,rrdRange,localTmpPath):
    bigipIpAddress= client.get_transport().getpeername()[0]
    uniqueId=hex(uuid.getnode())[2:] #ahora usaremos siempre el mismo directorio temporal para no llenarnos de directorios como cuando usabamos uuid.uuid4().hex
    remoteTmpPath=f"/var/tmp/perfF5_{uniqueId}" #siempre debe terminar sin /
    
    getOutputFromCmdRaw(
        client,
        f'Creating remote tmp directory {remoteTmpPath}...',
        f'mkdir -p {remoteTmpPath}'
    )

    logging.info('Generating graphs and stats...'+datetime.fromtimestamp( rrdRange['start'] ).strftime("%Y-%m-%d %H:%M:%S")+'->'+datetime.fromtimestamp( rrdRange['end'] ).strftime("%Y-%m-%d %H:%M:%S"))
    retGraphs=[]
    
    for rrdGraph in rrdGraphs:
        cmd=rrdtoolCmd(rrdGraph,rrdRange,remoteTmpPath)
        graphInfo={}

        graphInfo['title']=rrdGraph['title']
        getOutputFromCmdRaw(
            client,
            f"Graph '{rrdGraph['title']}' {rrdGraph['filename']} ",
            cmd
        )
        graphInfo['series']=[]
        logging.info(f'{" "*1}Getting MAX values for every Serie...')    
        for serie in rrdGraph['series']:
            cmd=rddtoolMaxCmd(serie,rrdRange)
            result=getOutputFromCmdRaw(
                client,
                f'{" "*2}Serie "{serie["label"]}" {serie["name"]}...',
                cmd
            )
            result=result.replace('0x0','').strip()
            if 'format-values' in serie:
                formatValuesFunction=serie['format-values']
            else:
                formatValuesFunction=None

            graphInfo['series'].append({
                "name": serie['name'],
                "label": serie['label'],
                "maxValue": result,
                "format-values": formatValuesFunction,
                "overview-header": serie.get('overview-header',False)
            })
            logging.info(f'{" "*3} {serie["name"]} => {result}')  
        logging.infoAndHold(f'{" "*1}Starting sftp client...')
        try:
            sftpClient = client.open_sftp()
            logging.infoUnholdOk('OK')
            logging.infoAndHold(f"{' '*2}Transfering Remote:{remoteTmpPath}/{rrdGraph['filename']}  -> Local:{localTmpPath}/{bigipIpAddress}_{rrdGraph['filename']} ...")
            sftpClient.get(f"{remoteTmpPath}/{rrdGraph['filename']}", f"{localTmpPath}/{bigipIpAddress}_{rrdGraph['filename']}")
            logging.infoUnholdOk('OK')

            graphInfo['filename']=f"{localTmpPath}/{bigipIpAddress}_{rrdGraph['filename']}"        

            logging.infoAndHold('Closing sftp client...')
            sftpClient.close()
            logging.infoUnholdOk('OK')
        except Exception as err:
            logging.error(f"ERROR: Unexpected {err=}, {type(err)=}")
            raise Exception('Failed to transfer file via sftp')
        retGraphs.append(graphInfo)
    #TODO: Cambiar el metodo de borrado de archivos temporales.
    logging.infoAndHold(f'Deleting remote temp directory {remoteTmpPath}...')
    stdin, stdout, stderr = client.exec_command(f'rm -Rf {remoteTmpPath}')
    if stdout.channel.recv_exit_status() == 0:
        logging.infoUnholdOk('OK')
    else:
        logging.error(f'ERROR: {stderr.read().decode("utf8")}')
        raise Exception('Failed to delete the remote temp directory.')
    return retGraphs


def rrdtoolCmd(rrdGraph,rrdRange,remoteTmpPath):
    secToGraph=((rrdRange['end']-rrdRange['start']))
    if secToGraph > 2592000 :
        steps=600
    elif secToGraph > 604800 :
        steps=600
    elif secToGraph > 86400 :
        steps=60
    elif secToGraph > 10800 :
        steps=30
    else:
        steps=10
    reducef="AVERAGE"
    logging.info(f"Step=>{steps}")
    cmd = f"rrdtool graph {remoteTmpPath}/{rrdGraph['filename']} -D -w 909 -h 269 --font DEFAULT:11: " \
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
        cmd += f"DEF:{serie['name']}={serie['rrd']}:{serie['name']}:{serie['cf']}:reduce={reducef}:step={steps} "
        suffix=''
        if 'bytestobits' in serie:
            cmd += f"CDEF:{serie['name']}bits={serie['name']},8,* "
            suffix='bits'
        if 'percentOf' in serie:
            cmd += f"DEF:{serie['percentOf']}={serie['rrd']}:{serie['percentOf']}:{serie['cf']}:reduce={reducef}:step={steps} "
            cmd += f"CDEF:{serie['name']}percent={serie['name']},{serie['percentOf']},/,100,* "
            suffix='percent'
        cmd += f"LINE2:{serie['name']}{suffix}{serie['color']}:\"{serie['label']}\" "
    return cmd

def rddtoolMaxCmd(serie,rrdRange):
    secToGraph=((rrdRange['end']-rrdRange['start']))
    if secToGraph > 2592000 :
        steps=600
    elif secToGraph > 604800 :
        steps=600
    elif secToGraph > 86400 :
        steps=60
    elif secToGraph > 10800 :
        steps=30
    else:
        steps=10
    reducef="AVERAGE"
    cmd="rrdtool graph /var/tmp/borrame.png -D -w 909 -h 269 " \
        f"--start {rrdRange['start']} --end {rrdRange['end']} " \
        f"DEF:{serie['name']}={serie['rrd']}:{serie['name']}:{serie['cf']}:reduce={reducef}:step={steps} "
    suffix=''
    if 'bytestobits' in serie:
            cmd += f"CDEF:{serie['name']}bits={serie['name']},8,* "
            suffix='bits'
    if 'percentOf' in serie:
            cmd += f"DEF:{serie['percentOf']}={serie['rrd']}:{serie['percentOf']}:{serie['cf']}:reduce={reducef}:step={steps} "
            cmd += f"CDEF:{serie['name']}percent={serie['name']},{serie['percentOf']},/,100,* "
            suffix='percent'
    cmd+=f"VDEF:max={serie['name']}{suffix},MAXIMUM PRINT:max:\"%.0lf\""
  
    return cmd

def getInfoFromCmd(client, cmdInfo, execCmd, keysToParse, multiple=False):
    execCmdOutput = getOutputFromCmdRaw(client, cmdInfo, execCmd)
    
    ret = {}
    for keyToParse in keysToParse:
        if keyToParse.get('multiple', multiple): #buscamos el multiple de la key sino usamos el global que se paso como argumento         
            result = re.findall(keyToParse['regexp'], execCmdOutput,re.MULTILINE)
            ret[keyToParse['key']] = result
            retStr = ", ".join(map(lambda tuple: "=".join(tuple), result))
        else:
            result = re.search(keyToParse['regexp'], execCmdOutput,re.MULTILINE)
            ret[keyToParse['key']] = result.group(1)
            retStr = result.group(1)
        logging.info(f"{' '*1}{keyToParse['key']} => {retStr}")
    return ret

def getOutputFromCmdRaw(client,cmdInfo,execCmd):
    logging.infoAndHold(cmdInfo)
    stdin, stdout, stderr = client.exec_command(execCmd)
    execCmdOutput=stdout.read().decode("utf8")#por problema de buffer que se llena, primero leemos y despues revisamos el error
    if stdout.channel.recv_exit_status() == 0:
        logging.infoUnholdOk('OK')
    else:
        logging.error(f'ERROR: {stderr.read().decode("utf8")}')
        raise Exception('Failed to get execute remote command')
    return execCmdOutput

def getDeviceInfo(bigipIpAddress,bigipPort,bigipUsername, bigipPassword,rrdRange,localTmpPath):
    deviceInfo={}
    deviceInfo['rangeStart']=datetime.fromtimestamp( rrdRange['start'] )
    deviceInfo['rangeEnd']=datetime.fromtimestamp( rrdRange['end'] )
    os.makedirs(localTmpPath, exist_ok=True)
    logging.infoAndHold(f'Connecting to {bigipIpAddress}:{bigipPort}...')
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())

    # DateTime=datetime.today().strftime('%Y%m%d%H%M%S')
    try:
        client.connect(bigipIpAddress, username=bigipUsername,
                       password=bigipPassword, timeout=10,port=bigipPort)
    except Exception as err:
        logging.error(f"Unexpected {err=}, {type(err)=}")
        logging.error(f"Wrong password for user {bigipUsername} at {bigipIpAddress}?")
        raise Exception('Failed to start ssh session.')
    logging.infoUnholdOk('OK')

    for cmd in cmdsToRun:
        deviceInfo |= getInfoFromCmd(
            client,
            cmd['info'],
            cmd['cmd'],
            cmd['keys'],
            multiple=cmd.get('multiple', False)
        )

    deviceInfo['graphs']=getGraphs(client,rrdGraphs,rrdRange,localTmpPath)

    logging.infoAndHold('Closing ssh session...')
    client.close()
    logging.infoUnholdOk('OK')

    #print(json.dumps(deviceInfo, indent=2,default=str))
    return deviceInfo

# TODO: implementar estadisticas de log por f5 id
def getLtmLogsStats(ltmLogs):
    ltmLogStats=[]
    return ltmLogStats
