from paramiko import SSHClient, AutoAddPolicy
import os
import re
from datetime import datetime
from datetime import date
from datetime import timedelta
import uuid
import modules.logging as logging

def getGraphs(client,rrdGraphs,rrdRange,LocalTmpPath):
    bigipIpAddress= client.get_transport().getpeername()[0]
    uniqueId=uuid.uuid4().hex
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

        result=graphInfo['title']=rrdGraph['title']

        getOutputFromCmdRaw(
            client,
            f"Graph '{rrdGraph['title']}' {rrdGraph['filename']} {result} ",
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
            if 'format-values' in serie:
                formatValuesFunction=serie['format-values']
            else:
                formatValuesFunction=None

            graphInfo['series'].append({
                "name": serie['name'],
                "label": serie['label'],
                "maxValue": result,
                "format-values": formatValuesFunction
            })
        logging.infoAndHold(f'{" "*1}Starting sftp client...')
        try:
            sftpClient = client.open_sftp()
            logging.infoUnholdOk('OK')
            logging.infoAndHold(f"{' '*2}Transfering Remote:{remoteTmpPath}/{rrdGraph['filename']}  -> Local:{LocalTmpPath}/{bigipIpAddress}_{rrdGraph['filename']} ...")
            sftpClient.get(f"{remoteTmpPath}/{rrdGraph['filename']}", f"{LocalTmpPath}/{bigipIpAddress}_{rrdGraph['filename']}")
            logging.infoUnholdOk('OK')

            graphInfo['filename']=f"{LocalTmpPath}/{bigipIpAddress}_{rrdGraph['filename']}"        

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

def getInfoFromCmd(client, cmdInfo, execCmd, keysToParse, multiple=False):
    execCmdOutput = getOutputFromCmdRaw(client, cmdInfo, execCmd)
    
    ret = {}
    for keyToParse in keysToParse:
        if multiple:
            result = re.findall(keyToParse['regexp'], execCmdOutput,re.MULTILINE)
            ret[keyToParse['key']] = result
            retStr = ", ".join(map(lambda tuple: "=".join(tuple), result))
        else:
            result = re.search(keyToParse['regexp'], execCmdOutput)
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

def getDeviceInfo(bigipIpAddress, bigipUsername, bigipPassword,rrdGraphs,rrdRange,LocalTmpPath):
    deviceInfo={}
    deviceInfo['rangeStart']=datetime.fromtimestamp( rrdRange['start'] )
    deviceInfo['rangeEnd']=datetime.fromtimestamp( rrdRange['end'] )
    os.makedirs(LocalTmpPath, exist_ok=True)
    logging.infoAndHold(f'Connecting to {bigipIpAddress}...')
    client = SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(AutoAddPolicy())

    # DateTime=datetime.today().strftime('%Y%m%d%H%M%S')
    try:
        client.connect(bigipIpAddress, username=bigipUsername,
                       password=bigipPassword, timeout=10)
    except Exception as err:
        logging.error(f"Unexpected {err=}, {type(err)=}")
        logging.error(f"Wrong password for user {bigipUsername} at {bigipIpAddress}?")
        raise Exception('Failed to start ssh session.')
    logging.infoUnholdOk('OK')

    deviceInfo|=getInfoFromCmd(
        client,
        'Getting hostname...',
        "echo $HOSTNAME",
        [{
            'key':'hostname',
            'regexp':r'(.+)'
        }]
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting tmos version...',
        "tmsh show sys version  | grep \" Version\"",
        [{
            'key':'tmosVersion',
            'regexp':r'Version\s+(.+)'
        }]
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting hardware information...',
        "tmsh show sys hardware | grep -A20 Platform",
        [{
            'key':'sysPlatformName',
            'regexp':r'Name\s+(.+)'
        },
        {
            'key':'sysChassisSerial',
            'regexp':r'(Chassis|Appliance) Serial\s+(.+)'
        }
        ]
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting management ip address...',
        'ip address show mgmt | grep " inet "',
        [{
            'key':'sysManagementIp',
            'regexp':r'(\d+\.\d+\.\d+\.\d+\/\d+)'
        }
        ]
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting provisioned modules list...',
        "tmsh list sys provision one-line | grep level ",
        [{
            'key':'sysProvision',
            'regexp':r'sys provision (.+) { level (.+) }'
        }
        ],
        multiple=True
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting failover status...',
        "tmsh show cm failover-status | grep \"Status  \"",
        [{
            'key':'failoverStatus',
            'regexp':r'Status\s+(.+)'
        }
        ]
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting sync status...',
        "tmsh show cm sync-status",
        [{
            'key':'syncStatus',
            'regexp':r'^(Status|Mode)\s+(.+)$'
        }
        ],
        multiple=True
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting ltm logs...',
        'ls -r /var/log/ltm.*.gz | xargs -n 1 zcat | cat - /var/log/ltm.1 /var/log/ltm | grep -P " (warning|err|crit|alert|emerg) " | wc -l',
        [{
            'key':'ltmLogs',
            'regexp':r'(.+)'
        }
        ]
    )
    deviceInfo|=getInfoFromCmd(
        client,
        'Getting system uptime...',
        'awk \'{m=$1/60; h=m/60; printf "%sd %sh %sm\\n", int(h/24), int(h%24), int(m%60), int($1%60) }\' /proc/uptime',
        [{
            'key':'sysUptime',
            'regexp':r'(.+)'
        }
        ]
    )

    deviceInfo['graphs']=getGraphs(client,rrdGraphs,rrdRange,LocalTmpPath)

    logging.infoAndHold('Closing ssh session...')
    client.close()
    logging.infoUnholdOk('OK')

   # print(devicesInfo)
    return deviceInfo

# TODO: implementar estadisticas de log por f5 id
def getLtmLogsStats(ltmLogs):
    ltmLogStats=[]
    return ltmLogStats