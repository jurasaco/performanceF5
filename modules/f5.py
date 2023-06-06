from paramiko import SSHClient, AutoAddPolicy
import os
import re
from datetime import datetime
from datetime import date
from datetime import timedelta
import uuid
import modules.logging as logging
import modules.report as report
import json
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
                "overview-header": "CPU %",
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
                "overview-header": "Conns",
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
        "upper-limit": 100,
        "vertical-label":"Percent Used",
        "base": 1024,
        "series": [
            {
                "name": "Rtmmused",
                "label": "TMM Memory Used",
                "overview-header": "TMM Mem %",
                "rrd": "/var/rrd/memory",
                "cf": "AVERAGE",
                "color": "#FF0000",
                "percentOf": "Rtmmmemory"
            },
            {
                "name": "Rotherused",
                "label": "Other Memory Used",
                "overview-header": "Other Mem %",
                "rrd": "/var/rrd/memory",
                "cf": "AVERAGE",
                "color": "#00FF00",
                "percentOf": "Rothertotal"
            },
            {
                "name": "Rusedswap",
                "label": "Swap Used",
                "overview-header": "Swap Mem %",
                "rrd": "/var/rrd/memory",
                "cf": "AVERAGE",
                "color": "#0000FF",
                "percentOf": "Rtotalswap"
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
                "overview-header": "Thrput Service",
                "rrd": "/var/rrd/throughput",
                "cf": "AVERAGE",
                "color": "#FF0000",
                "format-values": report.convert_bps,
                "bytestobits" : True
            },
            {
                "name": "tput_bytes_in",
                "label": "In",
                "overview-header": "Thrput In",
                "rrd": "/var/rrd/throughput",
                "cf": "AVERAGE",
                "color": "#00FF00",
                "format-values": report.convert_bps,
                "bytestobits" : True
            },
            {
                "name": "tput_bytes_out",
                "label": "Out",
                "overview-header": "Thrput Out",
                "rrd": "/var/rrd/throughput",
                "cf": "AVERAGE",
                "color": "#0000FF",
                "format-values": report.convert_bps,
                "bytestobits" : True
            }

        ]
    }
]
#'ls -r /var/log/ltm.*.gz | xargs -n 1 zcat | cat - /var/log/ltm.1 /var/log/ltm | grep -P " (warning|err|crit|alert|emerg) " | wc -l'
cmdsToRun = [
    {
        'info': 'Getting hostname...',
        'cmd': "echo $HOSTNAME",
        'keys': [{'key':'hostname', 'regexp':r'(.+)'}]
    },
    {
        'info': 'Getting tmos version...',
        'cmd': "tmsh show sys version  | grep \" Version\"",
        'keys': [{'key':'tmosVersion', 'regexp':r'Version\s+(.+)'}]
    },
    {
        'info': 'Getting hardware information...',
        'cmd': "tmsh show sys hardware | grep -A20 Platform",
        'keys': [
            {'key':'sysPlatformName', 'regexp':r'Name\s+(.+)'},
            {'key':'sysChassisSerial', 'regexp':r'(?:Chassis|Appliance) Serial\s+(.+)'}
        ]
    },
    {
        'info': 'Getting management ip address...',
        'cmd': 'ip address show mgmt | grep " inet "',
        'keys': [{'key':'sysManagementIp', 'regexp':r'(\d+\.\d+\.\d+\.\d+\/\d+)'}]
    },
    {
        'info': 'Getting self ip information...',
        'cmd': 'tmsh list net self one-line all-properties',
        'keys': [
            {'key':'selfIpIpAddress', 'regexp':r'net self ([^\s]+) { address ([^\s]+) '},
            {'key':'selfIpAllowedServices', 'regexp':r'net self ([^\s]+) { .+ allow-service ({.+}|[^\s]+) '}
        ],
        'multiple': True
    },
    {
        'info': 'Getting ntp information...',
        'cmd': 'ntpq -pn',
        'keys': [
            {'key':'ntpStatus', 'regexp':r'^([^\d]|\s|)(\d+\.\d+\.\d+\.\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)'}
        ],
        'multiple': True
    },
    {
        'info': 'Getting provisioned modules list...',
        'cmd': "tmsh list sys provision one-line | grep level ",
        'keys': [{'key':'sysProvision', 'regexp':r'sys provision (.+) { level (.+) }'}],
        'multiple': True
    },
    {
        'info': 'Getting failover status...',
        'cmd': "tmsh show cm failover-status | grep \"Status  \"",
        'keys': [{'key':'failoverStatus', 'regexp':r'Status\s+(.+)'}]
    },
    {
        'info': 'Getting sync status...',
        'cmd': "tmsh show cm sync-status",
        'keys': [{'key':'syncStatus', 'regexp':r'^(Status|Mode)\s+(.+)$'}],
        'multiple': True
    },
    {
        'info': 'Getting ltm logs (only ltm and ltm.1 files)...',
        'cmd': 'cat /var/log/ltm.1 /var/log/ltm | grep -P " (warning|err|crit|alert|emerg) " | wc -l',
        'keys': [{'key':'ltmLogs', 'regexp':r'(.+)'}]
    },
    {
        'info': 'Getting system uptime...',
        'cmd': 'awk \'{m=$1/60; h=m/60; printf "%sd %sh %sm\\n", int(h/24), int(h%24), int(m%60), int($1%60) }\' /proc/uptime',
        'keys': [{'key':'sysUptime', 'regexp':r'(.+)'}]
    }
]

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
