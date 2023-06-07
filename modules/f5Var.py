import modules.report as report

cmdsToRun = [
    {
        'info': 'Getting hostname...',
        'cmd': "echo $HOSTNAME",
        'keys': [{'key':'hostname', 'regexp':r'(.+)'}]
    },
    {
        'info': 'Getting sysDateTime...',
        'cmd': 'date +"%Y-%m-%d %H:%M:%S"',
        'keys': [{'key':'sysDateTime', 'regexp':r'(.+)'}]
    },
    {
        'info': 'Getting sysTimezone...',
        'cmd': 'tmsh list sys ntp all-properties',
        'keys': [{'key':'sysTimezone', 'regexp':r'timezone\s+(.+)'}]
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
        'cmd': "tmsh show cm failover-status",
        'keys': [
            {'key':'failoverStatus', 'regexp':r'^Status\s+(.+)$'},
            {'key':'failoverConnections', 'regexp':r'(\d+\.\d+\.\d+\.\d+\:\d+)\s{2,}([^\s]+)\s{2,}([^\s]+)\s{2,}([^\s]+)\s{2,}(.+?)\s{2,}([^\s]+)','multiple': True},
            ]
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
    },
    {
        'info': 'Getting password policy...',
        'cmd': 'tmsh list auth password-policy policy-enforcement',
        'keys': [{'key':'sysPasswordPolicy', 'regexp':r'policy-enforcement\s(.+)$'}]
    },
    {
        'info': 'Getting failed login attemps count ...',
        'cmd': 'cat /var/log/audit.1 /var/log/audit | grep "failed to login" | wc -l',
        'keys': [{'key':'sysFailedLoginAttemps', 'regexp':r'(.+)'}]
    },
    {
        'info': 'Getting sshd idle timeout ...',
        'cmd': 'tmsh list sys sshd inactivity-timeout',
        'keys': [{'key':'sysSSHIdleTimeout', 'regexp':r'inactivity-timeout\s(.+)$'}]
    },
    {
        'info': 'Getting httpd idle timeout ...',
        'cmd': 'tmsh list sys httpd auth-pam-idle-timeout',
        'keys': [{'key':'sysHTTPidleTimeout', 'regexp':r'auth-pam-idle-timeout\s(.+)$'}]
    }
]


###########definicion de diccionario para generar graficos######

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