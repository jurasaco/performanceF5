import modules.logging as logging
import os
import base64
import sys
from datetime import datetime
from datetime import date
from datetime import timedelta
from mako.template import Template

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
def generateHtml2(devicesInfo,reportNamePrefix,outputPath,customTemplateFile):
    if not len(devicesInfo) > 0: 
        logging.warning("Empty device performance dictionary. The report was not generated.")
        return None
    logging.info("Generating HTML report from default template...")
    #get tmppath or path of the module
    if hasattr(sys, '_MEIPASS'):
        reportTemplateFile = os.path.abspath(os.path.join(sys._MEIPASS,'modules','__report__.html'))
    else:
        reportTemplateFile = os.path.abspath(os.path.join(os.path.dirname(__file__),'__report__.html'))
    if customTemplateFile:
        reportTemplateFile = customTemplateFile
    logging.info(f'{" "*1}Template file {reportTemplateFile}')
    
    reportTemplate = Template(filename=reportTemplateFile)
    html=reportTemplate.render(devicesInfo=devicesInfo)
    nowStr=datetime.today().strftime('%Y%m%d%H%M%S')
    reportFileOutput=f'{outputPath}/{reportNamePrefix}_{nowStr}.html'
    logging.infoAndHold(f'{" "*1}Saving report to {reportFileOutput}...')
    with open(reportFileOutput, 'w',encoding='utf-8') as file:
        file.write(html)
    logging.infoUnholdOk('OK')
    
def generateHtml(devicesInfo,reportName,outputPath):
    if not len(devicesInfo) > 0: 
        logging.warning("Empty device performance dictionary. The report was not generated.")
        return None
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

    table.overviewperf > thead > tr > th {min-width: 50px; background-color: rgb(49, 96, 183);color: white; font-size: 8pt;}
    table.overviewperf > tbody > tr > td {min-width: 50px; font-size: 8pt;text-align: right;}

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
    deviceInfoHtmlOverviewPerf=""
    logging.info("Generating HTML report...")
    for deviceIp,deviceInfo in devicesInfo.items():
        logging.info(f'{" "*1}Converting {deviceIp} information to html...')
        #print(json.dumps(deviceInfo, indent=2,default=str))
        deviceInfoHtml+=f"""
        <p class=perfGraphContents1>
        <span class=subtitle >Gráficos de rendimiento {deviceInfo['hostname']}</span>
        </p>
        <p class=perfGraphContents2>
        Periodo {deviceInfo['rangeStart']} - {deviceInfo['rangeEnd']}.
        </p>     
        """
        allMaxValues={}
        for graph in deviceInfo['graphs']:
            maxValueInfo=[]
            for serie in graph['series']:
                if 'format-values' in serie and not serie['format-values']==None:
                    maxValueInfo.append(f"{serie['label']} = {serie['format-values'](int(serie['maxValue']) if serie['maxValue'].isnumeric() else 0)}")
                    if serie["overview-header"] :
                        allMaxValues[f"{serie['overview-header']}"] = serie['format-values'](int(serie['maxValue']) if serie['maxValue'].isnumeric() else 0)
                else:
                    maxValueInfo.append(f"{serie['label']} = {serie['maxValue']}")
                    if serie["overview-header"] :
                        allMaxValues[f"{serie['overview-header']}"] = serie['maxValue']
            maxValueInfoStr=f'Valores máximos del periodo: {", ".join(maxValueInfo)}.'     
            deviceInfoHtml+=f"""
        <p class=perfGraphContents2>
        <span class=subtitle2 >{graph['title']}</span>
        </p>
        <p class=perfGraphContents3 >
        {maxValueInfoStr}
        </p>
        <p class=perfGraphContents1 style="text-align:center">
        <img width=605 height=179 src="data:image/png;base64,{base64.b64encode(open(graph['filename'], 'rb').read()).decode() }" class=graph >
        </p>
        <br>
        """
            os.remove(graph['filename']) 
        deviceInfoHtml+="<br>"
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
        tdStr=""
        thStr=""
        for mvLabel,mvValue in allMaxValues.items():
            thStr+=f"<th>{mvLabel}</th>\n"
            tdStr+=f"<td>{mvValue}</td>\n"
        deviceInfoHtmlOverviewPerf+=f"""
        <tr>
            <td>{deviceInfo['hostname']}</td>
            {tdStr}
            <td>>>COMENTARIO<<</td>    
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

    deviceInfoHtmlOverviewPerf=f"""
    <p class=perfGraphContents1>
    <span class=subtitle >Visión general rendimiento</span>
    </p>
    <p class=perfGraphContents2 >
    Periodo {deviceInfo['rangeStart']} - {deviceInfo['rangeEnd']}.
    </p>
    <p class=perfGraphContents1 style="text-align:center" >
        <table class=overviewperf >
        <thead>
            <tr>
                <th style="color: white;background-color: rgb(49, 96, 183);">Nombre de host</th>
                {thStr}
                <th style="color: white;background-color: rgb(49, 96, 183);">Comentario</th>
            </tr>
        </thead>
        <tbody>
        {deviceInfoHtmlOverviewPerf}
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
    {deviceInfoHtmlOverviewPerf}
    <br>
    {deviceInfoHtml}
    </page>
    </body>
    </html>
    """
    nowStr=datetime.today().strftime('%Y%m%d%H%M%S')
    reportFileOutput=f'{outputPath}/{reportName}_{nowStr}.html'
    logging.infoAndHold(f'{" "*1}Saving report to {reportFileOutput}...')
    with open(reportFileOutput, 'w',encoding='utf-8') as file:
        file.write(html)
    logging.infoUnholdOk('OK')
    return True
