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
def generateHtml2(devicesInfo,reportNamePrefix,outputPath,customTemplateFile,gensufix=True):
    if not len(devicesInfo) > 0: 
        logging.warning("Empty device performance dictionary. The report was not generated.")
        return None
    logging.info("Generating HTML report from default template...")
    #get tmppath or path of the module
    if hasattr(sys, '_MEIPASS'):
        #is a pyinstaller onefile app, so we should use sys.MEIPASS (temp folder)
        reportTemplateFile = os.path.abspath(os.path.join(sys._MEIPASS,'modules','__report__.html'))
    else:
        reportTemplateFile = os.path.abspath(os.path.join(os.path.dirname(__file__),'__report__.html'))
    if customTemplateFile:
        reportTemplateFile = customTemplateFile
    logging.info(f'{" "*1}Template file {reportTemplateFile}')
    
    reportTemplate = Template(filename=reportTemplateFile)
    html=reportTemplate.render(devicesInfo=devicesInfo)
    nowStr=datetime.today().strftime('%Y%m%d%H%M%S')
    reportFileOutput=f'{outputPath}/{reportNamePrefix}{ "_" + nowStr if gensufix else "" }.html'
    logging.infoAndHold(f'{" "*1}Saving report to {reportFileOutput}...')
    with open(reportFileOutput, 'w',encoding='utf-8') as file:
        file.write(html)
    logging.infoUnholdOk('OK')
