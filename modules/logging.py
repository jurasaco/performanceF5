import colorama #for windows terminal colors
from termcolor import colored
colorama.init()
def error(msg,color='red',lend='\n',lflush=True):
    print(colored(msg,color),end=lend,flush=lflush)

def info(msg,color='white',lend='\n',lflush=True):
    print(colored(msg,color),end=lend,flush=lflush)

def infoAndHold(msg,color='white',lend='',lflush=True):
    print(colored(msg,color),end=lend,flush=lflush)

def infoUnholdOk(msg,color='green',lend='\n',lflush=True):
    print(colored(msg,color),end=lend,flush=lflush)

def infoUnholdError(msg,color='red',lend='\n',lflush=True):
    print(colored(msg,color),end=lend,flush=lflush)
    
def warning(msg,color='yellow',lend='\n',lflush=True):
    print(colored(msg,color),end=lend,flush=lflush)