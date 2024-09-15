from colorama import init as colorama_init
from colorama import deinit as colorama_init
from colorama import reinit as colorama_reinit
from colorama import Fore
from colorama import Style

# Defining global variables
colorInit = False
colorReset = Style.RESET_ALL

# Defining a function that will print colored or non colored text to stdout (terminal). Takes in 2 lists, messageList that contains message
def terminalPrinter(messageList, colorList):
    global colorInit
    global colorReset

    if (not isInteractiveMode and not overrideInteractiveMode):
        return

    if(colorInit):
        colorama_reinit()
    else:
        colorama_init()
        colorInit = True
    
    if type(messageList) != list and type(colorList) != list:
        print(f"{colorList}{messageList}{colorReset}",end="")

    else:
        for message,color in zip(messageList, colorList):
            print(f"{color}{message}{colorReset}",end="")

    colorama_deinit()
