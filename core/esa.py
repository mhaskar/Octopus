#!/usr/bin/python

from termcolor import colored
import tabulate
from functions import listeners_information
avs = []
siem_found = False

AV_list = {
    "Kaspersky":    ["avp", "avpui", "klif", "KAVFS", "kavfsslp"],
    "Symantec":    ["SmcGui", "SISIPSService"],
    "Avast":    ["aswBcc", "bcc"],
    "Bitdefender": ["epag", "EPIntegrationService", "EPProtectedService", "EPSecurityService"],
    "Cylance": ["CylanceSvc", "CylanceUi"],
    "ESET": ["epfw", "epfwlwf", "epfwwfp"],
    "FireEye Endpoint Agent": ["xagt"],
    "F-Secure": ["fsdevcon", "FSORSPClient"],
    "MacAfee": ["enterceptagent", "McAfeeEngineService", "McAfeeFramework"],
    "SentinelOne": ["SentinelAgent", "SentinelOne"],
    "Sophos": ["sophosssp", "sophossps"],
    "TrendMicro": ["tmntsrv"],
    "Windows Defender": ["MsMpEng"],
    "ZoneALarm": ["zlclient"],
    "Panda AntiVirus": ["AVENGINE"],
    "AVG": ["avgemc"],
    "Avira" : ["avscan"],
    "G data" : ["AVKProxy"],

}
SIEM = {

    "winlogbeat":"winlogbeat"
}


def esa(processes, session):
    sysmon = False
    # check for AVs
    for process in processes:
        for key in AV_list.keys():
            for av_process in AV_list[key]:
                if process == av_process:
                    avs.append(key)

    # check for SIEM collector
    for process in processes:
        for siem in SIEM:
            if process == siem:
                siem_found = process

    # check for sysmon
    for process in processes:
        if process == "Sysmon64":
            sysmon = True

    hostname = session[2]
    os_version = session[7]
    domain = session[5]
    if domain == "WORKGROUP":
        domain = "Not domain-joined device !"
    arch = session[7].split("(")[1].split(")")
    anti_virus = ",".join(i for i in set(avs))
    siem = siem_found
    systime = processes[-1]
    uptime = processes[-2]
    language = processes[-3]
    os_build = processes[-4]
    internal_ips = processes[-5].split(";")

    print colored('\nEndpoint situation awareness report for %s' % hostname, "yellow")
    print colored("\n=============")
    print "Hostname : \t%s" % hostname
    print "Domain : \t%s" % domain
    print "OS : \t\t%s" % os_version
    print "OS build : \t%s" % os_build
    print "OS arch : \t%s" % arch[0]
    print "AntiVirus : \t%s" % anti_virus
    print "SIEM collector : %s" % siem
    print "SysMon Enabled : %s" % sysmon
    # print "Mail Applications : "
    print "Internal interfaces/IPs :"
    for ip in internal_ips:
        print "\tIP : %s" % ip
    print "\n"
    # print "SMBshares : "
    # print "Device connected to internet : "
    # print "Powershell logging enabled  : "
    print "Device language : %s" % language
    print "Device uptime : %s hours" % uptime
    print "Device local time : %s" % systime
    #print "Installed APPs : "
