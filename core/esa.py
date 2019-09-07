#!/usr/bin/python

from termcolor import colored
import tabulate
from functions import listeners_information
avs = []
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
    "Windows Defender": ["MsMpEng.exe"],
    "ZoneALarm": ["zlclient"],
    "Panda AntiVirus": ["AVENGINE"],
    "AVG": ["avgemc"],
    "Avira" : ["avscan"],
    "G data" : ["AVKProxy"],

}
SIEM = {

    "":"",
}

others = {

    "Sysmon":"Sysmon.exe"

}

def esa(processes, session):
    for process in processes:
        for key in AV_list.keys():
            for av_process in AV_list[key]:
                if process == av_process:
                    avs.append(key)


    hostname = session[2]
    os_version = session[7]
    os_build = processes[-1]
    domain = session[5]
    if domain == "WORKGROUP":
        domain = "Not domain-joined device !"
    arch = session[7].split("(")[1].split(")")
    anti_virus = ",".join(i for i in set(avs))
    siem = False

    print colored('\nEndpoint situation awareness report for %s' % hostname, "yellow")
    print colored("\n=============")
    print "Hostname : \t%s" % hostname
    print "Domain : \t%s" % domain
    print "OS : \t\t%s" % os_version
    print "OS build : \t%s" % os_build
    print "OS arch : \t%s" % arch[0]
    print "AntiVirus : \t%s" % anti_virus
    print "SIEM solution : %s" % siem
