#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: February 11, 2025
# Release Note: Disable EOP Phishing Simulation

from pyngrok import conf, ngrok
from datetime import datetime
import requests, json, sys, os, urllib3, paramiko, re, string, random, time, subprocess, csv, asyncio
import xml.etree.ElementTree as ET
from subprocess import PIPE
from lxml.etree import fromstring
from importlib import reload
#from import_file import import_file
from requests_toolbelt.multipart.encoder import MultipartEncoder
from dotenv import load_dotenv

import tempfile
import zipfile
import datetime

urllib3.disable_warnings()

script_path = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_path)

#variable = import_file('./config.py')
load_dotenv()
Qualys_username=os.getenv("Qualys_username")
Qualys_password=os.getenv("Qualys_password")
TAGNAME=os.getenv("TAGNAME")
activationKey=os.getenv("activationKey")
bearer=os.getenv("bearer")
sma_server=os.getenv("sma_server")
sma_token=os.getenv("sma_token")
sma_uname=os.getenv("sma_uname")
sma_server_api=os.getenv("sma_server_api")


headers = {
    "Accept": "application/json",
    "Content-Type": "application/json; charset=utf-8",
    "Authorization": "Bearer " + bearer
}

#clear registered webhooks
response = requests.get('https://webexapis.com/v1/webhooks', headers=headers)
if len(response.json()['items']) != 0:
    for i in range(len(response.json()['items'])):
        webhook_id = response.json()['items'][i]['id']
        del_webhook_response = requests.delete('https://webexapis.com/v1/webhooks/'+webhook_id,  headers=headers)

conf.get_default().region = "us"
ngrok.connect(5000).public_url #Start ngrok on port 5000
ngrok_response = requests.get('http://127.0.0.1:4040/api/tunnels')
webhook_url = ngrok_response.json()['tunnels'][0]['public_url']
#listener = ngrok.forward(5000, authtoken_from_env=True) #Start ngrok on port 5000
#for t in client.tunnels.list():
#    print(t)
#for t in client.tunnel_sessions.list():
#    print(t)
#webhook_url = listener.url()
print(webhook_url)
with open('webhook.txt', 'w') as file:
    file.write(webhook_url)

#create new webhooks
response = requests.post('https://webexapis.com/v1/webhooks', json.dumps({"resource" : "messages","event" : "created","targetUrl" : webhook_url,"name" : "SecurityAssistantBot"}), headers=headers)
response = requests.post('https://webexapis.com/v1/webhooks', json.dumps({"resource" : "memberships","event" : "created","targetUrl" : webhook_url,"name" : "SecurityAssistantBot"}), headers=headers)
response = requests.post('https://webexapis.com/v1/webhooks', json.dumps({"resource" : "attachmentActions","event" : "created","targetUrl" : webhook_url,"name" : "SecurityAssistantBot"}), headers=headers)

#generate access list
if os.path.exists('accesslist.xml') :
    root = ET.parse('accesslist.xml').getroot()
    accesslist_ADMIN = []
    accesslist_CERTIFICATES = []
    accesslist_QUALYS = []
    accesslist_RELEASEEMAIL = []
    accesslist_SCRIPTSTATUS = []
#    accesslist_REQUESTEDQUARANTINE = []
#    accesslist_EOPPHISHSIM = []
    if len(root.findall("ADMIN")[0]) != 0:
        for i in range(len(root.findall("ADMIN")[0])):
            accesslist_ADMIN.append(root.findall("ADMIN")[0][i-1].text.lower())
    if len(root.findall("CERTIFICATES")[0]) != 0:
        for i in range(len(root.findall("CERTIFICATES")[0])):
            accesslist_CERTIFICATES.append(root.findall("CERTIFICATES")[0][i-1].text.lower())
    if len(root.findall("QUALYS")[0]) != 0:
        for i in range(len(root.findall("QUALYS")[0])):
            accesslist_QUALYS.append(root.findall("QUALYS")[0][i-1].text.lower())
    if len(root.findall("RELEASEEMAIL")[0]) != 0:
        for i in range(len(root.findall("RELEASEEMAIL")[0])):
            accesslist_RELEASEEMAIL.append(root.findall("RELEASEEMAIL")[0][i-1].text.lower())
    if len(root.findall("SCRIPTSTATUS")[0]) != 0:
        for i in range(len(root.findall("SCRIPTSTATUS")[0])):
            accesslist_SCRIPTSTATUS.append(root.findall("SCRIPTSTATUS")[0][i-1].text.lower())
#    if len(root.findall("REQUESTEDQUARANTINE")[0]) != 0:
#        for i in range(len(root.findall("REQUESTEDQUARANTINE")[0])):
#            accesslist_REQUESTEDQUARANTINE.append(root.findall("REQUESTEDQUARANTINE")[0][i-1].text.lower())
#    if len(root.findall("EOPPHISHSIM")[0]) != 0:
#        for i in range(len(root.findall("EOPPHISHSIM")[0])):
#            accesslist_EOPPHISHSIM.append(root.findall("EOPPHISHSIM")[0][i-1].text.lower())        
else:
    accesslist_ADMIN = "ALL"

try:
    from flask import Flask
    from flask import request
except ImportError as e:
    print(e)
    print("Looks like 'flask' library is missing.\n"
          "Type 'pip3 install flask' command to install the missing library.")
    sys.exit()


def send_get(url, payload=None,js=True):
    if payload == None:
        request = requests.get(url, headers=headers)
    else:
        request = requests.get(url, headers=headers, params=payload)
    if js == True:
        request= request.json()
    return request


def send_post(url, data):
    request = requests.post(url, json.dumps(data), headers=headers).json()
    return request

def send_put(url, data):
    return requests.put(url, json.dumps(data), headers=headers).json()


def help_me():
    return "Sure! I can help. Below are the commands that I understand:<br/>" \
           "`Hello` - I will display my greeting message<br/>" \
           "`Help` - I will display what I can do.<br/>" \
           "`Release Emails` <br/>" \
           "`Qualys Assets` <br/>" \
           "`Client Certificates` <br/>" \
           "`Script Status` <br/>" \
           "<br/>" \
           "If you need to report an email security incident, please forward the suspicious email as an attachement to emailsecurity@ehealthsask.ca <br/>" \


def greetings():
    return "Hi, I am %s.<br/>" \
           "Type `Help` to see what I can do.<br/>" \
           "<br/>" \
           "If you have any questions, please contact Hao.Ban@eHealthsask.ca <br/>" % bot_name


def releaseemails(result, webhook):
    if result['inputs']['Question1'] == 'YES' and result['inputs']['Question2'] == 'YES' and result['inputs']['Question3'] == 'YES':
        if result['inputs']['Environment'] == 'ESA':
            MID = result['inputs']['MID']
            PersonId = result['personId']
            Created = result['created']
            PersonName = send_get('https://webexapis.com/v1/people/{0}'.format(PersonId))['displayName']
            PersonEmail = send_get('https://webexapis.com/v1/people/{0}'.format(PersonId))['emails']
            with open("ReleaseEmail.log", "r") as file:
                for line in file:
                    if MID in line and "successfully" in line:
                        msg = "Email was already released by: "+line
                        released = True
                        break
                    else:
                        released = False
            if not released:
                COMMAND = "grep "+MID+" mail_logs"
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                k = paramiko.RSAKey.from_private_key_file(os.path.expanduser('.\\.ssh\\id_rsa_esa'))
                ssh.connect(sma_server, username=sma_uname, pkey=k)
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(COMMAND)
                for line in ssh_stdout:
                    try:
                        found = re.search('MID .* \(', line.strip())
                        S_MID = found.group(0).split(" ")[1]
                    except AttributeError:
                        found = ''
                ssh.close()
                if not found:
                    msg = "Can't find Message MID#" + MID + " in Encrypted Message quarantine. Please check your input and try again."
                else:
                    SMA_MID = []
                    SMA_MID.append(int(S_MID))
                    SMA_headers = {"Content-Type": "text/plain","Authorization": 'Basic ' + sma_token}
                    SMA_body = {"action": "release","mids": SMA_MID,"quarantineName": "Encrypted Message","quarantineType": "pvo"}
                    print(SMA_headers)
                    print(SMA_body)
                    SMA_response = requests.post(sma_server_api, data=json.dumps(SMA_body), headers=SMA_headers, verify=False)
                    print(SMA_response.json())
                    if SMA_response.status_code == 200 and SMA_response.json()['data']['totalCount'] == 1:
                        msg = "MID#"+MID+" is released successfully, please check your mailbox."
                        print(msg)
                        print(PersonName, PersonEmail, "submitted MID#", MID, "at", Created, "and is released successfully.", file=open("ReleaseEmail.log", "a"))
                    if SMA_response.status_code == 200 and SMA_response.json()['data']['totalCount'] == 0:
                        msg = "MID#"+MID+" was already released by the others but wasn't from this bot service."
                        print(msg)    
        if result['inputs']['Environment'] == 'O365':
            MID = result['inputs']['MID']
            RECIPIENT = result['inputs']['RECIPIENT']
            #PersonId = result['personId']
            #PersonEmail = send_get('https://webexapis.com/v1/people/{0}'.format(PersonId))['emails']
            #RECIPIENT = PersonEmail[0].lower()
            Release_Email = subprocess.Popen(['powershell.exe', './Release_O365.ps1', MID, RECIPIENT], stdout=subprocess.PIPE)
            print(Release_Email.pid)
            Release_Email.wait()
            if Release_Email.returncode == 0:
                msg = Release_Email.stdout.read().decode("utf-8")
            else:
                msg = "Invalid result: " + str(Release_Email.returncode) + " Please contact the developer to get more detail."
    else:
        msg = "You answered \"NO\" to any of the questions above, please delete the email or mark it as \"Junk\" in your mail client."
        print(msg)
    send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})    


def queryassets(result, webhook):
    HOSTNAME = result['inputs']['HOSTNAME']
    xml = """<ServiceRequest>
<filters>
<Criteria field="tagName" operator="EQUALS">{TAGNAME}</Criteria>
<Criteria field="name" operator="CONTAINS">{HOSTNAME}</Criteria>
</filters>
</ServiceRequest>""".format(HOSTNAME=HOSTNAME, TAGNAME="Cloud Agent")
    headers = {'Content-Type': 'text/xml'}
    response = requests.post('https://qualysapi.qg1.apps.qualys.ca/qps/rest/2.0/search/am/hostasset', data=xml, headers=headers, auth=(Qualys_username, Qualys_password))
    root = ET.fromstring(response.text)
    status = root[0].text
    count = root[1].text
    if status == 'SUCCESS' and count != '0':
        try:
            hostname = root[3][0].findall('name')[0].text
        except IndexError:
            hostname = "IndexError"
        try:
            AssetID = root[3][0].findall('id')[0].text
        except IndexError:
            AssetID = "IndexError"
        try:
            HostID = root[3][0].findall('qwebHostId')[0].text
        except IndexError:
            HostID = "IndexError"
        try:
            IPAddress = root[3][0].findall('address')[0].text
        except IndexError:
            IPAddress = "IndexError"
        try:
            OS = root[3][0].findall('os')[0].text
        except IndexError:
            OS = "IndexError"
        try:
            FQDN = root[3][0].findall('fqdn')[0].text
        except IndexError:
            FQDN = root[3][0].findall('name')[0].text
        msg = status + " | " + count + " | " + hostname + " | Asset ID:" + AssetID + " | Host ID:" + HostID + " | IP Address:" + IPAddress  + " | OS:"  + OS
        RoomID = webhook['data']['roomId']
        send_post("https://webexapis.com/v1/messages/", {"roomId": RoomID, "markdown": msg})
        filename = FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
        path_filename = './vulnerabilities/' + FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
        if os.path.exists(path_filename):
            data = MultipartEncoder({'roomId': RoomID, "files": (filename, open(path_filename, 'rb'), 'text/csv')})
            request = requests.post('https://webexapis.com/v1/messages', data=data, headers = {"Authorization": "Bearer " + bearer, 'Content-Type': data.content_type})
        else:
            if HostID != "IndexError" and AssetID != "IndexError":
                msg = "Today's vulnerability file for " + HOSTNAME + " is not exist, bot is generating and will push the CSV file to you when it's done."
                send_post("https://webexapis.com/v1/messages/", {"roomId": RoomID, "markdown": msg})
                vuln_list(HostID,AssetID,RoomID,HOSTNAME, webhook)
            else:
                msg = "HostID or AssetID doesn't exist. Please contact the server administrator to have a check"
                send_post("https://webexapis.com/v1/messages/", {"roomId": RoomID, "markdown": msg})
    if status == 'SUCCESS' and count == '0':
        HOSTNAME = HOSTNAME.lower()
        xml = """<ServiceRequest>
<filters>
<Criteria field="tagName" operator="EQUALS">{TAGNAME}</Criteria>
<Criteria field="name" operator="CONTAINS">{HOSTNAME}</Criteria>
</filters>
</ServiceRequest>""".format(HOSTNAME=HOSTNAME, TAGNAME="Cloud Agent")
        headers = {'Content-Type': 'text/xml'}
        response = requests.post('https://qualysapi.qg1.apps.qualys.ca/qps/rest/2.0/search/am/hostasset', data=xml, headers=headers, auth=(Qualys_username, Qualys_password))
        root = ET.fromstring(response.text)
        status = root[0].text
        count = root[1].text
        if status == 'SUCCESS' and count != '0':
            msg = status + " | " + count + " | " + root[3][0].findall('name')[0].text + " | Asset ID:" + root[3][0].findall('id')[0].text + " | Host ID:" + root[3][0].findall('qwebHostId')[0].text + " | IP Address:" + root[3][0].findall('address')[0].text  + " | OS:"  + root[3][0].findall('os')[0].text
            HostID = root[3][0].findall('qwebHostId')[0].text
            AssetID = root[3][0].findall('id')[0].text
            try:
                FQDN = root[3][0].findall('fqdn')[0].text
            except IndexError:
                FQDN = root[3][0].findall('name')[0].text
            RoomID = webhook['data']['roomId']
            send_post("https://webexapis.com/v1/messages/", {"roomId": RoomID, "markdown": msg})
            filename = FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
            path_filename = './vulnerabilities/' + FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
            if os.path.exists(path_filename):
                data = MultipartEncoder({'roomId': RoomID, "files": (filename, open(path_filename, 'rb'), 'text/csv')})
                request = requests.post('https://webexapis.com/v1/messages', data=data, headers = {"Authorization": "Bearer " + bearer, 'Content-Type': data.content_type})
            else:
                msg = "Today's vulnerability file for " + HOSTNAME + " is not exist, bot is generating and will push the CSV file to you when it's done."
                send_post("https://webexapis.com/v1/messages/", {"roomId": RoomID, "markdown": msg})
                vuln_list(HostID,AssetID,RoomID,HOSTNAME)
    if status == 'SUCCESS' and count == '0':
        HOSTNAME = HOSTNAME.upper()
        xml = """<ServiceRequest>
<filters>
<Criteria field="tagName" operator="EQUALS">{TAGNAME}</Criteria>
<Criteria field="name" operator="CONTAINS">{HOSTNAME}</Criteria>
</filters>
</ServiceRequest>""".format(HOSTNAME=HOSTNAME, TAGNAME="Cloud Agent")
        headers = {'Content-Type': 'text/xml'}
        response = requests.post('https://qualysapi.qg1.apps.qualys.ca/qps/rest/2.0/search/am/hostasset', data=xml, headers=headers, auth=(Qualys_username, Qualys_password))
        root = ET.fromstring(response.text)
        status = root[0].text
        count = root[1].text
        if status == 'SUCCESS' and count != '0':
            msg = status + " | " + count + " | " + root[3][0].findall('name')[0].text + " | Asset ID:" + root[3][0].findall('id')[0].text + " | Host ID:" + root[3][0].findall('qwebHostId')[0].text + " | IP Address:" + root[3][0].findall('address')[0].text  + " | OS:"  + root[3][0].findall('os')[0].text
            HostID = root[3][0].findall('qwebHostId')[0].text
            AssetID = root[3][0].findall('id')[0].text
            try:
                FQDN = root[3][0].findall('fqdn')[0].text
            except IndexError:
                FQDN = root[3][0].findall('name')[0].text
            RoomID = webhook['data']['roomId']
            send_post("https://webexapis.com/v1/messages/", {"roomId": RoomID, "markdown": msg})
            filename = FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
            path_filename = './vulnerabilities/' + FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
            if os.path.exists(path_filename):
                data = MultipartEncoder({'roomId': RoomID, "files": (filename, open(path_filename, 'rb'), 'text/csv')})
                request = requests.post('https://webexapis.com/v1/messages', data=data, headers = {"Authorization": "Bearer " + bearer, 'Content-Type': data.content_type})
            else:
                msg = "Today's vulnerability file for " + HOSTNAME + " is not exist, bot is generating and will push the CSV file to you when it's done."
                send_post("https://webexapis.com/v1/messages/", {"roomId": RoomID, "markdown": msg})
                vuln_list(HostID,AssetID,RoomID,HOSTNAME, webhook)
        if status == 'SUCCESS' and count == '0':
            msg = "Can't find " + HOSTNAME + " in Qualys. Host name is case-sensitive, please confirm the hostname and try again."
            send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})


def vuln_list(HostID,AssetID,RoomID,HOSTNAME, webhook):
    global root_kb
    ID = HostID
    AssetID = AssetID
    RoomID = RoomID
    URL = 'https://qualysapi.qg1.apps.qualys.ca/api/2.0/fo/asset/host/vm/detection/?action=list&ids=' + ID
    headers = {'X-Requested-With': 'Python'}
    response = requests.post(URL, headers=headers, auth=(Qualys_username, Qualys_password), verify = False)
    root = ET.fromstring(response.text)
    try:
        CODE = root[0].findall('CODE')[0].text
        CODE_TEXT = root[0].findall('TEXT')[0].text
    except IndexError:
        CODE = 'NA'
        CODE_TEXT ='NA'
    if CODE == 'NA':
        try:
            HOSTLIST_TAG = root[0][1].tag
        except IndexError:
            HOSTLIST_TAG = 'NA'
        if HOSTLIST_TAG != 'NA':
            if os.path.exists('vulnerabilities'):
                FQDN = root[0][1][0].findall('DNS')[0].text
                filename = FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
                path_filename = './vulnerabilities/' + FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
            else:
                os.mkdir('vulnerabilities')
                filename = FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
                path_filename = './vulnerabilities/' + FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
            csvfile = open(path_filename, 'w', newline='', encoding="utf-8")
            csvfile_writer = csv.writer(csvfile)
            # ADD THE HEADER TO CSV FILE
            csvfile_writer.writerow(["SEVERITY", "ASSET IP", "TITLE", "FIRST DETECTED", "STATUS", "QID", "CVSSv3 Base (nvd)", "TYPE DETECTED", "CVE", "SOLUTION", "CVE-Description", "ASSET ID", "LAST DETECTED", "ASSET NAME", "RESULTS"])
            try:
                ASSET_IP = root[0][1][0].findall('IP')[0].text
            except IndexError:
                ASSET_IP = 'NA'
            try:
                VulnNumber = len(root[0][1][0].findall('DETECTION_LIST')[0])
            except IndexError:
                VulnNumber = 0
            if VulnNumber != 0:
                try:
                    len(root_kb[0][1])
                    print(' *** There are ', len(root_kb[0][1]), 'QID records. *** ')
                except NameError:
                    if os.path.isfile('Knowledge_Base.xml') and os.path.getsize('Knowledge_Base.xml') > 0 and ((datetime.fromtimestamp(os.stat('Knowledge_Base.xml').st_mtime)).strftime('%Y-%m') == time.strftime('%Y-%m', time.localtime())) :
                        tree = ET.parse('Knowledge_Base.xml')
                        root_kb = tree.getroot()
                    else:
                        headers = {'X-Requested-With': 'Python'}
                        URL = 'https://qualysapi.qg1.apps.qualys.ca/api/2.0/fo/knowledge_base/vuln/?action=list'
                        try:
                            response = requests.post(URL, headers=headers, auth=(Qualys_username, Qualys_password), verify = False)
                            if response.status_code == 200:
                                root_kb = ET.fromstring(response.text)
                                with open('Knowledge_Base.xml', 'w', encoding='utf-8-sig') as f:
                                    f.write(response.text)
                        except BaseException as error:
                            print('An exception occurred: {}'.format(error))
                    print(' *** Qualys Knowledge Base Data has been loaded into memory. *** ')
                for i in range(VulnNumber):
                    try:
                        QID = root[0][1][0].findall('DETECTION_LIST')[0][i].findall('QID')[0].text
                    except IndexError:
                        QID = 'NA'
                    try:
                        STATUS = root[0][1][0].findall('DETECTION_LIST')[0][i].findall('STATUS')[0].text
                    except IndexError:
                        STATUS = 'NA'
                    try:
                        SEVERITY = root[0][1][0].findall('DETECTION_LIST')[0][i].findall('SEVERITY')[0].text
                    except IndexError:
                        SEVERITY = 'NA'
                    try:
                        TYPE_DETECTED = root[0][1][0].findall('DETECTION_LIST')[0][i].findall('TYPE')[0].text
                    except IndexError:
                        TYPE_DETECTED = 'NA'
                    try:
                        RESULTS = root[0][1][0].findall('DETECTION_LIST')[0][i].findall('RESULTS')[0].text
                    except IndexError:
                        RESULTS = 'NA'
                    try:
                        FIRST_DETECTED = root[0][1][0].findall('DETECTION_LIST')[0][i].findall('FIRST_FOUND_DATETIME')[0].text
                    except IndexError:
                        FIRST_DETECTED = 'NA'
                    try:
                        LAST_DETECTED = root[0][1][0].findall('DETECTION_LIST')[0][i].findall('LAST_FOUND_DATETIME')[0].text
                    except IndexError:
                        LAST_DETECTED = 'NA'
                    CVE = []
                    if QID != 'NA':
                        for j in range(len(root_kb[0][1])):
                            if root_kb[0][1][j][0].text == QID:
                                try:
                                    TITLE = root_kb[0][1][j].findall('TITLE')[0].text
                                except IndexError:
                                    TITLE = 'NA'
                                try:
                                    CVSS_V3 = root_kb[0][1][j].findall('CVSS_V3')[0].findall('BASE')[0].text
                                except IndexError:
                                    CVSS_V3 = 'NA'
                                try:
                                    SOLUTION = root_kb[0][1][j].findall('SOLUTION')[0].text
                                    if SOLUTION is None:
                                        SOLUTION = 'NA'
                                    else:
                                        SOLUTION = (SOLUTION.replace('\n', ' ')).replace('\t', ' ')
                                except IndexError:
                                    SOLUTION = 'NA'
                                try:
                                    CVE_Number = len(root_kb[0][1][j].findall('CVE_LIST')[0].findall('CVE'))
                                except IndexError:
                                    CVE_Number = 0
                                if CVE_Number != 0:
                                    for k in range(CVE_Number):
                                        CVE.append(root_kb[0][1][j].findall('CVE_LIST')[0].findall('CVE')[k][0].text)
                                try:
                                    CVE_Description = root_kb[0][1][j].findall('DIAGNOSIS')[0].text
                                except IndexError:
                                    CVE_Description = 'NA'
                    # ADD A NEW ROW TO CSV FILE
                    csvfile_writer.writerow([SEVERITY, ASSET_IP, TITLE, FIRST_DETECTED, STATUS, QID, CVSS_V3, TYPE_DETECTED, CVE, SOLUTION, CVE_Description, AssetID, LAST_DETECTED, FQDN, RESULTS])
            csvfile.close()
            if os.path.exists(path_filename):
                data = MultipartEncoder({'roomId': RoomID, "files": (filename, open(path_filename, 'rb'), 'text/csv')})
                request = requests.post('https://webexapis.com/v1/messages', data=data, headers = {"Authorization": "Bearer " + bearer, 'Content-Type': data.content_type})
        else:
            msg = "There's no vulnerability for HOST " + HOSTNAME + ". If the host just registered, it would take a while to collect the vulnerabilities information, please try again later."
            send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg}) 
    else:
        msg = CODE + CODE_TEXT
        send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg}) 


def client_certificates(result, webhook):
    PersonId = result['personId']
    PersonEmail = send_get('https://webexapis.com/v1/people/{0}'.format(PersonId))['emails']
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " | " + str(PersonEmail[0]) + " | submit \"client certificates\" request.", file=open("Certificate_output.log", "a"))
    CSR_content = """[Version]

Signature = "$Windows NT$"
    
[NewRequest]

Subject = "CN={CommonName}, O={Organization}, OU={Department}, L={City}, S={Province}, C={Country}, E={Email}"

Exportable = True

KeyLength = 4096

KeySpec = 1

KeyUsage = 0xA0

MachineKeySet = FALSE

ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"

RequestType = PKCS10

FriendlyName = {CommonName}_{CertificateTemplate}_{DateTime}

[Extensions]

[RequestAttributes]

CertificateTemplate = {CertificateTemplate}
""".format(CommonName=result['inputs']['CN'], Organization=result['inputs']['O'], Department=result['inputs']['OU'], City=result['inputs']['L'], Province=result['inputs']['S'], Country=result['inputs']['C'], Email=result['inputs']['Email'], CertificateTemplate=result['inputs']['CertificateType'], DateTime=time.strftime("%Y-%m-%d", time.localtime()) )    
    filename = ''.join(random.choice(string.ascii_letters) for i in range(20))
    with open(filename, 'w') as CSRfile:
        CSRfile.writelines(CSR_content)
    CSRfile.close()
    environment = result['inputs']['Environment']  # tells if PROD or NON-PROD
    comment_file = filename + "_comment"
    comments = result['inputs']['Comments']
    with open(comment_file, 'w') as Commentfile:
        Commentfile.writelines(comments)
    Commentfile.close()
    if os.path.isfile(filename):
        Generate_Certificate = subprocess.Popen(['powershell.exe', './Generate_Certificate.ps1', filename, environment, comment_file])  # get file details, PROD or NON-PROD, write to comment_file if necessary
        print(Generate_Certificate.pid)
        Generate_Certificate.wait()
    else:
        print(filename, "doesn't exist")
    if Generate_Certificate.returncode != 0:
        msg = "Invalid result: " + str(Generate_Certificate.returncode) + " Please check the Certificate_output.log to get more detail."
    else:
        msg = "Email has been sent to " + result['inputs']['Email'] + " with the PFX file and password."
    send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})    

"""
def zip_directory(directory, zip_name):
    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zip_file:
        print(list(os.walk(f"BatchClientCertificate\\{directory}")))
        for files in os.walk(f"BatchClientCertificate\\{directory}"):
            if len(files[1]) == 1:

                zip_directory(files[1][0], zip_name)
            if len(files[2]) == 1:
                zip_file.write(os.path.join(files[0], files[2][0]), os.path.relpath(files[2][0], directory))
"""

#  def eop_phishsim(result):
#      Remove = result['inputs']['Remove']
#      if Remove == 'YES':
#          EOP_PhishSim_result = subprocess.run(['powershell.exe', '-File', './EOPPhishSim.ps1', '-remove'], capture_output=True, text=True)
#          msg = EOP_PhishSim_result.stdout
#          print(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " | submit \"Clean the current Phishing Simulation configuration\" request", file=open("Security_Assistant_Bot.log", "a"))
#      else:
#          Name = result['inputs']['Name'].replace(" ", "")
#          Domain = result['inputs']['Domain'].split(',')
#          IP = result['inputs']['IP'].split(',')
#          if len(Domain) > 20:
#              msg = "Domain entries can NOT be more than 20."
#          elif len(IP) > 10:
#              msg = "IP entries can NOT be more than 10."
#          else:
#              print(Name)
#              Domain = ','.join(Domain)
#              print(Domain)
#              IP = ','.join(IP)
#              print(IP)
#              EOP_PhishSim_result = subprocess.run(['powershell.exe', '-File', './EOPPhishSim.ps1', Name, Domain, IP], capture_output=True, text=True)
#              msg = EOP_PhishSim_result.stdout
#              print(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " | submit \"EOP Phish Simulation Configuration\" request with Domain " + Domain + " and with IP " + IP, file=open("Security_Assistant_Bot.log", "a"))
#      if msg != None:
#          send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})


app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def teams_webhook():
    if request.method == 'POST':
        webhook = request.get_json(silent=True)
        if webhook['resource'] == "attachmentActions" and webhook['data']['type'] == "submit":
            result = send_get('https://webexapis.com/v1/attachment/actions/{0}'.format(webhook['data']['id']))
            #print(result)
            if result['inputs']['id'] == "ReleaseEmails":
                releaseemails(result, webhook)
            if result['inputs']['id'] == "QualysAssets":
                queryassets(result, webhook)
            if result['inputs']['id'] == "ClientCertificates":
                client_certificates(result, webhook)
            if result['inputs']['id'] == "SingleOrBatch":
                if result["inputs"]["Batch"] == "True":
                    file_path = "./Client_Certificate_Information_Template.csv"
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as file:
                            send_put("https://webexapis.com/v1/messages/" + result["messageId"],
                                    {
                                        "roomId": webhook['data']['roomId'], 
                                        "attachments":[
                                                    {
                                                        "contentType": "application/vnd.microsoft.card.adaptive",
                                                        "content": {
                                                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                            "type": "AdaptiveCard",
                                                            "version": "1.2",
                                                            "body": [
                                                            {
                                                                "type": "TextBlock",
                                                                "size": "Large",
                                                                "weight": "Bolder",
                                                                "text": "Client Certificate Request",
                                                                "horizontalAlignment": "Center"
                                                            },
                                                            {
                                                                "type": "TextBlock",
                                                                "text": "To make a batch request, please download the file attached below:"
                                                            }]
                                                        }
                                            }
                                        ],
                                        "markdown": "Client Certificates"
                                    }
                            )
                            parent_id = send_get("https://webexapis.com/v1/messages/" + result["messageId"])["parentId"]
                            data = MultipartEncoder({'roomId': webhook['data']['roomId'], "parentId": parent_id, "files": (file_path, file, 'text/csv')})
                            requests.post("https://webexapis.com/v1/messages/", data=data, headers = {"Authorization": "Bearer " + bearer, 'Content-Type': data.content_type})
                            send_post("https://webexapis.com/v1/messages/",
                                    {
                                        "roomId": webhook['data']['roomId'],
                                        "parentId": parent_id,
                                        "attachments":[
                                                    {
                                                        "contentType": "application/vnd.microsoft.card.adaptive",
                                                        "content": {
                                                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                            "type": "AdaptiveCard",
                                                            "version": "1.2",
                                                            "body": [
                                                            {
                                                                "type": "TextBlock",
                                                                "wrap": True,
                                                                "text": "Once you have finished filling out the entries in the CSV file, please REPLY to this message and upload the file TO THIS THREAD"
                                                            },
                                                            {
                                                                "type": "TextBlock",
                                                                "weight": "Bolder",
                                                                "text": "CertificateTemplate HAS ONLY 3 VALID OPTIONS:\r1. SLRR\r2. DrugPlan2.0\r3. ClientAuthenticationCNET-privatekeyexportable",
                                                                "wrap": True
                                                            },
                                                            {
                                                                "type": "TextBlock",
                                                                "weight": "Bolder",
                                                                "text": "\nCA HAS ONLY 2 VALID OPTIONS:\r1. PROD\r2. NON-PROD",
                                                                "wrap": True
                                                            },
                                                            {
                                                                "type": "TextBlock",
                                                                "weight": "Bolder",
                                                                "text": "The CommonName field MUST BE NON-EMPTY",
                                                                "wrap": True
                                                            }]
                                                        }
                                            }
                                        ],
                                        "markdown": "Batch Client Certificates"
                                    }
                            )
                else:
                    send_put("https://webexapis.com/v1/messages/" + result["messageId"],
                            {
                                "roomId": webhook['data']['roomId'], 
                                "attachments": [
                                                {
                                                "contentType": "application/vnd.microsoft.card.adaptive",
                                                "content": {
                                                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                    "type": "AdaptiveCard",
                                                    "version": "1.2",
                                                    "body": [
                                                    {
                                                        "type": "TextBlock",
                                                        "size": "Large",
                                                        "weight": "Bolder",
                                                        "text": "Client Certificate Request",
                                                        "horizontalAlignment": "Center"
                                                    },
                                                    {
                                                        "type": "TextBlock",
                                                        "weight": "Bolder",
                                                        "text": "(Notice: comma is NOT allowed in all fields)",
                                                        "horizontalAlignment": "Center"
                                                    },
                                                    {
                                                        "type": "TextBlock",
                                                        "text": "Certificate Type"
                                                    },
                                                    {
                                                        "type": "Input.ChoiceSet",
                                                        "id": "CertificateType",
                                                        "choices": [
                                                            {
                                                                "title": "SLRR Certificate",
                                                                "value": "SLRR"
                                                            },
                                                            {
                                                                "title": "Drug Plan Certificate",
                                                                "value": "DrugPlan2.0"
                                                            },
                                                            {
                                                                "title": "Client Certificate",
                                                                "value": "ClientAuthenticationCNET-privatekeyexportable"
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        "type": "Input.ChoiceSet",
                                                        "id": "Environment",
                                                        "choices": [
                                                            {
                                                                "title": "PROD",
                                                                "value": "PROD"
                                                            },
                                                            {
                                                                "title": "NON-PROD",
                                                                "value": "NON-PROD"
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Common Name",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "CN"
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Organization",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "O"
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Department",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "OU"
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "City",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "L"
                                                    },
                                                    {
                                                        "type": "Input.ChoiceSet",
                                                        "id": "S",
                                                        "choices": [
                                                            {
                                                                "title": "Alberta",
                                                                "value": "AB"
                                                            },
                                                            {
                                                                "title": "British Columbia",
                                                                "value": "BC"
                                                            },
                                                            {
                                                                "title": "Manitoba",
                                                                "value": "MB"
                                                            },
                                                            {
                                                                "title": "New Brunswick",
                                                                "value": "NB"
                                                            },
                                                            {
                                                                "title": "Newfoundland and Labrador",
                                                                "value": "NL"
                                                            },
                                                            {
                                                                "title": "Nova Scotia",
                                                                "value": "NS"
                                                            },
                                                            {
                                                                "title": "Northwest Territories",
                                                                "value": "NT"
                                                            },
                                                            {
                                                                "title": "Nunavut",
                                                                "value": "NU"
                                                            },
                                                            {
                                                                "title": "Ontario",
                                                                "value": "ON"
                                                            },
                                                            {
                                                                "title": "Prince Edward Island",
                                                                "value": "PE"
                                                            },
                                                            {
                                                                "title": "Quebec",
                                                                "value": "QC"
                                                            },
                                                            {
                                                                "title": "Saskatchewan",
                                                                "value": "SK"
                                                            },
                                                            {
                                                                "title": "Yukon",
                                                                "value": "YT"
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Country",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "value": "CA",
                                                        "id": "C"
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Email",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "Email"
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Comments(Optional)",
                                                        "isMultiline": True,
                                                        "id": "Comments"
                                                    }
                                                    ],
                                                    "actions": [
                                                    {
                                                        "type": "Action.Submit",
                                                        "title": "Submit",
                                                        "data": {
                                                        "cardType": "input",
                                                        "id": "ClientCertificates"
                                                        }
                                                    }
                                                    ]
                                                }
                                                }
                                                ],
                                "markdown": "Client Certificates"
                            }
                    )
                #client_certificates(result, webhook)
#            if result['inputs']['id'] == "EOPPhishSim":
#                eop_phishsim(result)
        if webhook['resource']== "messages" and webhook['data']['personEmail']!= bot_email:
            print(webhook)
            msg = None
            if "@webex.bot" not in webhook['data']['personEmail']:
                result = send_get('https://webexapis.com/v1/messages/{0}'.format(webhook['data']['id']))
                in_message = result.get('text', '').lower()
                in_message = in_message.replace(bot_name.lower() + " ", '')
                if in_message.startswith('help'):
                    msg = help_me()
                elif in_message.startswith('hello'):
                    msg = greetings()
#                elif in_message.startswith("eop phishsim"):
#                    if accesslist_ADMIN == "ALL" or webhook['data']['personEmail'].lower() in accesslist_ADMIN or webhook['data']['personEmail'].lower() in accesslist_EOPPHISHSIM:
#                        requester = webhook['data']['personEmail'].lower()
#                        send_post("https://webexapis.com/v1/messages/", 
#                            {
#                                "roomId": webhook['data']['roomId'], 
#                                "parentId": webhook['data']['id'],
#                                "attachments": [
#                                                {
#                                                "contentType": "application/vnd.microsoft.card.adaptive",
#                                                "content": {
#                                                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
#                                                    "type": "AdaptiveCard",
#                                                    "version": "1.2",
#                                                    "body": [
#                                                    {
#                                                        "type": "TextBlock",
#                                                        "size": "Large",
#                                                        "weight": "Bolder",
#                                                        "text": "EOP Phish Simulation Configuration",
#                                                        "horizontalAlignment": "Center"
#                                                    },
#                                                    {
#                                                        "type": "TextBlock",
#                                                        "weight": "Bolder",
#                                                        "text": "(Notice: You can ONLY specify up to 20 Domain entries and 10 IP entries separated by commas.)",
#                                                        "horizontalAlignment": "Center"
#                                                    },
#                                                    {
#                                                        "type": "Input.Toggle",
#                                                        "title": "Clean the current Phishing Simulation configuration? (YES/NO)",
#                                                        "valueOn": "YES",
#                                                        "valueOff": "NO",
#                                                        "id": "Remove"
#                                                    },
#                                                    {
#                                                        "type": "Input.Text",
#                                                        "placeholder": "Name(No SPACE Allowed.)",
#                                                        "style": "text",
#                                                        "maxLength": 0,
#                                                        "value": "TerranovaPhishSim",
#                                                        "id": "Name"
#                                                    },
#                                                    {
#                                                        "type": "Input.Text",
#                                                        "placeholder": "Domain(ONLY up to 20 Domain entries separated by commas.)",
#                                                        "isMultiline": True,
#                                                        "id": "Domain"
#                                                    },
#                                                    {
#                                                        "type": "Input.Text",
#                                                        "placeholder": "IP(ONLY up to 10 IP entries separated by commas.)",
#                                                        "isMultiline": True,
#                                                        "id": "IP"
#                                                    }
#                                                    ],
#                                                    "actions": [
#                                                    {
#                                                        "type": "Action.Submit",
#                                                        "title": "Submit",
#                                                        "data": {
#                                                        "cardType": "input",
#                                                        "id": "EOPPhishSim"
#                                                        }
#                                                    }
#                                                    ]
#                                                }
#                                                }
#                                                ],
#                                "markdown": "EOP PhishSim"
#                            }
#                            )
#                        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " | " + requester + " | request Menu \"eop phishsim\"", file=open("Security_Assistant_Bot.log", "a"))
#                    else:
#                        msg = "Sorry, you (" + webhook['data']['personEmail'] + ") are NOT allowed to use this module. Please contact Hao.Ban@eHealthsask.ca for help."
#                elif in_message.startswith("requested quarantine"):
#                    if accesslist_ADMIN == "ALL" or webhook['data']['personEmail'].lower() in accesslist_ADMIN or webhook['data']['personEmail'].lower() in accesslist_REQUESTEDQUARANTINE:
#                        Requested_Quarantine = subprocess.Popen(['powershell.exe', './Quarantined_Emails_Requested.ps1', webhook['data']['roomId']])
#                        print(Requested_Quarantine.pid)
#                        Requested_Quarantine.wait()
#                    else:
#                        msg = "Sorry, you (" + webhook['data']['personEmail'] + ") are NOT allowed to use this module. Please contact Hao.Ban@eHealthsask.ca for help."
                elif in_message.startswith("script status"):
                    if accesslist_ADMIN == "ALL" or webhook['data']['personEmail'].lower() in accesslist_ADMIN or webhook['data']['personEmail'].lower() in accesslist_SCRIPTSTATUS:
                        Processor_Monitor = subprocess.Popen(['powershell.exe', './ProcessorMonitor.ps1', webhook['data']['roomId'], bearer])
                        print(Processor_Monitor.pid)
                        Processor_Monitor.wait()
                    else:
                        msg = "Sorry, you (" + webhook['data']['personEmail'] + ") are NOT allowed to use this module. Please contact Hao.Ban@eHealthsask.ca for help."
#                elif in_message.startswith("block address"):
#                    msg = block_address()
                elif in_message.startswith("release emails"):
                    if accesslist_ADMIN == "ALL" or webhook['data']['personEmail'].lower() in accesslist_ADMIN or webhook['data']['personEmail'].lower() in accesslist_RELEASEEMAIL:
                        send_post("https://webexapis.com/v1/messages/", 
                            {
                                "roomId": webhook['data']['roomId'], 
                                "parentId": webhook['data']['id'],
                                "attachments": [
                                                {
                                                "contentType": "application/vnd.microsoft.card.adaptive",
                                                "content": {
                                                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                    "type": "AdaptiveCard",
                                                    "version": "1.2",
                                                    "body": [
                                                    {
                                                        "type": "TextBlock",
                                                        "size": "Large",
                                                        "weight": "Bolder",
                                                        "text": "Release Encrypted Emails",
                                                        "horizontalAlignment": "Center"
                                                    },
                                                    {
                                                        "type": "TextBlock",
                                                        "text": "Before proceeding:",
                                                        "size": "Medium",
                                                        "weight": "Bolder"
                                                    },
                                                    {
                                                        "type": "Input.Toggle",
                                                        "title": "Do you know the sender? (Select-YES/Empty-NO)",
                                                        "valueOn": "YES",
                                                        "valueOff": "NO",
                                                        "id": "Question1"
                                                    },
                                                    {
                                                        "type": "Input.Toggle",
                                                        "title": "Are you expecting this message? (Select-YES/Empty-NO)",
                                                        "valueOn": "YES",
                                                        "valueOff": "NO",
                                                        "id": "Question2"
                                                    },
                                                    {
                                                        "type": "Input.Toggle",
                                                        "title": "Is this business-related? (Select-YES/Empty-NO)",
                                                        "valueOn": "YES",
                                                        "valueOff": "NO",
                                                        "id": "Question3"
                                                    },
                                                    {
                                                        "type": "Input.ChoiceSet",
                                                        "id": "Environment",
                                                        "choices": [
                                                            {
                                                                "title": "Microsoft O365",
                                                                "value": "O365"
                                                            },
                                                            {
                                                                "title": "Cisco ESA",
                                                                "value": "ESA"
                                                            }
                                                        ]
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Message ID",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "MID"
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "Recipient (Use COMMA to seperate Multi Email Address)",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "RECIPIENT"
                                                    }
                                                    ],
                                                    "actions": [
                                                    {
                                                        "type": "Action.Submit",
                                                        "title": "Submit",
                                                        "data": {
                                                        "cardType": "input",
                                                        "id": "ReleaseEmails"
                                                        }
                                                    }
                                                    ]
                                                }
                                                }
                                                ],
                                "markdown": "Release Emails"
                            }
                            )
                    else:
                        msg = "Sorry, you (" + webhook['data']['personEmail'] + ") are NOT allowed to use this module. Please contact Hao.Ban@eHealthsask.ca for help."
                elif in_message.startswith("qualys assets"):
                    if accesslist_ADMIN == "ALL" or webhook['data']['personEmail'].lower() in accesslist_ADMIN or webhook['data']['personEmail'].lower() in accesslist_QUALYS:
                        send_post("https://webexapis.com/v1/messages/", 
                            {
                                "roomId": webhook['data']['roomId'], 
                                "parentId": webhook['data']['id'],
                                "attachments": [
                                                {
                                                "contentType": "application/vnd.microsoft.card.adaptive",
                                                "content": {
                                                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                    "type": "AdaptiveCard",
                                                    "version": "1.2",
                                                    "body": [
                                                    {
                                                        "type": "TextBlock",
                                                        "size": "Medium",
                                                        "weight": "Bolder",
                                                        "text": "Query Qualys Assets",
                                                        "horizontalAlignment": "Center"
                                                    },
                                                    {
                                                        "type": "Input.Text",
                                                        "placeholder": "HOSTNAME",
                                                        "style": "text",
                                                        "maxLength": 0,
                                                        "id": "HOSTNAME"
                                                    }
                                                    ],
                                                    "actions": [
                                                    {
                                                        "type": "Action.Submit",
                                                        "title": "Submit",
                                                        "data": {
                                                        "cardType": "input",
                                                        "id": "QualysAssets"
                                                        }
                                                    }
                                                    ]
                                                }
                                                }
                                                ],
                                "markdown": "Qualys Assets"
                            }
                            )
                    else:
                        msg = "Sorry, you (" + webhook['data']['personEmail'] + ") are NOT allowed to use this module. Please contact Hao.Ban@eHealthsask.ca for help."
                elif in_message.startswith("client certificates"):
                    if accesslist_ADMIN == "ALL" or webhook['data']['personEmail'].lower() in accesslist_ADMIN or webhook['data']['personEmail'].lower() in accesslist_CERTIFICATES:
                        #requester = webhook['data']['personEmail'].lower()
                        print("PARENT ID:", webhook['data']['id'])
                        resp = send_post("https://webexapis.com/v1/messages/",
                                {
                                    "roomId": webhook['data']['roomId'], 
                                    "parentId": webhook['data']['id'],
                                    "attachments": [
                                                    {
                                                    "contentType": "application/vnd.microsoft.card.adaptive",
                                                    "content": {
                                                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                        "type": "AdaptiveCard",
                                                        "version": "1.3",
                                                        "body": [
                                                            {
                                                            "type": "TextBlock",
                                                            "size": "Large",
                                                            "text": "Client Certificate Request",
                                                            "horizontalAlignment": "Center"
                                                            },
                                                            {
                                                            "type": "TextBlock",
                                                            "text": "What kind of request would you like to make?"
                                                            },
                                                            {
                                                            "type": "Input.ChoiceSet",
                                                            "id": "Batch",
                                                            "value": "False",
                                                            "choices": [
                                                                {
                                                                    "title": "Single request",
                                                                    "value": "False"
                                                                },
                                                                {
                                                                    "title": "Batch request",
                                                                    "value": "True"
                                                                }
                                                            ]
                                                            },
                                                        ],
                                                        "actions": [
                                                                    {
                                                                    "type": "Action.Submit",
                                                                    "title": "Submit",
                                                                    "data": {
                                                                    "cardType": "input",
                                                                    "id": "SingleOrBatch"
                                                                    }
                                                                }
                                                        ]
                                                    }
                                                }
                                    ],
                                "markdown": "Client Certificates"
                            }
                        )
                        #print(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " | " + requester + " | request \"client certificates\" menu.", file=open("Certificate_output.log", "a"))
                    else:
                        msg = "Sorry, you (" + webhook['data']['personEmail'] + ") are NOT allowed to use this module. Please contact Hao.Ban@eHealthsask.ca for help."
                elif "data" in webhook.keys() and "files" in webhook["data"].keys() and "parentId" in webhook["data"].keys():
                    parent_msg = send_get("https://webexapis.com/v1/messages/" + webhook["data"]["parentId"])
                    if parent_msg["text"].lower() == "client certificates":
                        child_msg = send_get("https://webexapis.com/v1/messages?roomId={0}&parentId={1}".format(webhook["data"]["roomId"], webhook["data"]["parentId"]))["items"]
                        if len(child_msg) <= 15:
                            for m in child_msg:
                                if m["personEmail"] == bot_email and "markdown" in m.keys() and m["markdown"] == "Batch Client Certificates":
                                    file_type = requests.head(webhook["data"]["files"][0], headers={"Authorization": "Bearer " + bearer}).headers["Content-Type"]
                                    if file_type == "text/csv":
                                        current_datetime = datetime.datetime.now()
                                        filename = f"{webhook["data"]["personEmail"]}_{current_datetime.year:04}{current_datetime.month:02}{current_datetime.day:02}_{current_datetime.hour:02}{current_datetime.minute}"
                                        #print(filename)
                                        #time.sleep(10000)
                                        file_content = send_get(webhook["data"]["files"][0], js = False).content
                                        tmp = tempfile.NamedTemporaryFile(suffix = ".csv", dir = ".", delete = False)
                                        with open(tmp.name, "wb") as t:
                                            t.write(file_content)
                                        test = subprocess.Popen(['powershell.exe', './AutoGenerate_Client_CertificateTEST.ps1', tmp.name, filename])
                                        test.communicate()
                                        tmp.close()

                                        time.sleep(5)
                                        os.remove(tmp.name)

                                        zip_name = filename + ".zip"
                                        with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zip_file:
                                            #print(list(os.walk(f"BatchClientCertificate\\{filename}")))
                                            for root, directory, files in os.walk(f"BatchClientCertificate\\{filename}"):
                                                for file in files:
                                                    arc_name = root[root.find("\\") + 1:]
                                                    zip_file.write(os.path.join(root, file), os.path.join(arc_name, file))
                                        time.sleep(5)
                                        with open(zip_name, "rb") as file:
                                                data = MultipartEncoder({'roomId': webhook['data']['roomId'], "parentId": webhook["data"]["parentId"], "files": (zip_name, file)})
                                                res = requests.post("https://webexapis.com/v1/messages/", data=data, headers = {"Authorization": "Bearer " + bearer, 'Content-Type': data.content_type})

                                        time.sleep(5)    
                                        os.remove(zip_name)
                                    else:
                                        not_csv_msg = "Sorry, but I only accept CSV messages."
                                        send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "parentId": webhook["data"]["parentId"], "markdown": not_csv_msg})

                        else:
                            gt15_msg = "Sorry, but I will not process threads with more than 15 messages. Please make another client certificate request."
                            send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "parentId": webhook["data"]["parentId"], "markdown": gt15_msg})
                        
                else:
                    msg = "Sorry, but I did not understand your request. Type `Help` to see what I can do"
                if msg != None:
                    send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})
        if webhook['resource'] == "memberships" and webhook['data']['personEmail'] == bot_email:
            send_post("https://webexapis.com/v1/messages/",
                            {
                                "roomId": webhook['data']['roomId'],
                                "markdown": (greetings() +
                                             "**Note This is a group room and you have to call "
                                             "me specifically with `@%s` for me to respond**" % bot_name)
                            }
                            )
        return "true"
    elif request.method == 'GET':
        message = "<center><img src=\"https://avatar-prod-us-east-2.webexcontent.com/Avtr~V1~53fcb9d7-99c3-4fe5-a83b-f656c16211e5/V1~ccaf38fc8d2109cce27c723a55010f2f9b523d7a49596037da2cad3d0269498c~7fd13ec7094e44fb931d06d0bd1ed109\" alt=\"Webex Teams Bot\" style=\"width:256; height:256;\"</center>" \
                  "<center><h2><b>Congratulations! Your <i style=\"color:#ff8000;\">%s</i> bot is up and running.</b></h2></center>" \
                  "<center><b><i>Don't forget to create Webhooks to start receiving events from Webex Teams!</i></b></center>" % bot_name
        return message

def main():
    global bot_email, bot_name, root_kb, requester
    if len(bearer) != 0:
        test_auth = send_get("https://webexapis.com/v1/people/me", js=False)
        if test_auth.status_code == 401:
            print("Looks like the provided access token is not correct.\n"
                  "Please review it and make sure it belongs to your bot account.\n"
                  "Do not worry if you have lost the access token. "
                  "You can always go to https://developer.webex.com/my-apps "
                  "and generate a new access token.")
            sys.exit()
        if test_auth.status_code == 200:
            test_auth = test_auth.json()
            bot_name = test_auth.get("displayName","")
            bot_email = test_auth.get("emails","")[0]
    else:
        print("'bearer' variable is empty! \n"
              "Please populate it with bot's access token and run the script again.\n"
              "Do not worry if you have lost the access token. "
              "You can always go to https://developer.webex.com/my-apps "
              "and generate a new access token.")
        sys.exit()

    if "@webex.bot" not in bot_email:
        print("You have provided an access token which does not relate to a Bot Account.\n"
              "Please change for a Bot Account access token, view it and make sure it belongs to your bot account.\n"
              "Do not worry if you have lost the access token. "
              "You can always go to https://developer.webex.com/my-apps "
              "and generate a new access token for your Bot.")
        sys.exit()
    else:
        app.run(host='localhost', port=5000)

if __name__ == "__main__":
    main()