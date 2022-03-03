#!/usr/bin/env python3

# Author: hao.ban@ehealthsask.ca//banhao@gmail.com
# Version:
# Issue Date: March 02, 2022
# Release Note: 

from pyngrok import ngrok
import requests, json, sys, os, urllib3, paramiko, re, string, random, time, subprocess, csv, asyncio
import xml.etree.ElementTree as ET
from lxml.etree import fromstring
from requests_toolbelt.multipart.encoder import MultipartEncoder

urllib3.disable_warnings()

bearer = "" # BOT'S ACCESS TOKEN
headers = {
    "Accept": "application/json",
    "Content-Type": "application/json; charset=utf-8",
    "Authorization": "Bearer " + bearer
}

Qualys_username = ""
Qualys_password = ""

#clear registered webhooks
response = requests.get('https://webexapis.com/v1/webhooks', headers=headers)
if len(response.json()['items']) != 0:
    for i in range(len(response.json()['items'])):
        webhook_id = response.json()['items'][i]['id']
        del_webhook_response = requests.delete('https://webexapis.com/v1/webhooks/'+webhook_id,  headers=headers)

ngrok.connect(5000).public_url #Start ngrok on port 5000
ngrok_response = requests.get('http://127.0.0.1:4040/api/tunnels')
webhook_url = ngrok_response.json()['tunnels'][0]['public_url']
print(webhook_url)

#create new webhooks
response = requests.post('https://webexapis.com/v1/webhooks', json.dumps({"resource" : "messages","event" : "created","targetUrl" : webhook_url,"name" : "Security Assistant Bot"}), headers=headers)
response = requests.post('https://webexapis.com/v1/webhooks', json.dumps({"resource" : "memberships","event" : "created","targetUrl" : webhook_url,"name" : "Security Assistant Bot"}), headers=headers)
response = requests.post('https://webexapis.com/v1/webhooks', json.dumps({"resource" : "attachmentActions","event" : "created","targetUrl" : webhook_url,"name" : "Security Assistant Bot"}), headers=headers)


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


def help_me():
    return "Sure! I can help. Below are the commands that I understand:<br/>" \
           "`Help` - I will display what I can do.<br/>" \
           "`Hello` - I will display my greeting message<br/>" \
           "`Release Emails` <br/>" \
           "`Qualys Assets` <br/>" \
           "`Certificates` <br/>" \


def greetings():
    return "Hi, I am %s.<br/>" \
           "Type `Help` to see what I can do.<br/>" % bot_name


def releaseemails(result):
    if result['inputs']['Question1'] == 'YES' and result['inputs']['Question2'] == 'YES' and result['inputs']['Question3'] == 'YES':
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
            k = paramiko.RSAKey.from_private_key_file(os.path.expanduser('~\\.ssh\\id_rsa_esa'))
            ssh.connect("", username="", pkey=k)
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
                SMA_headers = {"Content-Type": "text/plain","Authorization": 'Basic '}
                SMA_body = {"action": "release","mids": SMA_MID,"quarantineName": "Encrypted Message","quarantineType": "pvo"}
                print(SMA_headers)
                print(SMA_body)
                SMA_response = requests.post("", data=json.dumps(SMA_body), headers=SMA_headers, verify=False)
                print(SMA_response.json())
                if SMA_response.status_code == 200 and SMA_response.json()['data']['totalCount'] == 1:
                    msg = "MID#"+MID+" is released successfully, please check your mailbox."
                    print(msg)
                    print(PersonName, PersonEmail, "submitted MID#", MID, "at", Created, "and is released successfully.", file=open("ReleaseEmail.log", "a"))
                if SMA_response.status_code == 200 and SMA_response.json()['data']['totalCount'] == 0:
                    msg = "MID#"+MID+" was already released by the others but wasn't from this bot service."
                    print(msg)    
    else:
        msg = "You answered \"NO\" to any of the questions above, please delete the email or mark it as \"Junk\" in your mail client."
        print(msg)
    send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})    


def queryassets(result):
    HOSTNAME = result['inputs']['HOSTNAME'].lower()
    xml = """<ServiceRequest>
<filters>
<Criteria field="tagName" operator="EQUALS">{TAGNAME}</Criteria>
<Criteria field="name" operator="CONTAINS">{HOSTNAME}</Criteria>
</filters>
</ServiceRequest>""".format(HOSTNAME=HOSTNAME, TAGNAME="Cloud Agent")
    headers = {'Content-Type': 'text/xml'}
    response = requests.post('https://qualysapi.qualys.com/qps/rest/2.0/search/am/hostasset', data=xml, headers=headers, auth=(Qualys_username, Qualys_password))
    root = ET.fromstring(response.text)
    status = root[0].text
    count = root[1].text
    if status == 'SUCCESS' and count != '0':
        msg = status + " | " + count + " | " + root[3][0].findall('name')[0].text + " | Asset ID:" + root[3][0].findall('id')[0].text + " | Host ID:" + root[3][0].findall('qwebHostId')[0].text + " | IP Address:" + root[3][0].findall('address')[0].text  + " | OS:"  + root[3][0].findall('os')[0].text
        HostID = root[3][0].findall('qwebHostId')[0].text
        AssetID = root[3][0].findall('id')[0].text
        FQDN = root[3][0].findall('fqdn')[0].text
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
            vuln_list(HostID,AssetID,RoomID)
    if status == 'SUCCESS' and count == '0':
        HOSTNAME = HOSTNAME.upper()
        xml = """<ServiceRequest>
<filters>
<Criteria field="tagName" operator="EQUALS">{TAGNAME}</Criteria>
<Criteria field="name" operator="CONTAINS">{HOSTNAME}</Criteria>
</filters>
</ServiceRequest>""".format(HOSTNAME=HOSTNAME, TAGNAME="Cloud Agent")
        headers = {'Content-Type': 'text/xml'}
        response = requests.post('https://qualysapi.qualys.com/qps/rest/2.0/search/am/hostasset', data=xml, headers=headers, auth=(Qualys_username, Qualys_password))
        root = ET.fromstring(response.text)
        status = root[0].text
        count = root[1].text
        if status == 'SUCCESS' and count != '0':
            msg = status + " | " + count + " | " + root[3][0].findall('name')[0].text + " | Asset ID:" + root[3][0].findall('id')[0].text + " | Host ID:" + root[3][0].findall('qwebHostId')[0].text + " | IP Address:" + root[3][0].findall('address')[0].text  + " | OS:"  + root[3][0].findall('os')[0].text
            HostID = root[3][0].findall('qwebHostId')[0].text
            AssetID = root[3][0].findall('id')[0].text
            FQDN = root[3][0].findall('fqdn')[0].text
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
                vuln_list(HostID,AssetID,RoomID)
        if status == 'SUCCESS' and count == '0':
            msg = "Can't find " + HOSTNAME + " in Qualys"
            send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})


def vuln_list(HostID,AssetID,RoomID):
    global root_kb
    try:
        len(root_kb[0][1])
        print(' *** There are ', len(root_kb[0][1]), 'QID records. *** ')
    except NameError:
        headers = {'X-Requested-With': 'Python'}
        URL = 'https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/?action=list'
        response = requests.post(URL, headers=headers, auth=(Qualys_username, Qualys_password), verify = False)
        root_kb = ET.fromstring(response.text)
        print(' *** Qualys Knowledge Base Data has been loaded into memory. *** ')
    ID = HostID
    AssetID = AssetID
    RoomID = RoomID
    URL = 'https://qualysapi.qualys.com/api/2.0/fo/asset/host/vm/detection/?action=list&ids=' + ID
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
            FQDN = root[0][1][0].findall('DNS')[0].text
        except IndexError:
            FQDN = 'NA'
        if FQDN != 'NA':
            if os.path.exists('vulnerabilities'):
                filename = FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
                path_filename = './vulnerabilities/' + FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
            else:
                os.mkdir('vulnerabilities')
                filename = FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
                path_filename = './vulnerabilities/' + FQDN + "_" + time.strftime('%Y-%m-%d', time.localtime()) + ".csv"
        else:
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
    else:
        msg = CODE + CODE_TEXT
        send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg}) 
    if os.path.exists(path_filename):
        data = MultipartEncoder({'roomId': RoomID, "files": (filename, open(path_filename, 'rb'), 'text/csv')})
        request = requests.post('https://webexapis.com/v1/messages', data=data, headers = {"Authorization": "Bearer " + bearer, 'Content-Type': data.content_type})


def certificates(result):
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
    environment = result['inputs']['Environment']
    with open(filename, 'w') as CSRfile:
        CSRfile.writelines(CSR_content)
    CSRfile.close()
    if os.path.isfile(filename):
        Generate_Certificate = subprocess.Popen(['powershell.exe', './Generate_Certificate.ps1', filename, environment])
        print(Generate_Certificate.pid)
        Generate_Certificate.wait()
    else:
        print(filename, "doesn't exist")
    if Generate_Certificate.returncode != 0:
        msg = "Invalid result: " + Generate_Certificate.returncode + " Please check the Certificate_output.log to get more detail."
    else:
        msg = "Email has been sent to " + result['inputs']['Email'] + " with the PFX file and password."
    send_post("https://webexapis.com/v1/messages/", {"roomId": webhook['data']['roomId'], "markdown": msg})    


app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def teams_webhook():
    if request.method == 'POST':
        global webhook
        webhook = request.get_json(silent=True)
        if webhook['resource'] == "attachmentActions" and webhook['data']['type'] == "submit":
            result = send_get('https://webexapis.com/v1/attachment/actions/{0}'.format(webhook['data']['id']))
            print(result)
            if result['inputs']['id'] == "ReleaseEmails":
                releaseemails(result)
            if result['inputs']['id'] == "QualysAssets":
                queryassets(result)
            if result['inputs']['id'] == "Certificates":
                certificates(result)
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
#                elif in_message.startswith("update iocs"):
#                    msg = update_iocs()
#                elif in_message.startswith("block address"):
#                    msg = block_address()
                elif in_message.startswith("release emails"):
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
                                                    "type": "Input.Text",
                                                    "placeholder": "MID",
                                                    "style": "text",
                                                    "maxLength": 0,
                                                    "id": "MID"
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
                elif in_message.startswith("qualys assets"):
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
                elif in_message.startswith("certificates"):
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
                                                    "text": "Certificate Request",
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
                                                            "title": "Client Certificate 1",
                                                            "value": "Client1"
                                                        },
                                                        {
                                                            "title": "Client Certificate 2",
                                                            "value": "Client2"
                                                        },
                                                        {
                                                            "title": "Client Certificate 3",
                                                            "value": "Client3"
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
                                                            "title": "UAT",
                                                            "value": "UAT"
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
                                                }
                                                ],
                                                "actions": [
                                                {
                                                    "type": "Action.Submit",
                                                    "title": "Submit",
                                                    "data": {
                                                    "cardType": "input",
                                                    "id": "Certificates"
                                                    }
                                                }
                                                ]
                                            }
                                            }
                                            ],
                            "markdown": "Certificates"
                        }
                        )
                else:
                    msg = "Sorry, but I did not understand your request. Type `Help me` to see what I can do"
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
        message = "<center><img src=\"https://avatar-prod-us-east-2.webexcontent.com/Avtr~V1~53fcb9d7-99c3-4fe5-a83b-f656c16211e5/V1~ccaf38fc8d2109cce27c723a55010f2f9b523d7a49596037da2cad3d0269498c~e79b3e7eaa094889b1cde299964b3fa6?quarantineState=evaluating\" alt=\"Webex Teams Bot\" style=\"width:256; height:256;\"</center>" \
                  "<center><h2><b>Congratulations! Your <i style=\"color:#ff8000;\">%s</i> bot is up and running.</b></h2></center>" \
                  "<center><b><i>Don't forget to create Webhooks to start receiving events from Webex Teams!</i></b></center>" % bot_name
        return message

def main():
    global bot_email, bot_name, root_kb
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