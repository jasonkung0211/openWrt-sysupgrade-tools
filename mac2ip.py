#!/usr/local/bin/python

import scapy.all as scapy
import argparse
import socket
import re
import time
import hashlib
import requests
import json


# fping -c 1 -g 192.168.8.0/24 && arp -n

keys_url = "https://jasonkung.execute-api.us-east-1.amazonaws.com/dev/certificates"


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Target IP/IP Range")
    options = parser.parse_args()
    return options


def get_cert_from_aws(euinwk):
    saltkey = 'te+H&#o_4eFris3echuKejotecrlcepr'
    timestamp = str(int(time.time()))
    string_to_sha1 = saltkey + euinwk + timestamp
    mysha1 = hashlib.sha1(string_to_sha1.encode('utf-8')).hexdigest()
    url = keys_url
    headers = {
        'X-ETI-Api-Key': euinwk,
        'X-ETI-Time': timestamp,
        'X-ETI-Token': mysha1,
        'cache-control': "no-cache",
    }
    try:
        response = requests.request("POST", url, headers=headers, timeout=2)
    except requests.exceptions.ConnectionError:
        return None
    if response.status_code < 300:
        return parse_cert(response.text)
    return None


def parse_cert(certifacation):
    cert_obj = json.loads(certifacation)
    # certificate = cert_obj['certificatePem']
    private_key = cert_obj['privateKey']
    # public_key = cert_obj['publicKey']
    # root_ca = cert_obj['rootCA']
    return private_key.strip()


def check_eui_valid(euinwk):
    return len(euinwk) == 16 and euinwk[0:6] == 'F87AEF'


def scan(ip, _macfilter):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []

    for element in answered_list:
        if not element[1].hwsrc.startswith(tuple(_macfilter)):
            continue
        zigbee = get_zigbee_mac_value(element[1].hwsrc).strip()
        if check_eui_valid(zigbee):
            key = get_cert_from_aws(zigbee)
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "zigbee": zigbee, "pkey": key}
        else:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "zigbee": zigbee, "pkey": ""}

        clients_list.append(client_dict)

    clients_list.sort(key=lambda x: x["mac"].lower())
    return clients_list


def print_result(results_list):
    print(" IP\t\t\tMAC Address\t\tZigbee MAC\t\thas key")
    print("-" * 65)
    for count, client in enumerate(results_list, start=1):
        print("".format())
        print("{:-3d}) {}\t{}\t{}\t{}".format(count, client["ip"], client["mac"].upper(), client["zigbee"], str(not(not client["pkey"]))))


def get_zigbee_mac_value(mac):
    wlan_mac = re.sub('[:]', '', mac).upper()
    return wlan_mac[:8] + "0000" + str(hex(int(wlan_mac[8:12], 16) - 0x2300))[2:].upper()


# def int_to_mac(macint):
#     if type(macint) != int:
#         raise ValueError('invalid integer')
#     return ':'.join(['{}{}'.format(a, b)
#                      for a, b
#                      in zip(*[iter('{:012x}'.format(macint))]*2)])
#
#
# def mac_to_int(mac):
#     res = re.match('^((?:(?:[0-9a-f]{2}):){5}[0-9a-f]{2})$', mac.lower())
#     if res is None:
#         raise ValueError('invalid mac address')
#     return int(res.group(0).replace(':', ''), 16)


if __name__ == '__main__':
    macprefix = ['9c:65:f9', '']
    scan_result = scan(get_host_ip() + '/24', macprefix)
    print_result(scan_result)
