from PySide2 import QtCore
from scapy.all import *
from scapy import utils
from math import log
from threading import Thread
from time import time
import requests
import platform


class Scan(QtCore.QThread):
    status = QtCore.Signal(str)
    finished = QtCore.Signal()
    prog = QtCore.Signal(int)
    error = QtCore.Signal()
    device = QtCore.Signal(str)
    new_device = QtCore.Signal(str, str)

    def __init__(self):
        QtCore.QThread.__init__(self)

        self.mac = ''
        self.gate = ''

        self.ips = []
        self.macs = []

        self.vendor_api = 'http://api.macvendors.com/{}/'
        self.lookup_ip = '8.8.8.8'

    def __del__(self):
        self.wait()

    @staticmethod
    def reverse_ip(ip):
        """
        reverses target ip
        :param ip: target ip
        :return: reversed ip
        """
        new_ip = ip.split('.')
        new_ip.reverse()
        return '.'.join(new_ip)

    def resolve_name(self, ip):
        """
        :param ip: target ip address
        :return: hostname if found
        """
        pkt = sr1(IP(dst=self.gate) / UDP() / DNS(rd=1, qd=DNSQR(
            qname="{}.in-addr.arpa".format(self.reverse_ip(ip)), qtype='PTR')), timeout=0.2)

        if pkt:
            if 'DNSRR' in pkt:
                if pkt['DNSRR'].rdata != self.not_found:
                    return pkt['DNSRR'].rdata[:-1]

        try:
            return socket.gethostbyaddr(ip)[0]

        except socket.herror:
            return 'n\\a'

    def get_gate(self):
        """
        gets the the gateaway for the selected iface
        :return: gw if found
        """
        pkt = sr1(IP(dst=self.lookup_ip, ttl=1) / ICMP(), timeout=0.2, retry=2)
        if pkt:
            return pkt.src

        return ''

    def get_ven(self, mac):
        """
        :param mac: target mac address
        :return: vendor if found
        """
        try:
            request = requests.get(self.vendor_api.format(mac))
            if request.ok:
                return request.text.strip()

        except requests.exceptions.ConnectionError:
            pass

        return 'n\\a'

    def check(self, mac):
        """
        checks that the ip or mac aren't discovered already
        :param mac: target mac address
        :return: True if wasn't discovered otherwise False
        """
        if mac not in self.macs:
            self.macs.append(mac)
            return True

        return False

    @staticmethod
    def mask(bytes_network, bytes_mask):
        """
        calculates the network address and mask
        :param bytes_network: network address in bytes
        :param bytes_mask: network mask in bytes
        :return: network address / mask
        """
        if bytes_mask <= 0 or bytes_mask >= 0xFFFFFFFF:
            raise ValueError("illegal netmask value", hex(bytes_mask))

        network = utils.ltoa(bytes_network)  # calculate the network address
        netmask = 32 - int(round(log(0xFFFFFFFF - bytes_mask, 2)))  # calculate the mask range

        if netmask < 16:  # nets that have a mask bigger than that aren't supported
            return None

        return '{}/{}'.format(network, netmask)

    @staticmethod
    def ping(ip):
        """
        pings the target ip
        :param ip: target ip
        :return: ping timeout
        """
        st = time()
        ans = sr1(IP(dst=ip) / ICMP(), timeout=0.5)

        if ans:
            return '{}ms'.format(int((time() - st) * 100)), ans[IP].ttl

        return 'n\\a', None

    def detect_os(self, ip):
        """
        detects the os and ping timeout
        :param ip: target ip
        :return: os and ping
        """
        sc, ttl = self.ping(ip)

        if ttl:
            if ttl == 64:
                return 'Linux', sc

            elif ttl == 128:
                return 'Windows', sc

            else:
                print('{}/{}'.format(ip, ttl))
                return 'n\\a', sc

        return 'n\\a', 'n\\a'

    def analayzer(self, ip, mac):
        """
        analyze the given parmaters and sends to gui
        :param ip: target ip
        :param mac: target mac
        :return: True if it's not in the table already otherwise false
        """

        if self.check(mac):

            ven = self.get_ven(mac)

            if ip == conf.iface.ip:
                nam = socket.gethostname()
                system = platform.system()
                ping = 'n\\a'

            else:
                nam = self.resolve_name(ip)

                system, ping = self.detect_os(ip)

                if 'android' in nam:
                    system = 'Android'

                elif 'Apple' in ven:
                    system = 'iOS'

            dev = ['Online', ip, nam, mac, ven, system, ping]
            self.device.emit('`'.join(dev))

            if ip != conf.iface.ip:
                return True

            return False

    def get_net(self):
        """
        :return: broadcast address
        """
        if conf.iface.ip == '0.0.0.0' or not self.gate:
            raise TypeError

        for x in conf.route.routes:
            try:
                if conf.iface in x:
                    net = self.mask(x[0], x[1])
                    if net:
                        return net

            except Exception as er:
                if type(er) == ValueError:
                    continue

                print('{} ({})'.format(er, type(er)))

    def initial_scan(self):
        """
        scans for all online hosts on the current iface
        """
        self.status.emit('Initial scan has been activated')

        try:
            net = self.get_net()

            if not net:
                raise TypeError

            ans, _ = arping(net, retry=2, timeout=0.5)

        except TypeError:
            self.error.emit()
            return

        self.prog.emit(len(ans))

        for x in ans:
            ip = x[1].psrc
            mac = x[1].src

            if self.analayzer(ip, mac):
                pass

            self.prog.emit(1)

        self.prog.emit(0)

    def fil(self, pck):
        """
        checks if a new host has joined the network
        :param pck: sniffed packet
        """
        if 'DHCP' in pck:
            ip = pck['DHCP'].options[2][1]
            mac = pck.src

            if self.analayzer(ip, mac):
                self.new_device.emit(ip, 'joined')

    def run(self):
        """
        runs the necessary functions
        """
        try:
            self.gate = self.get_gate()

        except socket.gaierror:
            self.error.emit()
            return
        Thread(self.initial_scan()).start()
        self.status.emit('Scanning for new hosts')
        sniff(lfilter=self.fil)
