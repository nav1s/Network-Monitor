from tkinter import *
from tkinter import messagebox
from time import strftime

from scapy.all import *
from threading import Thread

import socket


class PortScanner(object):
    def __init__(self, ip=None):
        self.master = Tk()
        self.master.geometry('600x500')
        self.master.title('Port Scanner')

        self.lastip = ''

        # Console Frame
        self.console_frame = Frame(self.master)

        self.scrollbar = Scrollbar(self.console_frame)

        self.console_text = Text(self.console_frame, yscrollcommand=self.scrollbar.set, fg='#23BFB1', bg='#130000',
                                 state=DISABLED)

        self.scrollbar.config(command=self.console_text.yview)

        self.closed_port = 0x14

        # Input Frame
        self.frame = Frame(self.master, width='200')

        self.scan_button = Button(self.frame, text='     Scan     ', command=self.scan)

        self.print_button = Button(self.frame, text='Save To file', command=self.print_to_file)

        self.host_name = Button(self.frame, text='Resolve host name', command=self.host)

        self.ip = Entry(self.frame)  # ip text

        if ip:
            self.ip.insert(0, ip)
            self.ip.config(state=DISABLED)

        self.port = Frame(self.frame, width=10)  # port text

        self.starting_port = Entry(self.port, width=8)

        self.finish_port = Entry(self.port, width=8)

        # dictionary of important known ports
        self.port_dict = {20: 'FTP', 21: 'FTP', 22: 'SSH', 25: 'SMTP', 110: 'POP3', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
                          989: 'FTPS',
                          990: 'FTPS'}

        self.mod_list = ['Regular Scan', 'Stealth Scan', 'Fin Scan']

        self.var = StringVar(self.master)
        self.var.set(self.mod_list[0])  # default value

        self.options = OptionMenu(self.frame, self.var, self.mod_list[0], self.mod_list[1], self.mod_list[2])

    def change_ip(self, ip):
        """
        change the ip to scan
        :param ip: required ip to change
        """
        self.ip.config(state=NORMAL)
        self.ip.delete(1.0, END)
        self.ip.insert(0, ip)
        self.ip.config(state=DISABLED)

    def host(self):
        """
        finds some info about the host
        """
        s = self.get_host_name(self.ip.get())
        if s == self.ip.get():
            self.output_console('Could not resolve this address')
        else:
            self.output_console('{} host name is: {}'.format(self.ip.get(), s))

    def print_to_file(self):  # prints everything in the console to a file
        """
        saves results to file
        """
        with open('Scan Results - {0}({1}).txt'.format(self.lastip, self.var.get()), 'w') as f:
            f.write(self.console_text.get('0.0', END))

    def output_console(self, text):
        """
        prints a given text to the console
        :param text: text to output
        """
        self.console_text.config(state=NORMAL)  # enable writing in the console

        self.console_text.insert(END, text + '\n')  # write the required text
        self.console_text.see(END)
        self.console_text.config(state=DISABLED)  # disable writing in console

    def reset_console(self):
        """
        deletes all text in the console
        """
        self.console_text.config(state=NORMAL)
        self.console_text.delete(1.0, END)  # delete all text
        self.console_text.config(state=DISABLED)

    def start(self):
        """
        starts the gui
        """
        self.gui()
        self.master.mainloop()

    def gui(self):
        """
        setup the gui
        """

        # Init Components
        ip_label = Label(self.frame, text='IP')
        port_label = Label(self.frame, text='Port')

        self.frame.pack(pady=15, padx=15)

        ip_label.grid(row=0, column=1)
        self.ip.grid(row=0, column=2)

        port_label.grid(row=1, column=1)
        self.port.grid(row=1, column=2)

        self.starting_port.grid(row=0, column=0)

        Label(self.port, text='-').grid(row=0, column=1, padx=3)

        self.finish_port.grid(row=0, column=2, padx=3)

        self.scan_button.grid(row=0, column=5)

        self.print_button.grid(row=1, column=5)

        self.options.grid(row=0, column=0)

        # self.host_name.grid(row=5, column=4)

        self.console_frame.pack(expand=1, pady=15, padx=15, fill=BOTH)

        self.scrollbar.pack(side=RIGHT, fill=Y)

        self.console_text.pack(expand=1, fill=BOTH)

    def add_port(self, port_number):
        """
        add a port to the result list
        :param port_number: the port number
        """
        if port_number in self.port_dict:  # check if the port is known
            out = 'port {}({}): Open'.format(port_number, self.port_dict[port_number])
        else:
            out = 'port {} is open'.format(port_number)

        self.output_console(out)

    def fred(self, starting_port, finish_port, scan_type):
        """
        scan fred
        :param starting_port: port to start
        :param finish_port: port to finish
        :param scan_type: type of scan
        """

        self.output_console('Scan Started at {}\n'.format(strftime('%X')))

        if self.scan_button['text'] == 'Scan':
            return

        if scan_type == self.mod_list[0]:
            ports = self.normal_scan(self.lastip, starting_port, finish_port)

        elif scan_type == self.mod_list[1]:
            ports = self.stealth_scan(self.lastip, starting_port, finish_port)

        else:
            ports = self.fin_scan(self.lastip, starting_port, finish_port)

        for port in ports:
            self.add_port(port)

        self.scan_button['text'] = 'Scan'

        self.output_console('\n\nThe target has {} open ports in the requested range'.format(len(ports)))
        self.output_console('Scan finished at {}'.format(strftime('%X')))

    def scan(self):
        """
        initialize a scan
        """
        if self.scan_button['text'] == 'Stop':
            self.lastip = self.ip.get()  # need test
            self.scan_button['text'] = 'Scan'

        elif self.check_ip():  # checks if the input is valid
            if not self.host_up(self.ip.get()):
                self.reset_console()
                self.output_console('Could not resolve the requested host')
                return

            if self.lastip != '':
                sure = messagebox.askokcancel('Port Scanner', 'The previous scan will be erased from the console')
                if not sure:
                    return

                self.reset_console()

            self.lastip = self.ip.get()

            if not self.check_port(self.starting_port.get()) or not self.check_port(self.finish_port.get()):
                self.output_console('Wrong syntax')
                return

            self.scan_button['text'] = 'Stop'

            a = Thread(target=self.fred,
                       args=(int(self.starting_port.get()), int(self.finish_port.get()) + 1, self.var.get()))
            a.start()  # starts a new fred

    def check_ip(self):
        """
        checks if the ip is valid
        :return: True if valid otherwise False
        """
        ip = self.ip.get()

        if ip == '':
            self.output_console('Please type an ip address\n')
            return False

        # checking if the ip is correct
        if ip.count('.') == 3 and ip.replace('.', '').isdigit() and ip[-1] != '.':
            num = ip.split('.')

            for x in num:
                if int(x) > 255:
                    self.output_console('Please type a valid ip address\n')
                    return False

            return True

        self.output_console('Please type a valid ip address\n')
        return False

    def stealth_scan(self, ip, start, end):
        """
        scans through all the requested ports in a stealthy way
        :param ip: requested ip
        :param start: first port
        :param end: last port
        :return: scan results
        """
        ans, _ = sr(IP(dst=ip) / TCP(sport=RandShort(), dport=range(start, end), flags='S'),
                    timeout=12)  # send syn packet

        ports = []
        for pck in ans:
            if pck:
                if pck[1][TCP].flags != self.closed_port:  # check if the flag of the returning packet say its closed
                    send(
                        IP(dst=ip) / TCP(sport=RandShort(), dport=pck[1][TCP].sport, flags='R'))  # close the connection
                    ports.append(pck[1][TCP].sport)

        return ports

    @staticmethod
    def check_port(port):
        """
        check if the port is valid
        :param port: a string to check
        :return: True if the string is a valid port otherwise False
        """
        if port.isdigit():
            if 65536 > int(port) > 0:
                return True
        return False

    @staticmethod
    def get_host_name(ip):
        """
        Finds the host name for a given host ip
        :param ip: requested ip
        :return: host name if found
        """
        if socket.getfqdn(ip)[:-6] == socket.getfqdn():  # checks i
            return socket.getfqdn()
        return socket.getfqdn(ip)

    @staticmethod
    def fin_scan(ip, first_port, last_port):
        """
        scans through all the requested ports
        :param ip: requested ip
        :param first_port: port to start from
        :param last_port: port to end at
        :return: scan results
        """
        ans, _ = sr(IP(dst=ip) / TCP(sport=RandShort(), dport=range(first_port, last_port), flags='F'), timeout=12)

        ports = []
        for pck in ans:
            if not pck:
                ports.append(pck)

        return ports

    @staticmethod
    def normal_scan(ip, first_port, last_port):
        """
        scans through all the requested ports
        :param ip: requested ip
        :param first_port: first port
        :param last_port: last port
        :return: scan results
        """
        ports = []
        for port in range(first_port, last_port):
            sock = socket.socket()
            sock.settimeout(0.05)  # set a timeout of 0.01 second to avoid delays

            if not sock.connect_ex((ip, port)):  # connect_ex returns 0 if it managed to connect
                sock.close()
                ports.append(port)

            sock.close()

        return ports

    @staticmethod
    def host_up(ip):
        """
        checks if the host is up
        :param ip: requested ip
        :return: True if the host is up otherwise False
        """
        ping = sr1(IP(dst=ip) / ICMP(), timeout=3)

        if ping:
            return True
        return False
