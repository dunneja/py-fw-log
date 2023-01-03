#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Filename     : py_fw_log.py
# Author       : Dunneja
# License      : MIT-license
# Comment      : This file is part of py-fw-log viewer.
# ----------------------------------------------------------------------------

"""
A program to parse iptables logs and display them in a console interface.
"""

import sys
import re
import getopt
import socket
from rich.table import Table
from rich.console import Console
from collections import Counter
from file_read_backwards import FileReadBackwards

def py_fw_log(argv):
    """
    py-fw-log command line interface to parse iptables/firewalld log files.
    """
    arg_log_file_name = ""
    arg_lines_to_show = ""
    arg_dns = ""
    arg_help = "{0} Usage: pyfwlog -l <logfile> -s <showlines> -d (Enables DNS resolution)".format(argv[0])    
    try:
        opts, args = getopt.getopt(argv[1:], "hi:l:s:d", ["help", "log_file_name=", 
        "lines_to_show=", "dns="])
    except:
        print(arg_help)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(arg_help)
            sys.exit(2)
        elif opt in ("-l", "--logfile"):
            arg_log_file_name = arg
        elif opt in ("-s", "--showlines"):
            arg_lines_to_show = arg
        elif opt in ("-d", "--dns"):
            arg_dns = True       
    fw_log_view(arg_log_file_name, int(arg_lines_to_show), arg_dns)

class fw_log_view():
    """
    Class to view iptables log file entries. 
    """
    def __init__(self, log_file_name, lines_to_show, dns=False):
        self.log_file_name = log_file_name
        self.lines_to_show = lines_to_show
        self.dns = dns
        self.main()

    def main(self):
        """
        Main method to loop through logs entries and call other methods.
        """
        try:
            self.main = True
            while self.main == True:
                self.iplist = []
                self.portlist = []
                self.data = {}
                self.log_line_count = 0
                grouping_re = re.compile('([^ ]+)=([^ ]+)')
                print("\n")
                table = Table(title="Py Firewall Log Viewer",
                    show_header=True, caption=self.log_file_name)
                table.add_column(
                    "Date & Time", justify="center", style="cyan", no_wrap=True)
                table.add_column("NIC", justify="center", style="green")
                table.add_column("PROTO", justify="center",
                    style="royal_blue1")
                table.add_column("SRC IP", justify="center",
                    style="dark_orange3")
                table.add_column("SPT", justify="center", style="gold1")
                table.add_column("DST IP", justify="center", style="plum2")
                table.add_column("DPT", justify="center",
                    style="bright_red", no_wrap=True)
                table.add_column("TTL", justify="center",
                    style="light_slate_grey", no_wrap=True)
                table.add_column("Hostname", justify="center", style="light_slate_grey", no_wrap=True)
                with FileReadBackwards(self.log_file_name, encoding="utf-8") as log_file:
                    for log_line in log_file:
                        if self.log_line_count < self.lines_to_show:
                            log_line = log_line.rstrip()
                            self.data = dict(grouping_re.findall(log_line))
                            self.date = log_line.split()
                            self.ipaddr = self.data['SRC']
                            self.ports = self.data['SPT']
                            self.iplist.append(self.ipaddr)
                            self.portlist.append(self.ports)
                            if self.dns == True:
                                self.hostname = self.get_hostname(self.ipaddr)
                            else:
                                self.hostname = "-"
                            self.log_line_count += 1
                            table.add_row(self.date[0]+" "+self.date[1]+" "+self.date[2]+" ", self.data['IN'], self.data['PROTO'], self.data[ 'SRC'], self.data['SPT'], self.data['DST'], self.data['DPT'], self.data['TTL'],self.hostname)
                console = Console()
                console.print(table)
                input("\nPress 'Enter' to show log viewer summary or 'CTRL-C' to Quit...\n")
                self.ip_sum()
                self.ports_sum()
                print(f"\nTotal Log lines Parsed: {str(self.log_line_count)}")
                with open(self.log_file_name, 'r') as log_file_count:
                    total_log_count = len(log_file_count.readlines())
                print(f"Total Blocked Entires in Log File: {total_log_count}\n")
                self.main = False 
        except KeyboardInterrupt:
            pass

    def ip_sum(self):
        """
        Building A Table Summary of IPs Blocked Vs Number of Hits.
        """
        ipcount = [ite for ite in Counter(self.iplist).most_common()]
        table = Table(title=f'\nBlocked IP Addresses', show_header=True,
                      caption=f'Top {str(self.log_line_count)} Summary')
        table.add_column("IP", justify="center", style="cyan", no_wrap=True)
        table.add_column("Hits", justify="center", style="magenta")
        for x in ipcount:
            table.add_row(str(x[0]), str(x[1]))
        console = Console()
        console.print(table)
        print("\n")

    def ports_sum(self):
        """
        Building A Table Summary of Ports Blocked Vs Number of Hits.
        """
        portcount = [ite for ite in Counter(self.portlist).most_common()]
        table = Table(title=f'Blocked Ports', show_header=True,
                      caption=f'Top {str(self.log_line_count)} Summary')
        table.add_column("Port", justify="center", style="cyan", no_wrap=True)
        table.add_column("Hits", justify="center", style="magenta")
        for x in portcount:
            table.add_row(str(x[0]), str(x[1]))
        console = Console()
        console.print(table)

    def get_hostname(self, ipaddr):
        """
        resolve ip address to hostname.
        """
        try:
            socket.setdefaulttimeout(5)
            hostname = socket.gethostbyaddr(ipaddr)
        except socket.error:
            hostname = '-'
        return hostname[0]

if __name__ == "__main__":
    py_fw_log(sys.argv)