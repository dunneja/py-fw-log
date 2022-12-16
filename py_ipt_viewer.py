#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Filename     : py_ipt_viewer.py
# Author       : Dunneja
# License      : MIT-license
# Comment      : This file is part of py iptables log viewer.
# ----------------------------------------------------------------------------

"""
A simple program to parse iptables logs and display them in a console interface.
"""

import re
import socket
from collections import Counter
from file_read_backwards import FileReadBackwards
from rich.console import Console
from rich.table import Table
from rich.progress import track

# Set iptables log file name and path.
log_file_name = "iptables.log"

# Set iptables input chain log.
input_chain_logname = r"IPTABLES:BLOCKED-CONN:"

# Set the number of log lines to display. 
lines_to_show = 20

def py_ipt_viewer():
    """
    table function, building tables and populating from log file.
    """
    print("\n")
    table = Table(
        title="Py IPTables Log Viewer", 
        show_header=True, caption=log_file_name)
    table.add_column("Date & Time", justify="center",
                     style="cyan", no_wrap=True)
    table.add_column("Chain", justify="center", style="magenta")
    table.add_column("NIC", justify="center", style="green")
    table.add_column("PROTO", justify="center", style="royal_blue1")
    table.add_column("SRC IP", justify="center", style="dark_orange3")
    table.add_column("SPT", justify="center", style="gold1")
    table.add_column("DST IP", justify="center", style="plum2")
    table.add_column("DPT", justify="center", style="bright_red", no_wrap=True)
    table.add_column("TTL", justify="center",
                     style="light_slate_grey", no_wrap=True)
    table.add_column("Hostname", justify="center",
                     style="light_slate_grey", no_wrap=True)
    grouping_re = re.compile('([^ ]+)=([^ ]+)')
    log_line_count = 0
    iplist = []
    # Pass log_file_name to FileReadsBackwards module.
    with FileReadBackwards(log_file_name, encoding="utf-8") as log_file:
        for log_line in log_file:
            if log_line_count < lines_to_show:
                log_line = log_line.rstrip()
                data = dict(grouping_re.findall(log_line))
                date_time = parse_date_time(log_line)
                chain = parse_chain(log_line)
                ipaddr = data['SRC']
                iplist.append(ipaddr)
                hostname = get_hostname(ipaddr)
                table.add_row(date_time, chain, data['IN'],  data['PROTO'],
                data['SRC'], data['SPT'], data['DST'], data['DPT'], data['TTL'], hostname)
                log_line_count += 1
        console = Console()
        console.print(table)
    print(f"Total Log lines Parsed: {str(log_line_count)}")
    with open(log_file_name, 'r') as log_file_count:
        total_log_count = len(log_file_count.readlines())
    print(f"Total Log Entires in Log File: {total_log_count}")
    ipcount = [ite for ite in Counter(iplist).most_common()]
    print("\nMost Commonly Blocked IP Addresses")
    print("----------------------------------")
    for x in ipcount:
        print(f'IP Address: {x[0]} | Hits: {x[1]}')
    print("\n")

def parse_date_time(log_line):
    """
    Function to parse the date/time of the log entry from the log file.
    """
    try:
        date_time_re = r"^[a-zA-Z]...\S[0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]"
        date_time = re.search(date_time_re, log_line)
    except Exception:
        date_time = 'unknown'
    return date_time.group()

def parse_chain(log_line):
    """
    Function to parse the chain the packet was dropped by.
    """
    try:
        chain = re.search(input_chain_logname, log_line)
    except Exception:
        chain = 'unknown'
    return chain.group()

def get_hostname(ipaddr):
    """
    resolve ip address to hostname.
    """
    try:
        hostname = socket.gethostbyaddr(ipaddr)
    except Exception:
        hostname = '-'
    return hostname[0]  

if __name__ == '__main__':
    py_ipt_viewer()