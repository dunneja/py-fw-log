#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Filename     : py_fwlog_view.py
# Author       : James Dunne <james.dunne1@gmail.com>
# License      : GPL-3.0
# Comment      : This file is part of py firewall log viewer.
# ----------------------------------------------------------------------------

import re
from rich.console import Console
from rich.table import Table

# Set iptables log file UNC.    
log_file = open("iptables.log", "r")

# Set iptables input chain
input_chain = r"IPTABLES:BLOCKED-CONN:"

def main():
    """
    Main function, building tables and populating from log file.
    """
    table = Table(title="Py Firewall Log Viewer - Dropped Packets")
    table.add_column("Date & Time", justify="center", style="cyan", no_wrap=True)
    table.add_column("Chain", justify="center", style="magenta")
    table.add_column("NIC", justify="center", style="green")
    table.add_column("SRC IP", justify="center", style="magenta")
    table.add_column("DST IP", justify="center", style="green")
    table.add_column("TTL", justify="center",
                     style="cyan", no_wrap=True)
    table.add_column("PROTO", justify="center", style="magenta")
    table.add_column("SPT", justify="center", style="green")
    table.add_column("DPT", justify="center",
                     style="cyan", no_wrap=True)
    count = 0
    LinesToShow = 20
    grouping_re = re.compile('([^ ]+)=([^ ]+)')
    while (count < LinesToShow):
        for line in log_file:   
            line = line.rstrip()
            data = dict(grouping_re.findall(line))
            date_time = parse_date_time(line)
            chain = parse_chain(line)
            table.add_row(f"{date_time}", f"{chain}", data['IN'], data['SRC'], data['DST'], data['TTL'], data['PROTO'], data['SPT'], data['DPT'])
            count += 1
    console = Console()
    console.print(table)

def parse_date_time(line):
    """
    Function to parse the date/time of the log entry from the log file.
    """
    try:
        date_time_re = r"^[a-zA-Z]...\S[0-9]\s[0-9][0-9]:[0-9][0-9]:[0-9][0-9]"
        date_time = re.search(date_time_re, line)
    except Exception:
        date_time = 'unknown'
    return date_time.group()

def parse_chain(line):
    """
    Function to parse the chain the packet was dropped by.
    """
    try:
        chain = re.search(input_chain, line)
    except Exception:
        chain = 'unknown'
    return chain.group()

if __name__ == '__main__':
    main()