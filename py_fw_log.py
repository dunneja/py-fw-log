#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Filename     : py_fw_log.py
# Author       : Dunneja
# License      : MIT-license
# Comment      : This file is part of py-fw-log.
# ----------------------------------------------------------------------------

"""
py-fw-log command line interface to parse iptables log files.
"""

import sys
import getopt
from py_ipt_view import fw_log_view as fwlogview

def pyfwlog(argv):
    arg_log_file_name = ""
    arg_lines_to_show = ""
    arg_dns = ""
    arg_help = "{0} Usage: pyfwlog -l <logfile> -s <showlines> -d [DNS Lookup]".format(argv[0])    
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
    fwlogview(arg_log_file_name, int(arg_lines_to_show), arg_dns)

if __name__ == "__main__":
    pyfwlog(sys.argv)
