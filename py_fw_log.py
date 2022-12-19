import sys
import getopt
from py_ipt_viewer import fw_log_view as fwlogview

def pyfwlog(argv):
    arg_log_file_name = ""
    arg_lines_to_show = ""
    arg_help = "{0} -l <logfile> -s <showlines>".format(argv[0])
    
    try:
        opts, args = getopt.getopt(argv[1:], "hi:l:s:", ["help", "log_file_name=", 
        "lines_to_show="])
    except:
        print(arg_help)
        sys.exit(2)
    
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(arg_help)  # print the help message
            sys.exit(2)
        elif opt in ("-l", "--logfile"):
            arg_log_file_name = arg
        elif opt in ("-s", "--showlines"):
            arg_lines_to_show = arg    
    fwlogview(arg_log_file_name, str(arg_lines_to_show))

if __name__ == "__main__":
    pyfwlog(sys.argv)