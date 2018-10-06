#!/usr/bin/env python2

"""ftpclient.py: Acts as a client for connecting to an FTP server. Adheres to
                 the FTP Protocol defined in RFC 959 and RFC 2428."""

import socket    # Used for network connections.
import sys       # Used for arg parsing.
import datetime  # Used for getting date & time for Logs.


''' GLOBALS '''

is_debug = True


''' CLASSES '''


class Logger:
    """Performs necessary logging of communication between Client & Server."""
    # Class vars: log_file
    def __init__(self, log_file):
        print_debug("Created Logger")
        self.log_file = log_file

    def get_date_time(self):
        """Returns datetime as a string in the format: 9/25/18 22:00:00.0002"""
        now = datetime.datetime.now()
        now_formatted = now.strftime("%m/%d/%Y %H:%M:%S.%f")
        return now_formatted


class FTP:
    """Executes defined FTP Client commands and handles Server's responses."""
    def __init__(self):
        print_debug("Created FTP")

    def user_cmd(self):
        print_debug("Executing USER")

    def pass_cmd(self):
        print_debug("Executing PASS")

    def cwd_cmd(self):
        print_debug("Executing CWD")

    def quit_cmd(self):
        print_debug("Executing QUIT")

    def pasv_cmd(self):
        print_debug("Executing PASV")

    def epsv_cmd(self):
        print_debug("Executing EPSV")

    def port_cmd(self):
        print_debug("Executing PORT")

    def eprt_cmd(self):
        print_debug("Executing EPRT")

    def retr_cmd(self):
        print_debug("Executing RETR")

    def stor_cmd(self):
        print_debug("Executing STOR")

    def pwd_cmd(self):
        print_debug("Executing PWD")

    def syst_cmd(self):
        print_debug("Executing SYST")

    def list_cmd(self):
        print_debug("Executing LIST")


''' FUNCTIONS '''


def usage():
    """Prints the usage/help message for this program."""
    program_name = sys.argv[0]
    print("Usage:")
    print("%s IP LOGFILE [PORT]" % program_name)
    print("  IP : IP address of host running the desired FTP Server.")
    print("  LOGFILE : Name of file containing FTP Client log details.")
    print("  PORT (optional) : Port used to connect to FTP Server. Default is"\
          " 21.")


def error_quit(msg, code):
    """Prints out an error message, the program usage, and terminates with an
    error code of `code`."""
    print(msg)
    usage()
    exit(code)


def parse_args():
    """Gets and returns provided arguments."""
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        error_quit("Incorrect number of arguments!", 400)
    DEFAULT_FTP_PORT = 21
    port = sys.argv[3] if len(sys.argv) == 4 else DEFAULT_FTP_PORT
    port = validate_port(port)
    host, log_file = sys.argv[1], sys.argv[2]
    return host, log_file, port


def validate_port(port):
    """Cast port to an int and ensure it is between 0 and 65535."""
    try:
        port = int(port)
        if port > 65535 or port < 0:
            raise ValueError('Port is not between 0 and 65535!')
    except Exception as e:
        error_quit("Invalid port!", 400)
    return port


def ftp_connect(host, log_file, port):
    """Connects Client to Server."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        error_quit("Invalid or unknown host address!", 400)
    s.connect((ip, port))


''' DEBUG '''


def print_debug(msg):
    if is_debug:
        print(msg)


''' MAIN '''


def main():
    print_debug("Starting...")
    host, log_file, port = parse_args()
    ftp_connect(host, log_file, port)
    logger = Logger(log_file)
    ftp = FTP()


''' PROCESS '''
if __name__ == '__main__':
    main()
