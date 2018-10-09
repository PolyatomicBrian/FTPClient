#!/usr/bin/env python2

"""ftpclient.py: Acts as a client for connecting to an FTP server. Adheres to
                 the FTP Protocol defined in RFC 959 and RFC 2428."""

import socket    # Used for network connections.
import sys       # Used for arg parsing.
import datetime  # Used for getting date & time for Logs.
import getpass   # Used for hiding inputted password.


''' GLOBALS '''

IS_DEBUG = True
DEFAULT_FTP_PORT = 21

# FTP Server Response Codes referenced in this program.
# Found here: https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
FTP_STATUS_CODE = {
    "SUCCESSFUL_LOGIN":  "230",
    "SUCCESSFUL_LOGOUT": "231"
}

# Program Arguments
REQUIRED_NUM_ARGS = 3
MAXIMUM_NUM_ARGS = 4

PROGRAM_ARG_NUM = 0  # ie sys.argv[0]
HOST_ARG_NUM = 1
LOG_ARG_NUM = 2
PORT_ARG_NUM = 3


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

    def __init__(self, host, log_file, port):
        """Create socket and invoke connection."""
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ftp_connect(host, log_file, port)
            msg_rec = repr(self.s.recv(1024))
        except socket.error as e:
            error_quit("Unable to connect due to: %s" % e, 500)
        print_debug(msg_rec)
        if not msg_rec:
            self.close_socket()

    def ftp_connect(self, host, log_file, port):
        """Connects Client to Server."""
        try:
            ip = socket.gethostbyname(host)
        except socket.error:
            error_quit("Invalid or unknown host address!", 400)
        except Exception:
            error_quit("Invalid or unknown host address!", 400)
        try:
            self.s.connect((ip, port))
        except socket.error:
            error_quit("Connection refused, did you specify the correct host and port?", 400)
        except Exception:
            error_quit("Unable to connect.", 400)

    def user_cmd(self, username):
        print_debug("Executing USER")
        self.s.send("USER %s\r\n" % username)
        msg_rec = repr(self.s.recv(1024))
        print_debug(msg_rec)
        return msg_rec

    def pass_cmd(self, password):
        print_debug("Executing PASS")
        self.s.send("PASS %s\r\n" % password)
        msg_rec = repr(self.s.recv(1024))
        print_debug(msg_rec)
        return msg_rec

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

    def close_socket(self):
        print_debug("Closing socket.")
        self.s.close()


''' FUNCTIONS '''


def usage():
    """Prints the usage/help message for this program."""
    program_name = sys.argv[PROGRAM_ARG_NUM]
    print("Usage:")
    print("%s IP LOGFILE [PORT]" % program_name)
    print("  IP : IP address of host running the desired FTP Server.")
    print("  LOGFILE : Name of file containing FTP Client log details.")
    print("  PORT (optional) : Port used to connect to FTP Server. Default is"\
          " 21.")


def error_quit(msg, code):
    """Prints out an error message, the program usage, and terminates with an
    error code of `code`."""
    print("[!] %s" % msg)
    usage()
    exit(code)


def parse_args():
    """Gets and returns provided arguments."""
    if len(sys.argv) < REQUIRED_NUM_ARGS or len(sys.argv) > MAXIMUM_NUM_ARGS:
        error_quit("Incorrect number of arguments!", 400)
    port = sys.argv[PORT_ARG_NUM] if len(sys.argv) == MAXIMUM_NUM_ARGS else DEFAULT_FTP_PORT
    port = validate_port(port)
    host, log_file = sys.argv[HOST_ARG_NUM], sys.argv[LOG_ARG_NUM]
    return host, log_file, port


def validate_port(port):
    """Cast port to an int and ensure it is between 0 and 65535."""
    try:
        port = int(port)
        if port > 65535 or port < 0:
            raise ValueError('Port is not between 0 and 65535!')
    except ValueError:
        error_quit("Port is not between 0 and 65535!", 400)
    except Exception:
        error_quit("Invalid port!", 400)
    return port


def prompt_user():
    """Prompt user for Username."""
    msg = "Enter Username: "
    username = raw_input(msg)
    return username


def prompt_pass():
    """Prompt user for Password. Hide input (make stdin invisible)."""
    msg = "Enter Password: "
    password = getpass.getpass(msg)
    return password


def get_ftp_server_code(resp_msg):
    """Returns the error code (a three-digit string) of an FTP server response."""
    return resp_msg[1:4]


def login(ftp):
    """Prompt user for Username & Password, authenticate with FTP server."""
    # Get username
    username = prompt_user()
    ftp.user_cmd(username)
    # Get password
    password = prompt_pass()
    pass_data = ftp.pass_cmd(password)
    # Retry inputs if unsuccessful authentication.
    while get_ftp_server_code(pass_data) != FTP_STATUS_CODE["SUCCESSFUL_LOGIN"]:
        print_debug("Login incorrect, try again.")
        username = prompt_user()
        ftp.user_cmd(username)
        password = prompt_pass()
        pass_data = ftp.pass_cmd(password)


def do_ftp(ftp):
    login(ftp)


''' DEBUG '''


def print_debug(msg):
    if IS_DEBUG:
        print(msg)


''' MAIN '''


def main():
    print_debug("Starting...")
    host, log_file, port = parse_args()
    logger = Logger(log_file)
    ftp = FTP(host, log_file, port)
    do_ftp(ftp)


''' PROCESS '''
if __name__ == '__main__':
    main()
