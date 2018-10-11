#!/usr/bin/env python2

"""ftpclient.py: Acts as a client for connecting to an FTP server. Adheres to
                 the FTP Protocol defined in RFC 959 and RFC 2428.
   Author: Brian Jopling, October 2018."""

import socket    # Used for network connections.
import sys       # Used for arg parsing.
import datetime  # Used for getting date & time for Logs.
import getpass   # Used for hiding inputted password.


''' GLOBALS '''

IS_DEBUG = True
DEFAULT_FTP_PORT = 21

# FTP Server Response Codes referenced in this program.
# Found here: https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes
FTP_STATUS_CODES = {
    "SUCCESSFUL_LOGIN":  "230",
    "SUCCESSFUL_LOGOUT": "231"
}

# Actions User can make when at the Main Menu.
# Adheres to the format:
# { choice_number : [display_msg, function_to_call] }
MAIN_MENU_SELECTIONS = {
    "1": ["Download a file.", "do_download"],
    "2": ["Upload a file.", "do_upload"],
    "3": ["List files.", "do_list"],
    "4": ["Change directory.", "do_cwd"],
    "5": ["Print working directory.", "do_pwd"],
    "6": ["Get server info.", "do_syst"],
    "7": ["Quit.", "do_quit"]
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
        # Create file
        f = open(log_file, "a")
        self.file = f

    def get_date_time(self):
        """Returns datetime as a string in the format: 9/25/18 22:00:00.0002"""
        now = datetime.datetime.now()
        now_formatted = now.strftime("%m/%d/%Y %H:%M:%S.%f")
        return now_formatted

    def log(self, msg):
        """Writes datetime & message to log."""
        current_datetime = self.get_date_time()
        self.file.write("%s %s\n" % (current_datetime, msg))

    def close_file(self):
        """Simply closes the file."""
        self.file.close()


class FTP:
    """Executes defined FTP Client commands and handles Server's responses."""

    def __init__(self, host, logger, port):
        """Create socket and invoke connection."""
        # TODO break this function into two others.
        self.logger = logger
        self.logger.log("Connecting to %s" % host)
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ftp_connect(host, logger, port)
            msg_rec = repr(self.s.recv(1024))
        except socket.error as e:
            error_quit("Unable to connect due to: %s" % e, 500)
        self.logger.log("Received: %s" % msg_rec)
        print_debug(msg_rec)
        if not msg_rec:
            self.close_socket()

    def ftp_connect(self, host, logger, port):
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

    def send_and_log(self, command):
        self.s.send(command)
        self.logger.log("Sent: %s" % command)
        msg_rec = repr(self.s.recv(1024))
        self.logger.log("Received: %s" % msg_rec)
        return msg_rec

    def user_cmd(self, username):
        print_debug("Executing USER")
        command = "USER %s\r\n" % username
        msg_rec = self.send_and_log(command)
        return msg_rec

    def pass_cmd(self, password):
        print_debug("Executing PASS")
        command = "PASS %s\r\n" % password
        msg_rec = self.send_and_log(command)
        return msg_rec

    def cwd_cmd(self, new_dir):
        print_debug("Executing CWD")
        command = "CWD %s\r\n" % new_dir
        msg_rec = self.send_and_log(command)
        return msg_rec

    def quit_cmd(self):
        print_debug("Executing QUIT")
        command = "QUIT\r\n"
        msg_rec = self.send_and_log(command)
        self.close_socket()
        return msg_rec

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
        command = "PWD\r\n"
        msg_rec = self.send_and_log(command)
        return msg_rec

    def syst_cmd(self):
        print_debug("Executing SYST")

    def list_cmd(self, dir=None):
        print_debug("Executing LIST")
        if dir:
            command = "LIST %s\r\n" % dir
        else:
            command = "LIST\r\n"
        msg_rec = self.send_and_log(command)
        return msg_rec

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


def prompt_username():
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
    username = prompt_username()
    ftp.user_cmd(username)
    # Get password
    password = prompt_pass()
    pass_data = ftp.pass_cmd(password)
    # Retry inputs if unsuccessful authentication.
    while get_ftp_server_code(pass_data) != FTP_STATUS_CODES["SUCCESSFUL_LOGIN"]:
        print_debug("Login incorrect, try again.")
        username = prompt_username()
        ftp.user_cmd(username)
        password = prompt_pass()
        pass_data = ftp.pass_cmd(password)


def do_download(ftp):
    print_debug("Unfinished Download")
    main_menu(ftp)


def do_upload(ftp):
    print_debug("Unfinished Upload")
    main_menu(ftp)


def do_list(ftp):
    dir = raw_input("List files in what directory (Current)? ")
    output = ftp.list_cmd(dir)
    print("%s\n" % output)
    main_menu(ftp)


def do_cwd(ftp):
    new_dir = raw_input("What directory do you want to change to? ")
    output = ftp.cwd_cmd(new_dir)
    print("%s\n" % output)
    main_menu(ftp)


def do_pwd(ftp):
    output = ftp.pwd_cmd()
    print("%s\n" % output)
    main_menu(ftp)


def do_syst(ftp):
    print_debug("Unfinished SYST")
    main_menu(ftp)


def do_quit(ftp):
    ftp.quit_cmd()


def handle_main_menu_choice(choice, ftp):
    """Calls function associated with user's Main Menu choice."""
    function_to_call = MAIN_MENU_SELECTIONS[choice][1]
    globals()[function_to_call](ftp)  # Call the function.


def main_menu(ftp):
    """Displays Main Menu and prompts user to select an action."""
    print("What would you like to do?")
    for key in sorted(MAIN_MENU_SELECTIONS):
        print("[%s] %s" % (key, MAIN_MENU_SELECTIONS[key][0]))
    choice = raw_input("> ")
    while choice not in list(MAIN_MENU_SELECTIONS.keys()):
        choice = raw_input("> ")
    handle_main_menu_choice(choice, ftp)


def do_ftp(ftp):
    login(ftp)
    main_menu(ftp)


''' DEBUG '''


def print_debug(msg):
    if IS_DEBUG:
        print(msg)


''' MAIN '''


def main():
    print_debug("Starting...")
    host, log_file, port = parse_args()
    logger = Logger(log_file)
    ftp = FTP(host, logger, port)
    do_ftp(ftp)


''' PROCESS '''
if __name__ == '__main__':
    main()
