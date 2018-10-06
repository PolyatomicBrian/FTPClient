#!/usr/bin/env python2

"""ftpclient.py: Acts as a client for connecting to an FTP server. Adheres to
                 the FTP Protocol defined in RFC 959 and RFC 2428."""

''' IMPORTS '''

import socket


''' GLOBALS '''

is_debug = True


''' CLASSES '''


class Logger:
    """Performs necessary logging of communication between Client & Server."""
    def __init__(self):
        print_debug("Created Logger")


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


''' DEBUG '''


def print_debug(msg):
    if is_debug:
        print(msg)


''' MAIN '''


def main():
    print_debug("Starting...")

    logger = Logger()
    ftp = FTP()



''' PROCESS '''
if __name__ == '__main__':
    main()
