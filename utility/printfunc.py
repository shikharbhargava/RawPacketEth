# MIT License
# This file is part of Raw Ethernet Packet Generator
# See https://github.com/shikharbhargava/raw-packet-eth-win for more information
# Copyright (C) Shikhar Bhargava

"""
This file contains implementation of functions to print error and warinings in color format
"""

import sys
from colorama import Fore, Style

def print_error(*err : str, exit_prog=False):
    """
    Prints the error statement to the error stream in RED color
    """
    print(Fore.RED + 'ERROR: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)
    if exit_prog:
        sys.exit(1)

def print_warning(*err : str):
    """
    Prints the warining statement in YELLOW color
    """
    print(Fore.YELLOW + 'WARNING: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)
