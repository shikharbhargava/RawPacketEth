import sys
from colorama import Fore, Style

def print_error(*err : str, exit_prog=False):
    print(Fore.RED + 'ERROR: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)
    if exit_prog:
        sys.exit(1)

def print_warning(*err : str):
    print(Fore.YELLOW + 'WARNING: ' + ' '.join(err) + Style.RESET_ALL, file=sys.stderr)
