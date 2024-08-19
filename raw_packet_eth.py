# MIT License
# This file is part of Raw Ethernet Packet Generator
# See https://github.com/shikharbhargava/raw-packet-eth-win for more information
# Copyright (C) Shikhar Bhargava

"""
Raw Ethernet Packet Generator is a CLI packet generator tool for ethernet on Windows 10/11.
It allows you to create and send any possible packet or sequence of packets on the ethernet link.
It is very simple to use, powerful and supports many adjustments of parameters while sending.
"""

import os
import sys
import threading
import time

import bottombar as bb

from pynput.keyboard import Key, Listener, KeyCode, Controller
import win32gui
import win32process
from packgen import PacketGenerator

def main():
    """
    Main function, Initializes PacketGenerator  and sends configured packet
    """
    default_string = 'Press a key to choose an option from the bottom menu.'

    def clear_screen():
        os.system('clear')

    class Clock:
        def __str__(self):
            return time.strftime('%H:%M:%S')

        def __repr__(self):
            return self.__str__()

    initial_focus_process = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())

    def start_listener(gen:PacketGenerator):
        keyboard = Controller()
        esc = False
        def on_release(key:KeyCode):
            nonlocal esc
            nonlocal gen
            nonlocal keyboard
            nonlocal default_string
            focus_process = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
            if focus_process != initial_focus_process:
                return False
            if key == Key.esc or str(key) == "'q'":
                keyboard.press(Key.esc)
                keyboard.release(Key.esc)
                c = input("Are you sure you want to close [Y|n]:")
                if c in ('y', 'Y', ''):
                    esc = True
                    return False
                if c in ('n', 'N'):
                    print(default_string)
                    return True
                print("Invalid input!")
                print(default_string)
                return True
            if str(key) == "'g'":
                print('Generating Packet(s)...')
                gen.send_packet()
                print(default_string)
            elif str(key) == "'c'":
                clear_screen()
                print(default_string)
            elif str(key) == "'s'":
                print('Configurations...')
                print(gen)
                print(default_string)
            #else:
            #    print(f'Unknown option: {str(key)}')
            return True

        listener:Listener = None
        while not esc:
            focus_process = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
            if focus_process != initial_focus_process:
                time.sleep(1)
                continue
            with Listener(on_release = on_release) as listener:
                listener.join()

    gen = PacketGenerator(sys.argv)
    clear_screen()
    print(default_string)
    bb.add('Generate Packet', label='g')
    bb.add('show configurations', label='s')
    bb.add('clear', label='c')
    bb.add(Clock(), label='time', right=True, refresh=1)
    bb.add('to quit', label='esc or q', right=True)
    listener_thread = threading.Thread(target=lambda: start_listener(gen))
    listener_thread.start()
    listener_thread.join()
    #clear_screen()

if __name__=="__main__":
    main()
