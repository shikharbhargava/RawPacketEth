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

menuLeft = dict({
    KeyCode(char='g'): { 'text' : 'Generate Packet', 'help' : False },
    KeyCode(char='s'): { 'text' : 'show configurations', 'help' : False },
    KeyCode(char='c'): { 'text' : 'Clear', 'help' : True },
})

menuRight = dict({
    KeyCode(char='m'): { 'text' : 'Manual', 'help' : True },
    KeyCode(char='q'): { 'text' : 'Quit', 'help' : True, 'second' : Key.esc},
    KeyCode(char='?'): { 'text' : None, 'help' : True }
})

def main():
    """
    Main function, Initializes PacketGenerator  and sends configured packet
    """
    default_string = 'Press a key to choose an option from the bottom menu.'
    __help_mode_keys = list()
    __general_keys = list()

    def clear_screen():
        os.system('clear')

    class Clock:
        """
        Clock class, typecast to str to get the time in format <Hr>:<Min>:<Sec>
        """
        def __str__(self):
            return time.strftime('%H:%M:%S')

        def __repr__(self):
            return self.__str__()

    initial_focus_process = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())

    def  __findKey(key : KeyCode, help_mode = False):
        if (help and  key in __help_mode_keys) or (key in __general_keys):
            return True
        return False

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
            found = __findKey(key)
            if gen.help_mode() and not found:
                return True
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
            if str(key) in ("'g'", "'G'"):
                print('Generating Packet(s)...')
                gen.send_packet()
                print(default_string)
            elif str(key) in ("'c'", "'C'"):
                clear_screen()
                print(default_string)
            elif str(key) in ("'s'", "'S'"):
                try:
                    config = str(gen)
                    print('Configurations...')
                    print(config)
                except ValueError as e:
                    print(e)
                print(default_string)
            elif str(key) in ("'m'", "'M'"):
                gen.help()
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

    for l, v in (menuLeft | menuRight).items():
        __general_keys.append(l)
        try:
            help = v['help']
            if help:
                __help_mode_keys.append(l)
            second = v['second']
            __general_keys.append(second)
            if help:
                __help_mode_keys.append(second)
        except KeyError:
            pass


    print(default_string)
    for l, v in menuLeft.items():
        second = None
        try:
            second = v['second']
        except KeyError:
            pass
        show = (not gen.help_mode()) or v['help']
        if show:
            text = v['text']
            lable = l.char
            if second is not None:
                second_key = str(second).split('.')[1]
                lable = lable + f' or {second_key}'
            if text is not None and show:
                bb.add(text, label=lable)
            else:
                bb.add(lable)
    bb.add(Clock(), label='time', right=True, refresh=1)
    for l, v in reversed(menuRight.items()):
        second = None
        try:
            second = v['second']
        except KeyError:
            pass
        text = v['text']
        show = (not gen.help_mode()) or v['help']
        if show:
            lable = l.char
            if second is not None:
                second_key = str(second).split('.')[1]
                lable = lable + f' or {second_key}'
            if text is not None:
                bb.add(text, label=lable, right=True)
            else:
                bb.add(lable, right=True)
    listener_thread = threading.Thread(target=lambda: start_listener(gen))
    listener_thread.start()
    listener_thread.join()
    #clear_screen()

if __name__=="__main__":
    main()
