import os, sys
import threading
import time

import bottombar as bb

from pynput.keyboard import Key, Listener, KeyCode
import win32gui, win32process
from packetgenerator import PacketGenerator

def main():
    """
    Main function, Initializes PacketGenerator  and sends configured packet
    """
    
    def clear_screen():
        os.system('clear')

    class Clock:
        def __str__(self):
            return time.strftime('%H:%M:%S')

    initial_focus_process = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())

    def start_listener(gen:PacketGenerator):
        pressed_esc = False
        def on_release(key:KeyCode):
            nonlocal pressed_esc
            nonlocal gen
            focus_process = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
            if focus_process != initial_focus_process:
                return False
            if key == Key.esc:
                pressed_esc = True
                return False
            if str(key) == "'g'":
                gen.send_packet()

        listener:Listener = None
        while not pressed_esc:
            focus_process = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
            if focus_process != initial_focus_process:
                time.sleep(0.1)
                continue
            with Listener(on_release = on_release) as listener:
                listener.join()

    gen = PacketGenerator(sys.argv)
    clear_screen()
    with bb.add('g: Generate Packet'):
        with bb.add(Clock(), label='time', right=True, refresh=1):
            with bb.add('esc: to quit', right=True):
                listener_thread = threading.Thread(target=lambda: start_listener(gen))
                listener_thread.start()
                listener_thread.join()
    clear_screen()

if __name__=="__main__":
    main()
