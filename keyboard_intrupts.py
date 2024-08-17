import os

import keyboard

def clear_screen():
    # For Windows
    if os.name == 'nt':
        os.system('cls')
    # For macOS and Linux
    else:
        os.system('clear')
def on_key_event(event):
    print(f"Key {event.name} pressed")
    #clear_screen()
    print("Press a key..")

# Set up the listener
keyboard.on_release(on_key_event)

print("Press a key..")

# Keep the script running
keyboard.wait('esc')  # Press 'esc' to exit
