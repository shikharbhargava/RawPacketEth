from multiprocessing import Process
import keyboard
import time

def my_loop():
    while True:
        print("a")
        time.sleep(0.3)

if __name__ == '__main__':
    process = Process(target=my_loop)
    process.start()
    while process.is_alive():
        if keyboard.is_pressed('q'):
            process.terminate()
            break   