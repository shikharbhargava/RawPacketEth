import bottombar as bb
import time

def main():
    # Add a static item
    with bb.add('static item', label='info'):
        # Add a dynamic clock item
        with bb.add(Clock(), label='time', right=True, refresh=1):
            # Keep the script running to see the updates
            time.sleep(10)

class Clock:
    def __str__(self):
        return time.strftime('%H:%M:%S')

if __name__ == "__main__":
    main()
