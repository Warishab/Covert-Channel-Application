#!/usr/bin/python3
# file_monitor.py

import os
import inotify.adapters


def monitor():

    filename = 'hooray.txt'

    i = inotify.adapters.Inotify()

    # Monitor the directory
    i.add_watch("/home/warisha/project/source", mask=inotify.constants.IN_CREATE)

    # with open('/tmp/test_file', 'w'):
    #     pass
    # os.system('rm -rf /tmp/test_file')

    for event in i.event_gen(yield_nones=False):
        return event


        # os.system("cat {}/{}".format(path, filename))


def main():
    monitor()


if __name__ == "__main__":
    main()

