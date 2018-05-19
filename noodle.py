# (c) David Preece 2016-2017
# davep@polymath.tech : https://polymath.tech/ : https://github.com/rantydave
# This work licensed under the Non-profit Open Software Licence version 3 (https://opensource.org/licenses/NPOSL-3.0)
# For commercial licensing see https://20ft.nz/
"""The 'agent' for a node in 20ft"""

import requests
import json
import time
from node.node import Node
from awsornot.log import LogHandler


def main():
    # logging with an exclusion list
    log = LogHandler('20ft', 'node', ['Starting new HTTP connection',
                                      'Injected into pty', 'Injected into process',
                                      'stdin_process', 'stdin_container', 'tty_window', 'window size',
                                      'Message.send', 'Message.receive', 'Message.reply'])

    # get user data
    ud = None
    try:
        with open("/opt/20ft/etc/noodle-bootstrap") as f:
            ud_txt = f.read()
    except FileNotFoundError:
        ud_txt = requests.get('http://169.254.169.254/latest/user-data').text
    try:
        ud = json.loads(ud_txt)
    except (json.decoder.JSONDecodeError, TypeError):
        print("Could not bootstrap noodle, waiting for a bit then will restart...")
        time.sleep(10)
        exit(1)

    # go
    node = None
    try:
        node = Node(ud)
        node.run()
    finally:
        if node is not None:
            node.disconnect()
        log.stop()


if __name__ == "__main__":
    main()
