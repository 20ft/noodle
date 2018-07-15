# Copyright (c) 2016-2018 David Preece - davep@polymath.tech, All rights reserved.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
