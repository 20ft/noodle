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
"""A shell running inside the container"""
# The differences between a shell and a process are that:
# * A process only returns individual lines of data, shell returns whatever it can whenever it can
# * A shell cares about window sizes

import weakref
import logging
import os
import os.path
from threading import Thread
from ptyprocess import PtyProcess


class Shell:
    def __init__(self, container, conn, msg):
        self.conn = weakref.ref(conn)
        self.container = weakref.ref(container)
        self.msg = msg
        self.running = False
        self.pty = Shell._proc(container, msg)
        self.thread = Thread(target=self.forward, name="Shell on: " + self.container().name)
        self.thread.start()

    def stdin(self, data):
        return os.write(self.pty.fd, data)  # returns number characters written

    def set_window_size(self, width, height):
        self.pty.setwinsize(height, width)

    def forward(self):
        """Called by the event loop to indicate that there's some data to forward to the client"""
        self.running = True
        try:
            while self.running:
                try:
                    data = self.pty.read()
                    self.msg.reply(self.conn().skt, bulk=data, long_term=True)
                except EOFError:
                    self.running = False
        finally:
            logging.debug("Shell closed: " + str(self.msg.uuid))
            self.destroy()

    def destroy(self):
        # unregister first so we don't get notification of things we've closed
        if not self.pty.terminate():
            logging.warning("Shell didn't terminate: " + str(self.msg.uuid))
        self.container().process_has_destroyed(self.msg)
        self.running = False

    @staticmethod
    def _proc(container, msg):
        # don't use -F because it buggers up sending signals
        command = ['nsenter', '-m', '-u', '-i', '-n', '-p', '-U', '-C', '-t', str(container.namespace_pid())]
        shells = ('bash', 'ash', 'sh', 'zsh', 'ksh', 'fish')
        shell_cmd = None

        # find a shell
        if shell_cmd is None:
            for shell in shells:
                if os.path.isfile(container.base_dir + '/bin/' + shell):
                    shell_cmd = '/bin/' + shell
                    break
                if os.path.isfile(container.base_dir + '/sbin/' + shell):
                    shell_cmd = '/sbin/' + shell
                    break

        # ok
        if shell_cmd is None:
            shell_cmd = 'sh'
        command.extend([shell_cmd, '-l'])
        logging.debug("Shell using: " + shell_cmd)

        echo = msg.params['echo'] if 'echo' in msg.params else False
        return PtyProcess.spawn(command, env={'TERM': 'xterm'}, echo=echo)

    def __repr__(self):
        return "<container.shell.Shell object at %x>" % id(self)
