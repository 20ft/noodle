# (c) David Preece 2016-2017
# davep@polymath.tech : https://polymath.tech/ : https://github.com/rantydave
# This work licensed under the Non-profit Open Software Licence version 3 (https://opensource.org/licenses/NPOSL-3.0)
# For commercial licensing see https://20ft.nz/
"""A process 'manually' launched in the container"""
# By not passing a command in the params, a shell is created

import weakref
import logging
import signal
import os
import select
from threading import Thread
from subprocess import Popen, PIPE, DEVNULL


class Process:

    @staticmethod
    def single_shot(container, msg):
        proc = Process._proc(container, msg)
        stdout, stderr = proc.communicate()
        return stdout, stderr, proc.returncode

    def __init__(self, container, conn, msg):
        self.container = weakref.ref(container)
        self.conn = weakref.ref(conn)
        self.msg = msg
        self.proc = Process._proc(container, msg, stdin=PIPE)
        self.thread = Thread(target=self.forward, name="Process forwarding: " + msg.params['command'])
        self.thread.start()

    def stdin(self, data):
        self.proc.stdin.write(data)

    def forward(self):
        while True:
            rlist, wlist, xlist = select.select([self.proc.stdout, self.proc.stderr], [], [])
            for file in rlist:
                data = file.read(8192)
                if len(data) != 0:
                    stream = "stdout" if file == self.proc.stdout else "stderr"
                    logging.debug("%s/%s: %s" % (self.msg.uuid.decode(), stream, data.decode()))
                    self.msg.reply(self.conn().skt,
                                   results=None if file == self.proc.stdout else {'stderr': True},
                                   bulk=data,
                                   long_term=True)
                else:
                    if self.proc is None:
                        return
                    rtn = self.proc.wait()
                    logging.info("Process ended: %s (%d)" % (self.msg.uuid.decode(), rtn))
                    self.container().process_has_destroyed(self.msg, rtn)
                    self.proc = None
                    return

    def destroy(self):
        logging.debug("Explicitly called destroy on: " + self.msg.uuid.decode())
        if self.proc is None:
            logging.debug("...but was not necessary")
            return
        returncode = Process.kill_entire_group(self.proc.pid)
        return returncode

    @staticmethod
    def kill_entire_group(pid):
        # try terminate first
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            logging.debug("Could not destroy entire group - pid was missing: " + str(pid))
            return
        logging.debug("Destroying process group (terminate): " + str(pgid))

        os.killpg(pgid, signal.SIGTERM)
        try:
            _, returncode = os.waitpid(pid, 0)
            return returncode
        except ChildProcessError:
            logging.info("ChildProcessError in kill_entire_group (SIGTERM): " + str(pid))
            return 0
        except OSError as e:

            # try kill
            logging.debug("Destroying process group (kill): " + str(pgid))
            os.killpg(pgid, signal.SIGKILL)
            try:
                _, returncode = os.waitpid(pid, 0)
                return returncode
            except ChildProcessError:
                logging.info("ChildProcessError in kill_entire_group (SIGKILL): " + str(pid))
                return 0
            except OSError:
                logging.warning("Could not kill process group: " + str(pgid))

    @staticmethod
    def _proc(container, msg, stdin=DEVNULL):
        # don't use -F because it buggers up sending signals
        command = ['nsenter', '-m', '-u', '-i', '-n', '-p', '-U', '-C', '-t', str(container.namespace_pid()),
                   'sh', '-c', msg.params['command']]
        return Popen(command,
                     stdin=stdin, stdout=PIPE, stderr=PIPE,
                     env={e[0]: e[1] for e in container.env},
                     bufsize=0,
                     start_new_session=True)

    def __repr__(self):
        return "<container.process.Process object at %x (%s)>" % (id(self), self.msg.params['command'])
