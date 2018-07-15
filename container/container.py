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
"""Lightweight launching of docker containers on systemd-nspawn"""

import logging
import weakref
import os
import os.path
import signal
import time
import psutil
from ptyprocess import PtyProcess
from threading import Thread, Lock
from subprocess import call, DEVNULL, check_output, CalledProcessError
from .process import Process
from .shell import Shell
from .sftp import Sftp


class Container:
    """The node's conception of a container - does all the work (no controller on nodes)"""
    def __init__(self, parent, network, msg, config):
        self.parent = weakref.ref(parent)
        self.network = network
        self.connection = weakref.ref(self.parent().connection)
        self.msg = msg
        self.uuid = msg.uuid
        self.name = 'ctr-' + self.uuid.decode()
        self.base_dir = '/var/lib/machines/' + self.name
        self.config = config
        self.volumes = msg.params['volumes'] if 'volumes' in msg.params else None
        if self.volumes is None:
            self.volumes = []
        self.processes = {}
        self.sftp = Sftp(self._ensure_valid_filename)
        self.last_heartbeat = time.time()
        self.lock = Lock()
        if 'sleep' in self.msg.params and self.msg.params['sleep'] is True:
            self.lock.acquire()
        self.bail_on_release = False
        self.env = [e.split('=') for e in config['Env']]
        if self.msg.params['env'] is not None:
            self.env.extend([(e[0], e[1]) for e in self.msg.params['env']])
        self.pty_process = None
        self.ip = None
        self.net_if = None
        self.runner = None
        self.rebooting = False
        self._namespace_pid = None
        self._owner_uid = None
        self._launch_time = time.time()
        self._send_stdout = True
        logging.debug("Container (%s) docker config: %s" % (self.name, str(config)))

    def launch(self, template, ip):
        """Readies and boots the container from an image template (on its own thread)"""
        # we may need to send a message back
        try:
            # prepare
            self.ip = ip
            self._create_rootfs(template)
            self.net_if = self.network.create_container_interface(self.name)
            self.runner = Thread(target=self._run, name="Running: " + self.name)
            self.runner.start()
            logging.info("Starting container (%s) on: %s" % (self.name, self.ip))
        except RuntimeError as e:
            self.msg.reply(self.connection().send_skt(), {'exception': str(e)})
            logging.error(str(e))

    def wake(self):
        if self.msg.params['sleep'] is True:
            logging.debug("Waking sleeping container: " + self.name)
            self.lock.release()

    def namespace_pid(self):
        """Find the pid of the root process in the namespace"""
        if self._namespace_pid is None:
            path = "/sys/fs/cgroup/systemd/machine.slice/machine-ctr\\x2d%s.scope/cgroup.procs" % self.uuid.decode()
            while True:
                try:
                    with open(path, 'r') as f:
                        self._namespace_pid = f.readline()[:-1]
                        break
                except FileNotFoundError:
                    logging.info("Could not find namespace pid for: " + self.name)
                    raise ValueError("Finding container failed (no namespace pid)")

            if self._namespace_pid == '':
                logging.info("Namespace pid was blank: " + self.name)
                raise ValueError("Finding container failed (blank namespace)")
        return self._namespace_pid

    def owner_uid(self):
        if self._owner_uid is None:
            path = "/proc/%s/uid_map" % self.namespace_pid()
            try:
                with open(path, 'r') as f:
                    parts = f.readline().split()
                    self._owner_uid = int(parts[1])
            except FileNotFoundError:
                pass  # _owner_uid is already None so doesn't need setting
        return self._owner_uid

    def stdin(self, data):
        """Inject data into the root process's stdin"""
        if self.pty_process is None:
            raise ValueError("No pty process to send string to")
        self.pty_process.write(data)
        # handle ctrl-c - note that sending it directly to the shell doesn't work
        if b'\x03' in data:
            nsenter = psutil.Process(self.pty_process.pid)
            shell = nsenter.children()[0]
            if len(shell.children()) > 0:
                os.kill(shell.children()[0].pid, signal.SIGINT)

    def reboot(self, reset_filesystem):
        """Reboot the container"""
        logging.info("Rebooting: " + self.name)
        self.rebooting = True
        self._send_stdout = False

        # kill the container
        self.destroy()

        # are we resetting?
        if reset_filesystem:
            call(['zfs', 'rollback', 'tf/%s@boot' % self.name], stdout=DEVNULL)

        # restart
        self._send_stdout = True
        self.runner = Thread(target=self._run, name="Running: " + self.name)
        self.runner.start()

    def destroy(self):
        """Destroy the container"""
        if self.pty_process is None:
            logging.debug("Called destroy on an already dead container (ignoring): " + self.name)
            return 1
        if self.pty_process.pid is None:
            logging.debug("Called destroy on a container with no pid (ignoring): " + self.name)
            return 1

        # individual processes first - the client makes the processes look closed on its side
        for process in list(self.processes.values()):
            process.destroy()

        # wake and let die the _run thread
        if self.lock.locked():
            self.bail_on_release = True
            self.lock.release()

        # the root process
        self._send_stdout = False
        returncode = Process.kill_entire_group(self.pty_process.pid)
        logging.debug("Destroyed container process: %s (%d)" % (self.name, returncode))
        return returncode

    def run_process(self, msg):
        """Run a process single shot, synchronous - no separate thread"""
        return Process.single_shot(self, msg)

    def spawn_process(self, msg):
        """Spawn a process in the container"""
        self.processes[msg.uuid] = Process(self, self.parent().connection, msg)

    def spawn_shell(self, msg):
        """"Spawn a shell in the container"""
        self.processes[msg.uuid] = Shell(self, self.parent().connection, msg)

    def destroy_process(self, msg):
        """Destroy a manually launched process"""
        try:
            proc = self.processes[msg.params['process']]
            return proc.destroy()  # calls process_has_destroyed all by itself
        except KeyError:
            logging.debug("Attempted to destroy an already destroyed process")

    def process_has_destroyed(self, msg, returncode=0):
        """Can be called externally (shell.py)"""
        if msg.uuid in self.processes:
            msg.reply(self.connection().send_skt(),
                      results={'returncode': returncode},
                      long_term=True)  # blank means "closed"
            del self.processes[msg.uuid]
        else:
            logging.debug("Informed about a destroyed process that's not there (informed twice?)")

    def firewall_ip(self, ip, allow):
        """Opening and closing firewall rules for a particular IP"""
        self.network.firewall_container_ip(self.namespace_pid(), ip, allow)
        logging.info("%s firewall for src=%s on: %s" %
                     ("Opened" if allow else "Closed", ip, self.name))

    def ping(self, ip):
        """Sending a single ping between two containers"""
        logging.debug("Pinging: " + ip)
        self.network.ping(self.namespace_pid(), ip)

    def _create_rootfs(self, template):
        """Create a root fs for the container to boot off"""
        call(['zfs', 'clone', template,
              '-o', 'mountpoint=legacy',
              '-o', 'devices=off',
              '-o', 'quota=4G',
              '-o', 'recordsize=8k',
              '-o', 'compression=on',
              'tf/' + self.name])
        call(['mkdir', '-p', self.base_dir])
        call(['mount', '-t', 'zfs', 'tf/' + self.name, self.base_dir])
        call(['mkdir', '-p', self.base_dir + '/etc'])
        call(['cp', '/etc/resolv.conf', self.base_dir + '/etc/'])

        # write in the pre-boot files
        for filename, bulk in self.msg.params['pre_boot_files'] if self.msg.params['pre_boot_files'] is not None \
                else []:
            try:
                self.sftp.put_file(filename, 0, bulk)  # validates
            except ValueError:
                logging.warning("Pre-boot file write failed: " + filename)

        # take a pre-boot snapshot
        call(['zfs', 'snapshot', 'tf/%s@boot' % self.name])

    def _run(self):
        """Run on a separate thread"""
        try:
            # https://opensource.com/business/14/9/security-for-docker
            # This also covers seccomp (is implemented by seccomp)
            # http://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/
            # https://www.freedesktop.org/wiki/Software/systemd/ContainerInterface/
            # don't drop: cap_sys_ptrace, cap_net_raw, cap_setuid, cap_setgid, cap_dac_override, cap_fowner
            self.net_if = self.network.create_container_interface(self.name)
            drop_caps = 'cap_net_admin,cap_sys_module,cap_sys_rawio,cap_sys_admin,cap_block_suspend,' + \
                        'cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_mknod,cap_audit_write,' + \
                        'cap_audit_control,cap_audit_read,cap_syslog,cap_wake_alarm,cap_setpcap,cap_sys_pacct,' + \
                        'cap_sys_tty_config,cap_mac_override,cap_mac_admin,cap_dac_read_search,cap_net_broadcast'
            cmdline = ['systemd-nspawn', '--quiet',
                       '--chdir=' + self.config['WorkingDir'],
                       '--private-users=pick',
                       '--settings=no',
                       '--network-interface=' + self.net_if,
                       '--drop-capability=' + drop_caps,
                       '--private-network',
                       '--machine=' + self.name]
            for e in self.env:
                if len(e) == 2:
                    cmdline.append('--setenv=%s=%s' % (e[0], e[1]))
                else:
                    cmdline.append("--setenv=" + e[0])
            cmdline.append('/bin/sh')
            logging.debug("Container (%s) startup line: %s" % (self.name, ' '.join(cmdline)))

            # run...
            self.pty_process = PtyProcess.spawn(cmdline)
            nspawn_output = self.pty_process.read()
            logging.debug("Nspawn output: \n" + nspawn_output.decode())

            # bring the network live
            self.network.configure_container_interface(self.net_if, self.ip, self.namespace_pid(),
                                                       whitelist=self.network.dns_servers)

            # mount nfs
            uid = self.owner_uid()
            for uuid, mount_point in self.volumes:
                os.makedirs(self.base_dir + mount_point, mode=0o755, exist_ok=True)
                try:
                    broker_ip = self.connection().connect_ip
                    check_output(['mount', '-o', 'rsize=8192,wsize=8192,noatime',
                                  '%s:tf/vol-%s' % (broker_ip, uuid.decode()), self.base_dir + mount_point])
                except CalledProcessError as e:
                    logging.error("Getting '%s' when mounting: tf/vol-%s" % (str(e), uuid.decode()))
                    raise RuntimeError("There was a problem mounting the volume: tf/vol-" + uuid.decode())

                # make the mount point have uid=root from the container's point of view
                uid = self.owner_uid()
                os.chown(self.base_dir + mount_point, uid, uid)

            if not self.rebooting:
                # tell the broker we're up
                self.connection().send_cmd(b'dependent_container', {'container': self.uuid,
                                                                    'node_pk': self.connection().keys.public_binary(),
                                                                    'ip': self.ip,
                                                                    'volumes': [v[0] for v in self.volumes],
                                                                    'cookie': self.msg.params['cookie']})

            # tell the client we're up
            self.msg.reply(self.connection().send_skt(), {'status': 'running',
                                                          'startup_time': time.time() - self._launch_time,
                                                          'ip': self.ip}, long_term=True)

            # if the container was launched asleep, the thread blocks here waiting for 'wake'
            self.rebooting = False
            self.lock.acquire()
            self.lock.release()

            # are we abandoning this container?
            if self.bail_on_release:
                logging.debug("Asleep container was abandoned: " + self.name)
                self.bail_on_release = False
                return

            # replace the shell with the actual command we're trying to run
            exec_line = 'exec ' + \
                        ' '.join(["'" + ep + "'" for ep in self.config['Entrypoint']]) + ' ' + \
                        ' '.join(["'" + cmd + "'" for cmd in self.config['Cmd']]) + '\n'
            logging.debug("Exec line: " + exec_line)
            self.pty_process.write(exec_line.encode())
            time.sleep(0.1)  # allow time for the process to do anything other than echo

            # return all except the first line of shell output
            shell_output = self.pty_process.read()
            first_cr = shell_output.find(b'\n')
            if first_cr != -1:  # there was a carriage return
                shell_output = shell_output[first_cr + 1:]
            logging.debug("Container first line out: " + shell_output.decode())
            self.msg.reply(self.connection().send_skt(), bulk=shell_output, long_term=True)
            self.parent().stats.container_startup(time.time() - self._launch_time)

            # message loop
            try:
                while True:
                    data = self.pty_process.read()
                    if self._send_stdout:  # don't send death rattles if we killed the container
                        logging.debug("Container output: " + data.decode())
                        self.msg.reply(self.connection().send_skt(), bulk=data, long_term=True)
            except EOFError:
                pass

            logging.debug("Container message loop ended: " + self.name)

        except ValueError as e:
            logging.warning(str(e))

        finally:
            # remove internal references that are now wrong
            self.pty_process = None
            self._namespace_pid = None
            self._owner_uid = None

            # any processes that were running aren't any more
            for proc in list(self.processes.keys()):
                self.process_has_destroyed(self.msg)  # removes them from self.processes itself

            # remove reference to the interface
            self.net_if = None

            # rebooting?
            if self.rebooting:
                return

            logging.info("Cleaning container in 'finally': " + self.name)

            # umount nfs drives
            for vol in self.volumes:
                call(['umount', self.base_dir + vol[1]])

            # remove FS and mount point (network connections take themselves down)
            attempts = 10
            while attempts > 0:
                words = b''
                try:
                    words = check_output(['zfs', 'destroy', '-R', 'tf/' + self.name])
                    break
                except CalledProcessError:
                    attempts -= 1
                    if attempts == 0:
                        logging.error("Failed to destroy zfs filesystem: " + 'tf/' + self.name)
                    else:
                        logging.error("Problem destroying zfs filesystem: " + words.decode())
                        time.sleep(1)
            call(['rm', '-rf', self.base_dir])

            # let the client know we're dead
            self.msg.reply(self.connection().send_skt(), {'status': 'destroyed'}, long_term=True)
            self.connection().destroy_send_skt()

    def _ensure_valid_process(self, msg):
        try:
            return self.processes[msg.params['process']]
        except KeyError:
            raise ValueError("No such process: " + str(msg.params['process']))

    def _ensure_valid_filename(self, filename):
        # ensuring that the passed path is not outside the container
        passed_path = self.base_dir + '/' + filename
        path = os.path.normpath(passed_path)
        if not path.startswith(self.base_dir):
            raise ValueError("Path expressed outside container: " + filename)
        return path

    def __repr__(self):
        return "<container.container.Container object at %x (uuid=%s ip=%s)>" % (id(self), self.uuid, self.ip)
