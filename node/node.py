# (c) David Preece 2016-2017
# davep@polymath.tech : https://polymath.tech/ : https://github.com/rantydave
# This work licensed under the Non-profit Open Software Licence version 3 (https://opensource.org/licenses/NPOSL-3.0)
# For commercial licensing see https://20ft.nz/

# Nodes have no concept of user (other than themselves)

import logging
import time
import threading
from messidge import KeyPair
from messidge.client.connection import Connection
from .stats import Stats
from .network import Network
from awsornot import dynamic_data_or_none
from awsornot.kvread import KeyValueRead
from files.deltatree import DeltaTree
from container.container import Container


class Node:
    """A Node (this physical machine)"""

    def __init__(self, user_data):
        # get connection ip and subnet from aws...
        ssm = KeyValueRead()
        location_ip = ssm.get_parameter(Name='/20ft/ip')['Parameter']['Value']

        # start
        keys = KeyPair(public=user_data['pk'], secret=user_data['sk'])
        self.connection = Connection(location_ip=location_ip, keys=keys, server_pk=user_data['bpk'],
                                     reflect_value_errors=True)
        self.stats = None
        self.watcher = None
        self.last_heartbeat_check = time.time()
        self.last_network_ping = time.time()
        self.containers = {}
        self.network = Network()
        self.delta_tree = DeltaTree(location_ip)

    def run(self):
        # bring the connection up
        self.connection.loop.register_on_idle(self.check_heartbeat)
        self.connection.register_commands(self, Node._commands)  # before the loop starts
        self.connection.register_connect_callback(self._send_inform_ip)
        self.connection.start()
        self.connection.wait_until_ready()

        # let the broker know our stats
        self.stats = Stats(self.connection.location_name(), self.connection)
        self.stats.start()

        # until the message loop is done
        try:
            self.connection.wait_until_complete()
        except KeyboardInterrupt:
            pass

    def check_heartbeat(self):
        # check the containers
        tme = time.time()
        for uuid, ctr in list(self.containers.items()):
            if tme - ctr.last_heartbeat >= 300:  # we really do hope this isn't necessary
                logging.info("Container timed out: " + str(uuid))
                self._impl_destroy_container(uuid, True)

        # maybe we need to ping the other parts of the network
        if (tme - self.last_network_ping) >= 300:
            self.network.ping_peers()
            self.last_network_ping = tme

    def disconnect(self):
        # controlled shutdown the containers - the client side produces events so we don't need to
        for ctr in list(self.containers.values()):
            self._impl_destroy_container(ctr.uuid, False)

        # close stuff down
        self.stats.stop()
        self.connection.disconnect()

    ##################  Network

    def _send_inform_ip(self, rid):
        data = {'ip': self.network.external_ip}

        # maybe cross correlate with amazon id's?
        if dynamic_data_or_none() is not None:
            data['instance_id'] = dynamic_data_or_none()['instanceId']

        # let the broker know our external ip
        self.connection.send_cmd(b'inform_external_ip', data)

    def _network_topology(self, msg):
        self.network.topology(msg.params['topology'])

    ################## Containers

    def _spawn_container(self, msg):
        # checks
        description = msg.params['description']
        if description['Architecture'] != 'amd64' or description['Os'] != 'linux':
            raise ValueError("Does not appear to be a linux/amd64 container: " + description['uuid'])

        # check and strip trailing slashes
        if 'volumes' in msg.params and msg.params['volumes'] is not None:
            for vol in msg.params['volumes']:
                if len(vol[0]) != 22 or len(vol[1]) == 0:
                    raise ValueError("Volume specifications are wrong")
                if vol[1][-1:] == '/':
                    vol[1] = vol[1][:-1]

        # Have a look at the configuration, replace any missing bits with defaults
        try:
            config = description['Config']
        except KeyError:
            raise ValueError("Config node not in description")
        Node._ensure_docker_config(config, 'Cmd', [])
        Node._ensure_docker_config(config, 'Entrypoint', [])
        Node._ensure_docker_config(config, 'Env', [])
        Node._ensure_docker_config(config, 'WorkingDir', '/')
        if config['WorkingDir'] == '':
            config['WorkingDir'] = '/'

        # allocate the container and fetch an IP from laksa
        ctr = Container(self, self.network, msg, config)
        self.containers[ctr.uuid] = ctr
        self.stats.containers = len(self.containers)
        logging.info("Spawning a container: %s" % ctr.name)
        self.connection.send_cmd(b'allocate_ip', {'container': ctr.uuid}, reply_callback=self._launch)

    def _launch(self, msg):
        # called when an ip has been allocated, also effectively an internal call
        # note that the container might've been nuked in the time we were waiting for an ip
        uuid = msg.params['container']
        if uuid in self.containers:
            container = self.containers[uuid]
            template = self.delta_tree.ensure_template(container.msg.params['layer_stack'], connection=self.connection)
            threading.Thread(target=container.launch,
                             args=(template, msg.params['ip']),
                             name="Launching ctr-" + uuid.decode(),
                             daemon=True).start()
        else:
            logging.warning("IP was allocated to a container, but it no longer exists: " +
                            str(msg.params['container']))
        msg.uuid = uuid  # fake replying to the original request

    def _wake_container(self, msg):
        logging.debug("Waking container: " + msg.params['container'].decode())
        self._ensure_valid_container(msg).wake()

    def _stdin_container(self, msg):
        self._ensure_valid_container(msg).stdin(msg.bulk)
        logging.debug("Injected into pty: " + msg.bulk.decode())

    def _heartbeat_container(self, msg):
        ctr = self._ensure_valid_container(msg)
        ctr.last_heartbeat = time.time()

    def _reboot_container(self, msg):
        ctr = self._ensure_valid_container(msg)
        ctr.reboot(msg.params['reset_filesystem'])

    def _destroy_container(self, msg):
        self._impl_destroy_container(msg.params['container'],
                                     not ('inform' in msg.params and msg.params['inform'] is False))

    def _impl_destroy_container(self, uuid, inform):
        try:
            ctr = self.containers[uuid]
        except KeyError:
            logging.debug("Caught attempt to destroy non-existent container, ignoring")
            return

        del self.containers[uuid]
        self.stats.containers = len(self.containers)
        ctr.destroy()

        # The client tells us if it doesn't want to be informed once the container has been destroyed
        if inform:
            # let the client know first (because we need the broker to forward the message)
            logging.debug("Informing client of destroyed container: " + ctr.name)
            ctr.msg.reply(self.connection.skt, {'status': 'destroyed'}, long_term=True)

            # and the broker
            logging.debug("Informing laksa of destroyed container: " + ctr.name)
            self.connection.send_cmd(b'destroyed_container', {'container': ctr.uuid,
                                                              'ip': ctr.ip,
                                                              'node_pk': self.connection.keys.public_binary()})

    def _run_process(self, msg):
        ctr = self._ensure_valid_container(msg)
        logging.info("Running (sync) a process: %s (%s)" % (msg.uuid, msg.params['command']))
        threading.Thread(target=self._impl_run_process,
                         args=(msg, ctr),
                         name="Process %s (%s)" % (msg.uuid, msg.params['command']),
                         daemon=True).start()

    def _impl_run_process(self, msg, ctr):
        # runs a blocking process on it's own thread
        stdout, stderr, exit_code = ctr.run_process(msg)
        skt = self.connection.send_skt()
        msg.reply(skt, {'stdout': stdout, 'stderr': stderr, 'exit_code': exit_code}, long_term=True)

    def _spawn_process(self, msg):
        self._ensure_valid_container(msg).spawn_process(msg)
        logging.info("Spawned (async) a process: %s (%s)" % (msg.uuid, msg.params['command']))

    def _spawn_shell(self, msg):
        self._ensure_valid_container(msg).spawn_shell(msg)
        logging.info("Spawned (async) a shell: " + str(msg.uuid))

    def _tty_window(self, msg):
        proc = self._ensure_valid_container(msg)._ensure_valid_process(msg)
        logging.debug("Setting window size: %s x %s" % (msg.params['width'], msg.params['height']))
        proc.set_window_size(msg.params['width'], msg.params['height'])

    def _stdin_process(self, msg):
        proc = self._ensure_valid_container(msg)._ensure_valid_process(msg)
        proc.stdin(msg.bulk)
        logging.debug("Injected into process (%s): %s" % (str(msg.params['process']), msg.bulk.decode()))

    def _destroy_process(self, msg):
        self._ensure_valid_container(msg).destroy_process(msg)
        logging.info("Destroyed process: " + str(msg.params['process']))

    def _allow_connection(self, msg):
        self._ensure_valid_container(msg).firewall_ip(msg.params['ip'], True)
        msg.reply(self.connection.skt)

    def _disallow_connection(self, msg):
        self._ensure_valid_container(msg).firewall_ip(msg.params['ip'], False)

    def _ping(self, msg):
        self._ensure_valid_container(msg).ping(msg.params['ip'])
        msg.reply(self.connection.skt)

    ################## SFTP
    # These are all blocking so we can return errors (path outside container) to the client

    def _stat_file(self, msg):
        try:
            stat = self._ensure_valid_container(msg).sftp.stat_file(msg.params['filename'])
            msg.reply(self.connection.skt, {'stat': stat})
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _lstat_file(self, msg):
        try:
            stat = self._ensure_valid_container(msg).sftp.lstat_file(msg.params['filename'])
            msg.reply(self.connection.skt, {'lstat': stat})
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _put_file(self, msg):
        container = self._ensure_valid_container(msg)
        uid = container.owner_uid()
        try:
            container.sftp.put_file(msg.params['filename'], uid, msg.bulk)
            msg.reply(self.connection.skt)
        except (TypeError, OSError) as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _fetch_file(self, msg):
        try:
            data = self._ensure_valid_container(msg).sftp.fetch_file(msg.params['filename'])
            msg.reply(self.connection.skt, bulk=data)
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _write_file(self, msg):
        try:
            container = self._ensure_valid_container(msg)
            uid = container.owner_uid()
            container.sftp.write_file(msg.params['filename'], msg.params['offset'], uid, msg.bulk)
            msg.reply(self.connection.skt)
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _rm_file(self, msg):
        try:
            self._ensure_valid_container(msg).sftp.rm_file(msg.params['filename'])
            msg.reply(self.connection.skt)
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _mv_file(self, msg):
        try:
            container = self._ensure_valid_container(msg)
            uid = container.owner_uid()
            container.sftp.mv_file(msg.params['filename'], msg.params['newpath'], uid)
            msg.reply(self.connection.skt)
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _ls_dir(self, msg):
        try:
            dir_entries = self._ensure_valid_container(msg).sftp.ls_dir(msg.params['directory'])
            msg.reply(self.connection.skt, {'entries': dir_entries})
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _mk_dir(self, msg):
        try:
            container = self._ensure_valid_container(msg)
            uid = container.owner_uid()
            container.sftp.mk_dir(msg.params['directory'], uid)
            msg.reply(self.connection.skt)
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    def _rm_dir(self, msg):
        try:
            self._ensure_valid_container(msg).sftp.rm_dir(msg.params['directory'])
            msg.reply(self.connection.skt)
        except OSError as e:
            msg.reply(self.connection.skt, {'error': e.errno})

    ################## Validation

    @staticmethod
    def _ensure_docker_config(config, parameter, default):
        # ensure a parameter exists in the DOCKER CONFIG, replace missing with defaults
        if parameter not in config or config[parameter] is None:
            config[parameter] = default

    def _ensure_valid_container(self, msg):
        if msg.params['container'] not in self.containers:
            raise ValueError("_ensure_valid_container failed for: " + msg.params['container'].decode())
        return self.containers[msg.params['container']]

    # commands are: {'command': (_function_to_call, ['list', 'essential, 'params'], needs_reply),....}

    _commands = {b'network_topology': (['topology'], False),

                 b'spawn_container': (['layer_stack', 'description', 'env', 'pre_boot_files', 'volumes'], True),
                 b'wake_container': (['container'], False),
                 b'stdin_container': (['container'], False),
                 b'heartbeat_container': (['container'], False),
                 b'reboot_container': (['container', 'reset_filesystem'], True),
                 b'destroy_container': (['container'], False),

                 b'stat_file': (['container', 'filename'], True),
                 b'lstat_file': (['container', 'filename'], True),
                 b'fetch_file': (['container', 'filename'], True),
                 b'put_file': (['container', 'filename'], True),
                 b'write_file': (['container', 'filename', 'offset'], True),
                 b'rm_file': (['container', 'filename'], True),
                 b'mv_file': (['container', 'filename', 'newpath'], True),
                 b'ls_dir': (['container', 'directory'], True),
                 b'mk_dir': (['container', 'directory'], True),
                 b'rm_dir': (['container', 'directory'], True),

                 b'run_process': (['container', 'command'], True),  # sync
                 b'spawn_process': (['container', 'command'], True),  # async, line by line
                 b'spawn_shell': (['container', 'echo'], True),  # async, has a pty
                 b'tty_window': (['container', 'process', 'width', 'height'], False),
                 b'stdin_process': (['container', 'process'], False),
                 b'destroy_process': (['container', 'process'], False),

                 b'allow_connection': (['container', 'ip'], True),
                 b'disallow_connection': (['container', 'ip'], False),
                 b'ping': (['container', 'ip'], True),
                 }

    def __repr__(self):
        return "<node.node.Node object at %x (containers=%x)>" % (id(self), len(self.containers))
