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
"""Creating (and maintaining) the network environment"""

# A node on addresses
# * Tunnels are created on 10.US.0.THEM where 'us' and 'them' are subnet id's
# * Default route is 10.US.0.1
# * The bridge gets 10.US.0.US because we'll never use that as a tunnel


import logging
import re
from subprocess import call, check_output, DEVNULL, CalledProcessError


class Network:
    nfs_port = "2049"

    def __init__(self):
        # get node details
        self.subnet_id = None
        self.external_ip = Network.external_ip()
        self.external_ip_cidr = Network.external_ip_cidr()
        self.external_if = Network.external_if()
        self.dns_servers = Network.dns_servers()
        self.tunnels = set()
        logging.debug("external_ip: %s   external_if: %s" % (self.external_ip, self.external_if))

    def __del__(self):
        # clean up networking changes
        if b'tfbr' in check_output(['ip', 'link', 'show']):
            call(['ip', 'link', 'del', 'tfbr'])
        call(['iptables', '-F', 'FORWARD'])
        # call(['iptables', '-F', 'INPUT'])  # don't mess with input because Fail2Ban needs it
        call(['iptables', '-t', 'nat', '-F', 'PREROUTING'])
        call(['iptables', '-t', 'nat', '-F', 'POSTROUTING'])
        for tunnel in self.tunnels:
            call(['ip', 'link', 'del', tunnel])

    @staticmethod
    def external_ip():
        return check_output(['hostname', '-I'])[:-1].decode().split()[0]

    @staticmethod
    def external_ip_cidr():
        ip = Network.external_ip()
        output = check_output(['ip', 'addr']).decode()
        result = re.search(ip + '/[0-9]+', output)
        return result.group(0)

    @staticmethod
    def external_if():
        ip_line = check_output(['ip addr show | grep ' + Network.external_ip()], shell=True)
        return ip_line.split(b' ')[-1][:-1] .decode()  # last one, lose the /n

    @staticmethod
    def drop_incoming_from_underlay(*, reverse=False):
        # but allow ping and established connections
        flag = ('-I' if reverse is False else '-D')
        call(['iptables', flag, 'INPUT', '-s', '10.0.0.0/8', '-j', 'DROP'])
        call(['iptables', flag, 'INPUT', '-p', 'icmp', '--icmp-type', '8', '-j', 'ACCEPT'])
        call(['iptables', flag, 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])

    @staticmethod
    def allow_incoming_from_node(subnet, *, reverse=False):
        sn = '10.%s.0.1/32' % subnet
        call(['iptables', ('-I' if reverse is False else '-D'), 'INPUT', '-s', sn, '-j', 'ACCEPT'])

    @staticmethod
    def dns_servers():
        with open('/etc/resolv.conf') as f:
            resolv = f.read()
        return [s[11:] for s in re.findall('nameserver [0-9]+.[0-9]+.[0-9]+.[0-9]+', resolv)]

    def create_container_interface(self, ctr_name):
        """Create a network interface that can be passed to the container"""
        ctr_name = ctr_name[4:12]

        # create the virtual ethernet pair
        call(['ip', 'link', 'add', 've-' + ctr_name, 'type', 'veth', 'peer', 'name', 'vec-' + ctr_name])

        return 'vec-' + ctr_name

    def configure_container_interface(self, if_name, ip, pid, *, whitelist=None):
        # set host end onto the bridge
        # gre headers assumed 24 bytes
        # https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/25885-pmtud-ipfrag.html
        host_if = if_name[:2] + if_name[3:]
        call(['ip', 'link', 'set', 'dev', host_if, 'master', 'tfbr'], stdout=DEVNULL)
        call(['ip', 'link', 'set', host_if, 'up'], stdout=DEVNULL)
        call(['ip', 'link', 'set', 'mtu', '8976', host_if])

        # set local firewalling - self, laksa, host end of bridge, established connections, otherwise not so much
        call(['nsenter', '-F', '-n', '-t', pid,
              'iptables', '--policy', 'INPUT', 'DROP'])
        call(['nsenter', '-n', '-t', pid,
              'iptables', '-A', 'INPUT', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
        call(['nsenter', '-F', '-n', '-t', pid,
              'iptables', '-A', 'INPUT', '-s', '127.0.0.1/32', '-j', 'ACCEPT'])
        call(['nsenter', '-F', '-n', '-t', pid,
              'iptables', '-A', 'INPUT', '-s', '%s/32' % ip, '-j', 'ACCEPT'])
        call(['nsenter', '-F', '-n', '-t', pid,
              'iptables', '-A', 'INPUT', '-s', '10.1.0.%s/32' % self.subnet_id, '-j', 'ACCEPT'])

        # not allowed to try to contact the internal lan except for whitelist servers
        if whitelist is not None:
            for white_ip in whitelist:
                call(['nsenter', '-F', '-n', '-t', pid,
                      'iptables', '-A', 'OUTPUT', '-d', white_ip, '-j', 'ACCEPT'])
        call(['nsenter', '-F', '-n', '-t', pid,
              'iptables', '-A', 'OUTPUT', '-d', self.external_ip_cidr, '-j', 'DROP'])

        # configure the network interface itself
        call(['nsenter', '-F', '-n', '-t', pid,
              'ip', 'addr', 'add', ip + '/16', 'dev', if_name])
        call(['nsenter', '-F', '-n', '-t', pid,
              'ip', 'link', 'set', if_name, 'up'])
        call(['nsenter', '-F', '-n', '-t', pid,
              'ip', 'link', 'set', 'mtu', '8976', if_name])

        # add default route via local bridge
        call(['nsenter', '-F', '-n', '-t', pid,
              'ip', 'route', 'add', 'default', 'via', '10.%s.0.%s' % (self.subnet_id, self.subnet_id)])

        # ensure the network is up
        for attempts in range(0, 10):
            try:
                ping_out = check_output(['nsenter', '-F', '-n', '-t', pid, 'ping', '-c', '1', '-w', '1', '10.1.0.1'])
                if b'1 received' not in ping_out:
                    raise RuntimeError("Container could not connect to the head node")
                return
            except CalledProcessError:
                logging.debug("Trying  again to connect to head node")
                pass

    def ping(self, pid, ip):
        call(['nsenter', '-F', '-n', '-t', pid, 'ping', '-c', '1', '-w', '1', ip], stdout=DEVNULL)

    def firewall_container_ip(self, pid, ip, allow):
        call(['nsenter', '-F', '-n', '-t', str(pid),
              'iptables', ('-I' if allow else '-D'), 'INPUT', '-s', ip + '/32', '-j', 'ACCEPT'])

    def ping_peers(self):
        for tunnel in self.tunnels:
            subnet = tunnel[3:]
            call(['ping', '-c', '1', '-w', '1', '10.%s.0.%s' % (subnet, subnet)], stdout=DEVNULL)

    def topology(self, subnets_and_addresses):
        # takes a map of subnet_id->address pairs
        logging.info("Informed of network topology: " + str(subnets_and_addresses))

        # have we done the basics?
        if self.subnet_id is None:
            for subnet, external_ip in subnets_and_addresses:
                if external_ip == self.external_ip:
                    # set subnet
                    self.subnet_id = subnet
                    call(['sysctl', '-w', 'net.ipv4.ip_forward=1'], stdout=DEVNULL)

                    # create bridge
                    # bridge creates it's own route, you don't need to add one
                    # can't set the mtu on the bridge, the veths should set it when connected
                    call(['ip', 'link', 'add', 'tfbr', 'type', 'bridge'], stdout=DEVNULL)
                    call(['ip', 'link', 'set', 'tfbr', 'up'])
                    call(['ip', 'addr', 'add', '10.%s.0.%s/16' % (subnet, subnet), 'dev', 'tfbr'], stdout=DEVNULL)

                    # create address translator
                    call(['iptables', '-t', 'nat', '-A', 'POSTROUTING',
                          '-s', '10.%s.0.0/16' % subnet, '-o', self.external_if, '-j', 'MASQUERADE'], stdout=DEVNULL)
                    call(['iptables', '-A', 'FORWARD', '-i', self.external_if, '-o', 'tfbr',
                          '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'])
                    call(['iptables', '-A', 'FORWARD', '-i', 'tfbr', '-o', self.external_if, '-j', 'ACCEPT'])

        # I may not have been informed of my own topology yet...
        if self.subnet_id is None:
            return

        # build tunnels between nodes
        remove_tunnels = set(self.tunnels)
        add_subnets = []
        for other_node_subnet_id, other_node_external_ip in subnets_and_addresses:
            # don't tunnel onto myself
            if other_node_subnet_id == self.subnet_id:
                continue

            # don't make a tunnel twice
            if 'tun' + other_node_subnet_id in self.tunnels:
                remove_tunnels.remove('tun' + other_node_subnet_id)  # still using this tunnel
                continue
            add_subnets.append(other_node_subnet_id)

            # build a tunnel between peers - address is 10.US.0.THEM
            # ip tunnel show
            # destination shows up wrong on ifconfig
            self.tunnels.add('tun' + other_node_subnet_id)
            call(['ip', 'tunnel', 'add', 'tun' + other_node_subnet_id, 'mode', 'gre',
                  'local', self.external_ip, 'remote', other_node_external_ip], stderr=DEVNULL, stdout=DEVNULL)
            call(['ip', 'link', 'set', 'mtu', '8976', 'tun' + other_node_subnet_id])
            call(['ip', 'addr', 'add', '10.%s.0.%s/16' % (self.subnet_id, other_node_subnet_id),
                  'dev', 'tun' + other_node_subnet_id], stderr=DEVNULL, stdout=DEVNULL)
            call(['ip', 'link', 'set', 'tun' + other_node_subnet_id, 'up'])
            call(['ip', 'route', 'add', '10.%s.0.0/16' % other_node_subnet_id,
                  'via', '10.%s.0.%s' % (self.subnet_id, other_node_subnet_id), 'dev', 'tun' + other_node_subnet_id],
                 stderr=DEVNULL, stdout=DEVNULL)
            logging.debug("Created a tunnel: tun" + other_node_subnet_id)

        # any tunnels left in remove_tunnels have been created but weren't referenced this time round
        for tun in remove_tunnels:
            if tun == 'tun1':
                continue  # don't remove the tunnel to the head node.
            call(['ip', 'link', 'delete', tun])  # takes the route with it
            self.tunnels.remove(tun)
            logging.debug("Removed tunnel: " + tun)

        # returns lists of subnets that were added and removed
        return add_subnets, [tun[3:] for tun in remove_tunnels]
