# (c) David Preece 2016-2017
# davep@polymath.tech : https://polymath.tech/ : https://github.com/rantydave
# This work licensed under the Non-profit Open Software Licence version 3 (https://opensource.org/licenses/NPOSL-3.0)
# For commercial licensing see https://20ft.nz/
"""Builds a tree of root -> sha256 -> sha256 -> etc."""
# btw, you can clean the whole lot up with zfs destroy -R tf/layer-

import requests
import logging
import shortuuid
import io
from awsornot import ensure_zpool
from tarfile import TarFile, ReadError
from subprocess import call, check_output, DEVNULL, CalledProcessError


class DtNode:
    def __init__(self, snapshot):
        self.deltas = {}  # possible next steps, not a stack
        self.snapshot = snapshot

    def __repr__(self):
        return "<files.deltatree.DtNode object at %x ('%s' to %s)>" % \
               (id(self), self.snapshot[12:18], ([key[:6] for key in self.deltas.keys()]))


class DeltaTree:
    # idea is that for any particular image we can start at 'blank' and work up the tree
    # until we find the closest node to what we want anyway, then start building from there

    def __init__(self, location_ip):
        self.location_ip = location_ip
        ensure_zpool('tf')

        # create the base snapshot if it's not there
        zfs_list = check_output(['zfs', 'list', '-H', '-t', 'snapshot', '-o', 'name'])
        zfs_list = str(zfs_list, 'ascii').split('\n')
        if 'tf/layer-@final' not in zfs_list:  # ensure we have the root fs
            call(['zfs', 'create',
                  '-o', 'sync=disabled',
                  '-o', 'dedup=on',
                  'tf/layer-'], stdout=DEVNULL)
            call(['zfs', 'snapshot', 'tf/layer-@final'], stdout=DEVNULL)
            call(['umount', 'tf/layer-'], stdout=DEVNULL)
            call(['rmdir', '/tf/layer-'], stdout=DEVNULL)

        # make a list of snapshots and their metadata
        layer_snapshots = []
        for fs in zfs_list:
            # if it's not one of ours, skip to the next one
            if len(fs) != 37 or fs[:9] != 'tf/layer-':
                continue
            # get the layer stack property from the filesystem
            ls_prop = check_output(['zfs', 'get', '-H', '-o',  'value', ':layer_stack', fs])
            if ls_prop == '-\n':  # zfs get prints a - when the property is blank
                continue
            # split into an actual stack and store
            layer_stack = str(ls_prop[:-1], 'ascii').split('/')
            layer_snapshots.append((fs, layer_stack))

        # sort the snapshots so the roots are created first
        layer_snapshots.sort(key=lambda snap: len(snap[1]))

        # build tree entries from metadata
        self.root = DtNode('tf/layer-@final')
        for snapshot in layer_snapshots:
            # go through each delta and create a single path up the tree
            position = self.root  # DtNode
            for step in snapshot[1]:
                if step not in position.deltas:
                    position.deltas[step] = DtNode(snapshot[0])
                position = position.deltas[step]

    def find_furthest(self, layer_stack):
        """Finds how far up the layer stack we can go with what we've got"""
        success_counter = 0
        position = self.root

        # iterate up the tree until we get as far as we can
        for delta in layer_stack:
            logging.debug("Trying for delta: " + delta)
            if delta in position.deltas:
                position = position.deltas[delta]
                success_counter += 1
            else:
                break
        return position, success_counter

    def ensure_template(self, layer_stack, connection=None):  # connection needs to be here
        """Create the base image for a container"""
        # find how many of the intermediate snapshots we already have
        last, success_count = self.find_furthest(layer_stack)
        logging.debug("Delta tree creating with head start: " + str(success_count))

        # layer stack is a list of deltas in the order they were written in
        layers_so_far = '/'.join(layer_stack[:success_count])
        for layer in layer_stack[success_count:]:
            logging.debug("Creating layer: " + layer)

            # the / delimited list of sha256 deltas used to create this layer
            layers_so_far += ('/' if len(layers_so_far) != 0 else '') + layer

            # the next layer is a inherited (cloned) from a snapshot
            dest_fs = 'tf/layer-' + shortuuid.uuid()  # need a uuid for namespace collisions
            call(['zfs', 'clone',
                  '-o', 'recordsize=8k',
                  '-o', 'compression=on',
                  last.snapshot, dest_fs], stdout=DEVNULL)

            # fetch via http then untar a pretend file
            layer_http = requests.get('http://%s:1025/%s' % (self.location_ip, layer))
            with io.BytesIO(layer_http.content) as f:
                tar = TarFile(fileobj=f)
                tar.extractall('/' + dest_fs)

            # create the snapshot and mark it so we know what it represents
            call(['zfs', 'snapshot', '%s@final' % dest_fs], stdout=DEVNULL)
            call(['zfs', 'set', ':layer_stack=' + layers_so_far, '%s@final' % dest_fs])

            # clean the mess up
            call(['zfs', 'unmount', dest_fs], stdout=DEVNULL)
            call(['rmdir', '/' + dest_fs])

            # let the delta tree know
            new_node = DtNode(dest_fs + "@final")
            last.deltas[layer] = new_node
            last = new_node

        return last.snapshot

    def __repr__(self):
        return "<files.deltatree.DeltaTree object at %x>" % id(self)
