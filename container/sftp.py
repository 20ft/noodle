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
"""A simple stateless sftp server"""


import logging
import os
import os.path


class Sftp:
    def __init__(self, validation_callback):
        # Path validation. Will call on 'parent' container object, may throw a ValueError
        self.validation_callback = validation_callback

    def lstat_file(self, filename):
        return self.stat_file(filename, lstat=False)

    def stat_file(self, filename, lstat=True):
        path = self.validation_callback(filename)
        logging.debug(("Stat file: " if lstat else "Lstat file: ") + path)
        return os.lstat(path) if lstat else os.stat(path)

    def fetch_file(self, filename):
        path = self.validation_callback(filename)

        # is actually a file
        if not os.path.isfile(path):
            raise ValueError("Filename is not actually a file")

        # OK, we're probably legit
        with open(path, 'rb') as file:
            logging.debug("Fetched From: " + filename)
            return file.read()

    def put_file(self, filename, uid, bulk):
        path = self.validation_callback(filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)

        # Sometimes we'll be sent strings.
        with open(path, 'wb') as f:
            if isinstance(bulk, str):
                f.write(bulk.encode())
            else:
                f.write(bulk)
            os.fchown(f.fileno(), uid, uid)
        logging.debug("Put: " + path)

    def write_file(self, filename, offset, uid, bulk):
        # prep
        path = self.validation_callback(filename)
        if offset == 0:  # we take this to mean "writing a new file now"
            if os.path.exists(path):  # file is there already, remove it first
                os.remove(path)
            else:
                # ensure we can make the file
                os.makedirs(os.path.dirname(path), exist_ok=True)
                os.chown(os.path.dirname(path) + '/', uid, uid)

        # write
        with open(path, 'r+b' if offset != 0 else 'wb') as f:
            logging.debug("Writing file: %s [%d +%d]" % (filename, offset, len(bulk)))
            f.seek(offset)
            f.write(bulk)
            os.fchown(f.fileno(), uid, uid)

    def rm_file(self, filename):
        path = self.validation_callback(filename)
        os.remove(path)
        logging.debug("File was removed: " + path)

    def mv_file(self, filename, newpath, uid):
        src = self.validation_callback(filename)
        dest = self.validation_callback(newpath)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        os.chown(os.path.dirname(dest) + '/', uid, uid)
        os.replace(src, dest)
        logging.debug("File was moved to: " + dest)

    def ls_dir(self, directory):
        path = self.validation_callback(directory)
        return [(entry.name, entry.stat(follow_symlinks=False)) for entry in os.scandir(path)]

    def mk_dir(self, directory, uid):
        path = self.validation_callback(directory)
        os.makedirs(path, exist_ok=True)
        os.chown(path + '/', uid, uid)
        logging.debug("Made a directory: " + path)

    def rm_dir(self, directory):
        path = self.validation_callback(directory)
        os.rmdir(path)
        logging.debug("Removed a directory: " + path)

    def __repr__(self):
        return "<container.sftp.Sftp object at %x>" % id(self)
