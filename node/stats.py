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
"""Sending node stats to laksa, independent process"""

from subprocess import Popen, PIPE
import threading
import logging
import weakref
import boto3
import awsornot
import requests


class Stats(threading.Thread):

    def __init__(self, dest, conn):
        super().__init__(group=None)
        self.name = "StatsThread"
        self.dest = dest
        self.kill = False
        self.conn = weakref.ref(conn)

        # can be written in (or not)
        self.containers = 0

        self.starts = 0
        self.start_time_total = 0
        self.current_ave_start_time = 0

        # the stats process
        self.vmstat = Popen(['vmstat', '5'], stdout=PIPE)
        self.vmstat.stdout.readline()  # bin the first three lines
        self.vmstat.stdout.readline()
        self.vmstat.stdout.readline()

        # possibly reporting to AWS too
        self.dynamic_data = awsornot.dynamic_data_or_none()
        if self.dynamic_data is not None:
            self.aws_stats = boto3.client('cloudwatch', region_name=self.dynamic_data['region'])
            self.iid = requests.get('http://169.254.169.254/latest/meta-data/instance-id').text

    def stop(self):
        self.vmstat.terminate()

    def container_startup(self, time):
        self.starts += 1
        self.start_time_total += time

    def run(self):
        logging.info("Stats thread started")

        while True:
            # internal stats
            if self.starts > 0:
                self.current_ave_start_time = self.start_time_total / self.starts
                self.starts = 0
                self.start_time_total = 0
            else:
                self.current_ave_start_time = 0

            # machine stats
            statline = self.vmstat.stdout.readline()
            if len(statline) == 0:  # process has been terminated
                logging.info("Stats thread finished")
                return
            parts = str(statline, 'ascii').split()

            # vmstat is prone to printing things that are not actually what we want, hence the try
            stats = {}
            try:
                stats = {"memory": int(parts[3]) + int(parts[5]),  # free plus cache
                         "paging": int(parts[6]) + int(parts[7]),  # swap in plus swap out
                         "cpu": int(parts[14]),  # percent
                         "ave_start_time": self.current_ave_start_time}
            except (ValueError, IndexError):
                continue

            # send the update
            if self.conn().connected:
                self.conn().send_cmd(b'update_stats', {'stats': stats})

            # aws?
            if self.dynamic_data is not None:
                self.aws_stats.put_metric_data(
                    Namespace='20ft Nodes',
                    MetricData=[
                        {
                            'MetricName': 'FreeMemory',
                            'Unit': 'Kilobytes',
                            'Value': stats['memory'],
                            'Dimensions': [
                                {
                                    'Name': 'InstanceID',
                                    'Value': self.iid
                                }
                            ]
                        },
                        {
                            'MetricName': 'FreeCPU',
                            'Unit': 'Percent',
                            'Value': stats['cpu'],
                            'Dimensions': [
                                {
                                    'Name': 'InstanceID',
                                    'Value': self.iid
                                }
                            ]
                        },
                        {
                            'MetricName': 'Paging',
                            'Unit': 'Kilobytes/Second',
                            'Value': stats['paging'],
                            'Dimensions': [
                                {
                                    'Name': 'InstanceID',
                                    'Value': self.iid
                                }
                            ]
                        },
                        {
                            'MetricName': 'Containers',
                            'Unit': 'Count',
                            'Value': self.containers,
                            'Dimensions': [
                                {
                                    'Name': 'InstanceID',
                                    'Value': self.iid
                                }
                            ]
                        },
                        {
                            'MetricName': 'AveStartupTime',
                            'Unit': 'Seconds',
                            'Value': stats['ave_start_time'],
                            'Dimensions': [
                                {
                                    'Name': 'InstanceID',
                                    'Value': self.iid
                                }
                            ]
                        }
                    ]
                )

    def __repr__(self):
        return "<node.stats.Stats object at %x>" % id(self)
