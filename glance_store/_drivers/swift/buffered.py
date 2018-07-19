#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import socket
import tempfile

from oslo_config import cfg
from oslo_utils import encodeutils

from glance_store import exceptions
from glance_store.i18n import _

LOG = logging.getLogger(__name__)
READ_SIZE = 65536

BUFFERING_OPTS = [
    cfg.StrOpt('swift_upload_buffer_dir',
               help="""
Directory to buffer image segments before upload to Swift.

Provide a string value representing the absolute path to the
directory on the glance node where image segments will be
buffered briefly before they are uploaded to swift.

NOTES:
* This is required only when the configuration option
  ``swift_buffer_on_upload`` is set to True.
* This directory should be provisioned keeping in mind the
  ``swift_store_large_object_chunk_size`` and the maximum
  number of images that could be uploaded simultaneously by
  a given glance node.

Possible values:
    * String value representing an absolute directory path

Related options:
    * swift_buffer_on_upload
    * swift_store_large_object_chunk_size

"""),
]
CONF = cfg.CONF


def validate_buffering(buffer_dir):
    if buffer_dir is None:
        msg = _('Configuration option "swift_upload_buffer_dir" is '
                'not set. Please set it to a valid path to buffer '
                'during Swift uploads.')
        raise exceptions.BadStoreConfiguration(store_name='swift',
                                               reason=msg)

    # NOTE(dharinic): Ensure that the provided directory path for
    # buffering is valid
    try:
        _tmpfile = tempfile.TemporaryFile(dir=buffer_dir)
    except OSError as err:
        msg = (_('Unable to use buffer directory set with '
                 '"swift_upload_buffer_dir". Error: %s') %
               encodeutils.exception_to_unicode(err))
        raise exceptions.BadStoreConfiguration(store_name='swift',
                                               reason=msg)
    else:
        _tmpfile.close()
        return True


class BufferedReader(object):
    """Buffer a chunk (segment) worth of data to disk before sending it swift.
    This creates the ability to back the input stream up and re-try put object
    requests.  (Swiftclient will try to reset the file pointer on any upload
    failure if seek and tell methods are provided on the input file.)

    Chunks are temporarily buffered to disk.  Disk space consumed will be
    roughly (segment size * number of in-flight upload requests).

    There exists a possibility where the disk space consumed for buffering MAY
    eat into the disk space available for glance cache. This may affect image
    download performance. So, extra care should be taken while deploying this
    to ensure there is enough disk space available.
    """

    def __init__(self, fd, checksum, os_hash_value, total, verifier=None,
                 backend_group=None):
        self.fd = fd
        self.total = total
        self.checksum = checksum
        self.os_hash_value = os_hash_value
        self.verifier = verifier
        self.backend_group = backend_group
        # maintain a pointer to use to update checksum and verifier
        self.update_position = 0

        if self.backend_group:
            buffer_dir = getattr(CONF,
                                 self.backend_group).swift_upload_buffer_dir
        else:
            buffer_dir = CONF.glance_store.swift_upload_buffer_dir

        self._tmpfile = tempfile.TemporaryFile(dir=buffer_dir)

        self._buffered = False
        self.is_zero_size = False
        self._buffer()
        # Setting the file pointer back to the beginning of file
        self._tmpfile.seek(0)

    def read(self, size):
        """Read up to a chunk's worth of data from the input stream into a
        file buffer.  Then return data out of that buffer.
        """
        remaining = self.total - self._tmpfile.tell()
        read_size = min(remaining, size)
        # read out of the buffered chunk
        result = self._tmpfile.read(read_size)
        # update the checksum and verifier with only the bytes
        # they have not seen
        update = self.update_position - self._tmpfile.tell()
        if update < 0:
            self.checksum.update(result[update:])
            self.os_hash_value.update(result[update:])
            if self.verifier:
                self.verifier.update(result[update:])
            self.update_position += abs(update)
        return result

    def _buffer(self):
        to_buffer = self.total
        LOG.debug("Buffering %s bytes of image segment" % to_buffer)

        while not self._buffered:
            read_size = min(to_buffer, READ_SIZE)
            try:
                buf = self.fd.read(read_size)
            except IOError as e:
                # We actually don't know what exactly self.fd is. And as a
                # result we don't know which exception it may raise. To pass
                # the retry mechanism inside swift client we must limit the
                # possible set of errors.
                raise socket.error(*e.args)
            if len(buf) == 0:
                self._tmpfile.seek(0)
                self._buffered = True
                self.is_zero_size = True
                break
            self._tmpfile.write(buf)
            to_buffer -= len(buf)

    # NOTE(belliott) seek and tell get used by python-swiftclient to "reset"
    # if there is a put_object error
    def seek(self, offset):
        LOG.debug("Seek from %s to %s" % (self._tmpfile.tell(), offset))
        self._tmpfile.seek(offset)

    def tell(self):
        return self._tmpfile.tell()

    @property
    def bytes_read(self):
        return self.tell()

    def __enter__(self):
        self._tmpfile.__enter__()
        return self

    def __exit__(self, type, value, traceback):
        # close and delete the temporary file used to buffer data
        self._tmpfile.__exit__(type, value, traceback)
