# Copyright 2010 OpenStack Foundation
# All Rights Reserved.
#
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

"""Storage backend for S3 or Storage Servers that follow the S3 Protocol"""

import hashlib
import httplib
import logging
import math
import re
import tempfile
import urlparse

import eventlet
from oslo_config import cfg
from oslo_utils import netutils
from oslo_utils import units
import six

import glance_store
from glance_store import capabilities
from glance_store.common import utils
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _
import glance_store.location

LOG = logging.getLogger(__name__)
_LE = glance_store.i18n._LE
_LI = glance_store.i18n._LI

DEFAULT_LARGE_OBJECT_SIZE = 100          # 100M
DEFAULT_LARGE_OBJECT_CHUNK_SIZE = 10     # 10M
DEFAULT_LARGE_OBJECT_MIN_CHUNK_SIZE = 5  # 5M
DEFAULT_THREAD_POOLS = 10                # 10 pools
MAX_PART_NUM = 10000                     # 10000 upload parts

_S3_OPTS = [
    cfg.StrOpt('s3_store_host',
               help=_('The host where the S3 server is listening.')),
    cfg.StrOpt('s3_store_access_key', secret=True,
               help=_('The S3 query token access key.')),
    cfg.StrOpt('s3_store_secret_key', secret=True,
               help=_('The S3 query token secret key.')),
    cfg.StrOpt('s3_store_bucket',
               help=_('The S3 bucket to be used to store the Glance data.')),
    cfg.StrOpt('s3_store_object_buffer_dir',
               help=_('The local directory where uploads will be staged '
                      'before they are transferred into S3.')),
    cfg.BoolOpt('s3_store_create_bucket_on_put', default=False,
                help=_('A boolean to determine if the S3 bucket should be '
                       'created on upload if it does not exist or if '
                       'an error should be returned to the user.')),
    cfg.StrOpt('s3_store_bucket_url_format', default='subdomain',
               help=_('The S3 calling format used to determine the bucket. '
                      'Either subdomain or path can be used.')),
    cfg.IntOpt('s3_store_large_object_size',
               default=DEFAULT_LARGE_OBJECT_SIZE,
               help=_('What size, in MB, should S3 start chunking image files '
                      'and do a multipart upload in S3.')),
    cfg.IntOpt('s3_store_large_object_chunk_size',
               default=DEFAULT_LARGE_OBJECT_CHUNK_SIZE,
               help=_('What multipart upload part size, in MB, should S3 use '
                      'when uploading parts. The size must be greater than or '
                      'equal to 5M.')),
    cfg.IntOpt('s3_store_thread_pools', default=DEFAULT_THREAD_POOLS,
               help=_('The number of thread pools to perform a multipart '
                      'upload in S3.')),
]


class UploadPart(object):

    """
    The class for the upload part
    """

    def __init__(self, mpu, fp, partnum, chunks):
        self.mpu = mpu
        self.partnum = partnum
        self.fp = fp
        self.size = 0
        self.chunks = chunks
        self.etag = {}  # partnum -> etag
        self.success = True


def run_upload(part):
    """
    Upload the upload part into S3 and set returned etag and size
    to its part info.
    """
    # We defer importing boto until now since it is an optional dependency.
    import boto.exception
    pnum = part.partnum
    bsize = part.chunks
    LOG.info(_LI("Uploading upload part in S3 partnum=%(pnum)d, "
                 "size=%(bsize)d, key=%(key)s, UploadId=%(UploadId)s") %
             {'pnum': pnum,
              'bsize': bsize,
              'key': part.mpu.key_name,
              'UploadId': part.mpu.id})

    try:
        key = part.mpu.upload_part_from_file(part.fp,
                                             part_num=part.partnum,
                                             size=bsize)
        part.etag[part.partnum] = key.etag
        part.size = key.size
    except boto.exception.BotoServerError as e:
        status = e.status
        reason = e.reason
        LOG.error(_LE("Failed to upload part in S3 partnum=%(pnum)d, "
                      "size=%(bsize)d, status=%(status)d, "
                      "reason=%(reason)s") %
                  {'pnum': pnum,
                   'bsize': bsize,
                   'status': status,
                   'reason': reason})
        part.success = False
    except Exception as e:
        LOG.error(_LE("Failed to upload part in S3 partnum=%(pnum)d, "
                      "size=%(bsize)d due to internal error: %(err)s") %
                  {'pnum': pnum,
                   'bsize': bsize,
                   'err': e})
        part.success = False
    finally:
        part.fp.close()


class StoreLocation(glance_store.location.StoreLocation):

    """
    Class describing an S3 URI. An S3 URI can look like any of
    the following:

        s3://accesskey:secretkey@s3.amazonaws.com/bucket/key-id
        s3+http://accesskey:secretkey@s3.amazonaws.com/bucket/key-id
        s3+https://accesskey:secretkey@s3.amazonaws.com/bucket/key-id

    The s3+https:// URIs indicate there is an HTTPS s3service URL
    """

    def process_specs(self):
        self.scheme = self.specs.get('scheme', 's3')
        self.accesskey = self.specs.get('accesskey')
        self.secretkey = self.specs.get('secretkey')
        s3_host = self.specs.get('s3serviceurl')
        self.bucket = self.specs.get('bucket')
        self.key = self.specs.get('key')

        if s3_host.startswith('https://'):
            self.scheme = 's3+https'
            s3_host = s3_host[8:].strip('/')
        elif s3_host.startswith('http://'):
            s3_host = s3_host[7:].strip('/')
        self.s3serviceurl = s3_host.strip('/')

    def _get_credstring(self):
        if self.accesskey:
            return '%s:%s@' % (self.accesskey, self.secretkey)
        return ''

    def get_uri(self):
        return "%s://%s%s/%s/%s" % (
            self.scheme,
            self._get_credstring(),
            self.s3serviceurl,
            self.bucket,
            self.key)

    def parse_uri(self, uri):
        """
        Parse URLs. This method fixes an issue where credentials specified
        in the URL are interpreted differently in Python 2.6.1+ than prior
        versions of Python.

        Note that an Amazon AWS secret key can contain the forward slash,
        which is entirely retarded, and breaks urlparse miserably.
        This function works around that issue.
        """
        # Make sure that URIs that contain multiple schemes, such as:
        # s3://accesskey:secretkey@https://s3.amazonaws.com/bucket/key-id
        # are immediately rejected.
        if uri.count('://') != 1:
            reason = _("URI cannot contain more than one occurrence "
                       "of a scheme. If you have specified a URI like "
                       "s3://accesskey:secretkey@"
                       "https://s3.amazonaws.com/bucket/key-id"
                       ", you need to change it to use the "
                       "s3+https:// scheme, like so: "
                       "s3+https://accesskey:secretkey@"
                       "s3.amazonaws.com/bucket/key-id")
            LOG.info(_LI("Invalid store uri: %s") % reason)
            raise exceptions.BadStoreUri(message=reason)

        pieces = urlparse.urlparse(uri)
        assert pieces.scheme in ('s3', 's3+http', 's3+https')
        self.scheme = pieces.scheme
        path = pieces.path.strip('/')
        netloc = pieces.netloc.strip('/')
        entire_path = (netloc + '/' + path).strip('/')

        if '@' in uri:
            creds, path = entire_path.split('@')
            cred_parts = creds.split(':')

            try:
                access_key = cred_parts[0]
                secret_key = cred_parts[1]
                # NOTE(jaypipes): Need to encode to UTF-8 here because of a
                # bug in the HMAC library that boto uses.
                # See: http://bugs.python.org/issue5285
                # See: http://trac.edgewall.org/ticket/8083
                access_key = access_key.encode('utf-8')
                secret_key = secret_key.encode('utf-8')
                self.accesskey = access_key
                self.secretkey = secret_key
            except IndexError:
                reason = _("Badly formed S3 credentials")
                LOG.info(reason)
                raise exceptions.BadStoreUri(message=reason)
        else:
            self.accesskey = None
            path = entire_path
        try:
            path_parts = path.split('/')
            self.key = path_parts.pop()
            self.bucket = path_parts.pop()
            if path_parts:
                self.s3serviceurl = '/'.join(path_parts).strip('/')
            else:
                reason = _("Badly formed S3 URI. Missing s3 service URL.")
                raise exceptions.BadStoreUri(message=reason)
        except IndexError:
            reason = _("Badly formed S3 URI")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)


class ChunkedFile(object):

    """
    We send this back to the Glance API server as
    something that can iterate over a ``boto.s3.key.Key``
    """

    def __init__(self, fp, chunk_size):
        self.fp = fp
        self.chunk_size = chunk_size

    def __iter__(self):
        """Return an iterator over the image file."""
        try:
            if self.fp:
                while True:
                    chunk = self.fp.read(self.chunk_size)
                    if chunk:
                        yield chunk
                    else:
                        break
        finally:
            self.close()

    def getvalue(self):
        """Return entire string value... used in testing."""
        data = ""
        self.len = 0
        for chunk in self:
            read_bytes = len(chunk)
            data = data + chunk
            self.len = self.len + read_bytes
        return data

    def close(self):
        """Close the internal file pointer."""
        if self.fp:
            self.fp.close()
            self.fp = None


class Store(glance_store.driver.Store):
    """An implementation of the s3 adapter."""

    _CAPABILITIES = capabilities.BitMasks.RW_ACCESS
    OPTIONS = _S3_OPTS
    EXAMPLE_URL = "s3://<ACCESS_KEY>:<SECRET_KEY>@<S3_URL>/<BUCKET>/<OBJ>"

    READ_CHUNKSIZE = 64 * units.Ki
    WRITE_CHUNKSIZE = READ_CHUNKSIZE

    def get_schemes(self):
        return ('s3', 's3+http', 's3+https')

    def configure_add(self):
        """
        Configure the Store to use the stored configuration options
        Any store that needs special configuration should implement
        this method. If the store was not able to successfully configure
        itself, it should raise `exceptions.BadStoreConfiguration`
        """
        self.s3_host = self._option_get('s3_store_host')
        access_key = self._option_get('s3_store_access_key')
        secret_key = self._option_get('s3_store_secret_key')
        # NOTE(jaypipes): Need to encode to UTF-8 here because of a
        # bug in the HMAC library that boto uses.
        # See: http://bugs.python.org/issue5285
        # See: http://trac.edgewall.org/ticket/8083
        self.access_key = access_key.encode('utf-8')
        self.secret_key = secret_key.encode('utf-8')
        self.bucket = self._option_get('s3_store_bucket')

        self.scheme = 's3'
        if self.s3_host.startswith('https://'):
            self.scheme = 's3+https'
            self.full_s3_host = self.s3_host
        elif self.s3_host.startswith('http://'):
            self.full_s3_host = self.s3_host
        else:  # Defaults http
            self.full_s3_host = 'http://' + self.s3_host

        buffer_dir = self.conf.glance_store.s3_store_object_buffer_dir
        self.s3_store_object_buffer_dir = buffer_dir

        _s3_obj_size = self._option_get('s3_store_large_object_size')
        self.s3_store_large_object_size = _s3_obj_size * units.Mi
        _s3_ck_size = self._option_get('s3_store_large_object_chunk_size')
        _s3_ck_min = DEFAULT_LARGE_OBJECT_MIN_CHUNK_SIZE
        if _s3_ck_size < _s3_ck_min:
            reason = (_("s3_store_large_object_chunk_size must be at "
                        "least %(_s3_ck_min)d MB. "
                        "You configured it as %(_s3_ck_size)d MB") %
                      {'_s3_ck_min': _s3_ck_min,
                       '_s3_ck_size': _s3_ck_size})
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="s3",
                                                   reason=reason)
        self.s3_store_large_object_chunk_size = _s3_ck_size * units.Mi
        self.s3_store_thread_pools = self._option_get('s3_store_thread_pools')
        if self.s3_store_thread_pools <= 0:
            reason = (_("s3_store_thread_pools must be a positive "
                        "integer. %s") % self.s3_store_thread_pools)
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="s3",
                                                   reason=reason)

    def _option_get(self, param):
        result = getattr(self.conf.glance_store, param)
        if not result:
            reason = ("Could not find %(param)s in configuration "
                      "options." % {'param': param})
            LOG.debug(reason)
            raise exceptions.BadStoreConfiguration(store_name="s3",
                                                   reason=reason)
        return result

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises `glance_store.exceptions.NotFound` if image does not exist
        """
        key = self._retrieve_key(location)
        cs = self.READ_CHUNKSIZE
        key.BufferSize = cs

        class ChunkedIndexable(glance_store.Indexable):
            def another(self):
                return (self.wrapped.fp.read(cs)
                        if self.wrapped.fp else None)

        return (ChunkedIndexable(ChunkedFile(key, cs), key.size), key.size)

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the image_size (or 0
        if unavailable)

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        try:
            key = self._retrieve_key(location)
            return key.size
        except Exception:
            return 0

    def _retrieve_key(self, location):
        loc = location.store_location
        s3host, s3port = netutils.parse_host_port(loc.s3serviceurl, 80)
        from boto.s3.connection import S3Connection

        uformat = self.conf.glance_store.s3_store_bucket_url_format
        calling_format = get_calling_format(s3_store_bucket_url_format=uformat)

        s3_conn = S3Connection(loc.accesskey, loc.secretkey,
                               host=s3host, port=s3port,
                               is_secure=(loc.scheme == 's3+https'),
                               calling_format=calling_format)
        bucket_obj = get_bucket(s3_conn, loc.bucket)

        key = get_key(bucket_obj, loc.key)

        msg = ("Retrieved image object from S3 using (s3_host=%(s3_host)s, "
               "access_key=%(accesskey)s, bucket=%(bucket)s, "
               "key=%(obj_name)s)" % ({'s3_host': loc.s3serviceurl,
                                       'accesskey': loc.accesskey,
                                       'bucket': loc.bucket,
                                       'obj_name': loc.key}))
        LOG.debug(msg)

        return key

    @capabilities.check
    def add(self, image_id, image_file, image_size, context=None):
        """
        Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes

        :retval tuple of URL in backing store, bytes written, checksum
                and a dictionary with storage system specific information
        :raises `glance_store.exceptions.Duplicate` if the image already
                existed

        S3 writes the image data using the scheme:
            s3://<ACCESS_KEY>:<SECRET_KEY>@<S3_URL>/<BUCKET>/<OBJ>
        where:
            <USER> = ``s3_store_user``
            <KEY> = ``s3_store_key``
            <S3_HOST> = ``s3_store_host``
            <BUCKET> = ``s3_store_bucket``
            <ID> = The id of the image being added
        """
        from boto.s3.connection import S3Connection

        loc = StoreLocation({'scheme': self.scheme,
                             'bucket': self.bucket,
                             'key': image_id,
                             's3serviceurl': self.full_s3_host,
                             'accesskey': self.access_key,
                             'secretkey': self.secret_key}, self.conf)

        s3host, s3port = netutils.parse_host_port(loc.s3serviceurl, 80)
        uformat = self.conf.glance_store.s3_store_bucket_url_format
        calling_format = get_calling_format(s3_store_bucket_url_format=uformat)

        s3_conn = S3Connection(loc.accesskey, loc.secretkey,
                               host=s3host, port=s3port,
                               is_secure=(loc.scheme == 's3+https'),
                               calling_format=calling_format)

        create_bucket_if_missing(self.conf, self.bucket, s3_conn)

        bucket_obj = get_bucket(s3_conn, self.bucket)
        obj_name = str(image_id)
        key = bucket_obj.get_key(obj_name)
        if key and key.exists():
            raise exceptions.Duplicate(message=_("S3 already has an image at "
                                                 "location %s") %
                                       self._sanitize(loc.get_uri()))

        msg = _("Adding image object to S3 using (s3_host=%(s3_host)s, "
                "access_key=%(access_key)s, bucket=%(bucket)s, "
                "key=%(obj_name)s)") % ({'s3_host': self.s3_host,
                                         'access_key': self.access_key,
                                         'bucket': self.bucket,
                                         'obj_name': obj_name})
        LOG.debug(msg)
        LOG.debug("Uploading an image file to S3 for %s" %
                  self._sanitize(loc.get_uri()))

        if image_size < self.s3_store_large_object_size:
            return self.add_singlepart(image_file, bucket_obj, obj_name, loc)
        else:
            return self.add_multipart(image_file, image_size, bucket_obj,
                                      obj_name, loc)

    def _sanitize(self, uri):
        return re.sub('//.*:.*@',
                      '//s3_store_secret_key:s3_store_access_key@',
                      uri)

    def add_singlepart(self, image_file, bucket_obj, obj_name, loc):
        """
        Stores an image file with a single part upload to S3 backend

        :param image_file: The image data to write, as a file-like object
        :param bucket_obj: S3 bucket object
        :param obj_name: The object name to be stored(image identifier)
        :loc: The Store Location Info
        """

        key = bucket_obj.new_key(obj_name)

        # We need to wrap image_file, which is a reference to the
        # webob.Request.body_file, with a seekable file-like object,
        # otherwise the call to set_contents_from_file() will die
        # with an error about Input object has no method 'seek'. We
        # might want to call webob.Request.make_body_seekable(), but
        # unfortunately, that method copies the entire image into
        # memory and results in LP Bug #818292 occurring. So, here
        # we write temporary file in as memory-efficient manner as
        # possible and then supply the temporary file to S3. We also
        # take this opportunity to calculate the image checksum while
        # writing the tempfile, so we don't need to call key.compute_md5()

        msg = ("Writing request body file to temporary file "
               "for %s") % self._sanitize(loc.get_uri())
        LOG.debug(msg)

        tmpdir = self.s3_store_object_buffer_dir
        temp_file = tempfile.NamedTemporaryFile(dir=tmpdir)
        checksum = hashlib.md5()
        for chunk in utils.chunkreadable(image_file, self.WRITE_CHUNKSIZE):
            checksum.update(chunk)
            temp_file.write(chunk)
        temp_file.flush()

        msg = ("Uploading temporary file to S3 "
               "for %s") % self._sanitize(loc.get_uri())
        LOG.debug(msg)

        # OK, now upload the data into the key
        key.set_contents_from_file(open(temp_file.name, 'rb'),
                                   replace=False)
        size = key.size
        checksum_hex = checksum.hexdigest()

        LOG.debug("Wrote %(size)d bytes to S3 key named %(obj_name)s "
                  "with checksum %(checksum_hex)s" %
                  {'size': size,
                   'obj_name': obj_name,
                   'checksum_hex': checksum_hex})

        return (loc.get_uri(), size, checksum_hex, {})

    def add_multipart(self, image_file, image_size, bucket_obj, obj_name, loc):
        """
        Stores an image file with a multi part upload to S3 backend

        :param image_file: The image data to write, as a file-like object
        :param bucket_obj: S3 bucket object
        :param obj_name: The object name to be stored(image identifier)
        :loc: The Store Location Info
        """

        checksum = hashlib.md5()
        pool_size = self.s3_store_thread_pools
        pool = eventlet.greenpool.GreenPool(size=pool_size)
        mpu = bucket_obj.initiate_multipart_upload(obj_name)
        LOG.debug("Multipart initiate key=%(obj_name)s, "
                  "UploadId=%(UploadId)s" %
                  {'obj_name': obj_name,
                   'UploadId': mpu.id})
        cstart = 0
        plist = []

        chunk_size = int(math.ceil(float(image_size) / MAX_PART_NUM))
        write_chunk_size = max(self.s3_store_large_object_chunk_size,
                               chunk_size)
        it = utils.chunkreadable(image_file, self.WRITE_CHUNKSIZE)
        buffered_chunk = ''
        while True:
            try:
                buffered_clen = len(buffered_chunk)
                if buffered_clen < write_chunk_size:
                    # keep reading data
                    read_chunk = next(it)
                    buffered_chunk += read_chunk
                    continue
                else:
                    write_chunk = buffered_chunk[:write_chunk_size]
                    remained_data = buffered_chunk[write_chunk_size:]
                    checksum.update(write_chunk)
                    fp = six.BytesIO(write_chunk)
                    fp.seek(0)
                    part = UploadPart(mpu, fp, cstart + 1, len(write_chunk))
                    pool.spawn_n(run_upload, part)
                    plist.append(part)
                    cstart += 1
                    buffered_chunk = remained_data
            except StopIteration:
                if len(buffered_chunk) > 0:
                    # Write the last chunk data
                    write_chunk = buffered_chunk
                    checksum.update(write_chunk)
                    fp = six.BytesIO(write_chunk)
                    fp.seek(0)
                    part = UploadPart(mpu, fp, cstart + 1, len(write_chunk))
                    pool.spawn_n(run_upload, part)
                    plist.append(part)
                break

        pedict = {}
        total_size = 0
        pool.waitall()

        for part in plist:
            pedict.update(part.etag)
            total_size += part.size

        success = True
        for part in plist:
            if not part.success:
                success = False

        if success:
            # Complete
            xml = get_mpu_xml(pedict)
            bucket_obj.complete_multipart_upload(obj_name,
                                                 mpu.id,
                                                 xml)
            checksum_hex = checksum.hexdigest()
            LOG.info(_LI("Multipart complete key=%(obj_name)s "
                         "UploadId=%(UploadId)s "
                         "Wrote %(total_size)d bytes to S3 key"
                         "named %(obj_name)s "
                         "with checksum %(checksum_hex)s") %
                     {'obj_name': obj_name,
                      'UploadId': mpu.id,
                      'total_size': total_size,
                      'checksum_hex': checksum_hex})
            return (loc.get_uri(), total_size, checksum_hex, {})
        else:
            # Abort
            bucket_obj.cancel_multipart_upload(obj_name, mpu.id)
            LOG.error(_LE("Some parts failed to upload to S3. "
                          "Aborted the object key=%(obj_name)s") %
                      {'obj_name': obj_name})
            msg = (_("Failed to add image object to S3. "
                     "key=%(obj_name)s") % {'obj_name': obj_name})
            raise glance_store.BackendException(msg)

    @capabilities.check
    def delete(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete

        :location `glance_store.location.Location` object, supplied
                  from glance_store.location.get_location_from_uri()

        :raises NotFound if image does not exist
        """
        loc = location.store_location
        s3host, s3port = netutils.parse_host_port(loc.s3serviceurl, 80)
        from boto.s3.connection import S3Connection

        uformat = self.conf.glance_store.s3_store_bucket_url_format
        calling_format = get_calling_format(s3_store_bucket_url_format=uformat)

        s3_conn = S3Connection(loc.accesskey, loc.secretkey,
                               host=s3host, port=s3port,
                               is_secure=(loc.scheme == 's3+https'),
                               calling_format=calling_format)
        bucket_obj = get_bucket(s3_conn, loc.bucket)

        # Close the key when we're through.
        key = get_key(bucket_obj, loc.key)

        msg = _("Deleting image object from S3 using (s3_host=%(s3_host)s, "
                "access_key=%(accesskey)s, bucket=%(bucket)s, "
                "key=%(obj_name)s)") % ({'s3_host': loc.s3serviceurl,
                                         'accesskey': loc.accesskey,
                                         'bucket': loc.bucket,
                                         'obj_name': loc.key})
        LOG.debug(msg)

        return key.delete()


def get_bucket(conn, bucket_id):
    """
    Get a bucket from an s3 connection

    :param conn: The ``boto.s3.connection.S3Connection``
    :param bucket_id: ID of the bucket to fetch
    :raises ``glance_store.exceptions.NotFound`` if bucket is not found.
    """

    bucket = conn.get_bucket(bucket_id)
    if not bucket:
        msg = _("Could not find bucket with ID %s") % bucket_id
        LOG.debug(msg)
        raise exceptions.NotFound(msg)

    return bucket


def get_s3_location(s3_host):
    from boto.s3.connection import Location
    locations = {
        's3.amazonaws.com': Location.DEFAULT,
        's3-eu-west-1.amazonaws.com': Location.EU,
        's3-us-west-1.amazonaws.com': Location.USWest,
        's3-ap-southeast-1.amazonaws.com': Location.APSoutheast,
        's3-ap-northeast-1.amazonaws.com': Location.APNortheast,
    }
    # strip off scheme and port if present
    key = re.sub('^(https?://)?(?P<host>[^:]+)(:[0-9]+)?$',
                 '\g<host>',
                 s3_host)
    return locations.get(key, Location.DEFAULT)


def create_bucket_if_missing(conf, bucket, s3_conn):
    """
    Creates a missing bucket in S3 if the
    ``s3_store_create_bucket_on_put`` option is set.

    :param conf: Configuration
    :param bucket: Name of bucket to create
    :param s3_conn: Connection to S3
    """
    from boto.exception import S3ResponseError
    try:
        s3_conn.get_bucket(bucket)
    except S3ResponseError as e:
        if e.status == httplib.NOT_FOUND:
            if conf.glance_store.s3_store_create_bucket_on_put:
                host = conf.glance_store.s3_store_host
                location = get_s3_location(host)
                try:
                    s3_conn.create_bucket(bucket, location=location)
                except S3ResponseError as e:
                    msg = (_("Failed to add bucket to S3.\n"
                             "Got error from S3: %s.") %
                           utils.exception_to_str(e))
                    raise glance_store.BackendException(msg)
            else:
                msg = (_("The bucket %(bucket)s does not exist in "
                         "S3. Please set the "
                         "s3_store_create_bucket_on_put option "
                         "to add bucket to S3 automatically.")
                       % {'bucket': bucket})
                raise glance_store.BackendException(msg)


def get_key(bucket, obj):
    """
    Get a key from a bucket

    :param bucket: The ``boto.s3.Bucket``
    :param obj: Object to get the key for
    :raises ``glance_store.exceptions.NotFound`` if key is not found.
    """

    key = bucket.get_key(obj)
    if not key or not key.exists():
        msg = (_("Could not find key %(obj)s in bucket %(bucket)s") %
               {'obj': obj, 'bucket': bucket})
        LOG.debug(msg)
        raise exceptions.NotFound(message=msg)
    return key


def get_calling_format(bucket_format=None,
                       s3_store_bucket_url_format='subdomain'):

    import boto.s3.connection
    if bucket_format is None:
        bucket_format = s3_store_bucket_url_format
    if bucket_format.lower() == 'path':
        return boto.s3.connection.OrdinaryCallingFormat()
    else:
        return boto.s3.connection.SubdomainCallingFormat()


def get_mpu_xml(pedict):
    xml = '<CompleteMultipartUpload>\n'
    for pnum, etag in pedict.iteritems():
        xml += '  <Part>\n'
        xml += '    <PartNumber>%d</PartNumber>\n' % pnum
        xml += '    <ETag>%s</ETag>\n' % etag
        xml += '  </Part>\n'
    xml += '</CompleteMultipartUpload>'
    return xml
