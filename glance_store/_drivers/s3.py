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

from concurrent import futures
import io
import logging
import math
import re
import urllib

try:
    from boto3 import session as boto_session
    from botocore import client as boto_client
    from botocore import exceptions as boto_exceptions
    from botocore import utils as boto_utils
except ImportError:
    boto_session = None
    boto_client = None
    boto_exceptions = None
    boto_utils = None

from oslo_config import cfg
from oslo_utils import encodeutils
from oslo_utils import units

import glance_store
from glance_store import capabilities
from glance_store.common import utils
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _
import glance_store.location

LOG = logging.getLogger(__name__)

DEFAULT_LARGE_OBJECT_SIZE = 100          # 100M
DEFAULT_LARGE_OBJECT_CHUNK_SIZE = 10     # 10M
DEFAULT_LARGE_OBJECT_MIN_CHUNK_SIZE = 5  # 5M
DEFAULT_THREAD_POOLS = 10                # 10 pools
MAX_PART_NUM = 10000                     # 10000 upload parts

_S3_OPTS = [
    cfg.StrOpt('s3_store_host',
               help="""
The host where the S3 server is listening.

This configuration option sets the host of the S3 or S3 compatible storage
Server. This option is required when using the S3 storage backend.
The host can contain a DNS name (e.g. s3.amazonaws.com, my-object-storage.com)
or an IP address (127.0.0.1).

Possible values:
    * A valid DNS name
    * A valid IPv4 address

Related Options:
    * s3_store_access_key
    * s3_store_secret_key

"""),
    cfg.StrOpt('s3_store_region_name',
               default='',
               help="""
The S3 region name.

This parameter will set the region_name used by boto.
If this parameter is not set, we we will try to compute it from the
s3_store_host.

Possible values:
    * A valid region name

Related Options:
    * s3_store_host

"""),
    cfg.StrOpt('s3_store_access_key',
               secret=True,
               help="""
The S3 query token access key.

This configuration option takes the access key for authenticating with the
Amazon S3 or S3 compatible storage server. This option is required when using
the S3 storage backend.

Possible values:
    * Any string value that is the access key for a user with appropriate
      privileges

Related Options:
    * s3_store_host
    * s3_store_secret_key

"""),
    cfg.StrOpt('s3_store_secret_key',
               secret=True,
               help="""
The S3 query token secret key.

This configuration option takes the secret key for authenticating with the
Amazon S3 or S3 compatible storage server. This option is required when using
the S3 storage backend.

Possible values:
    * Any string value that is a secret key corresponding to the access key
      specified using the ``s3_store_host`` option

Related Options:
    * s3_store_host
    * s3_store_access_key

"""),
    cfg.StrOpt('s3_store_bucket',
               help="""
The S3 bucket to be used to store the Glance data.

This configuration option specifies where the glance images will be stored
in the S3. If ``s3_store_create_bucket_on_put`` is set to true, it will be
created automatically even if the bucket does not exist.

Possible values:
    * Any string value

Related Options:
    * s3_store_create_bucket_on_put
    * s3_store_bucket_url_format

"""),
    cfg.BoolOpt('s3_store_create_bucket_on_put',
                default=False,
                help="""
Determine whether S3 should create a new bucket.

This configuration option takes boolean value to indicate whether Glance should
create a new bucket to S3 if it does not exist.

Possible values:
    * Any Boolean value

Related Options:
    * None

"""),
    cfg.StrOpt('s3_store_bucket_url_format',
               default='auto',
               help="""
The S3 calling format used to determine the object.

This configuration option takes access model that is used to specify the
address of an object in an S3 bucket.

NOTE:
In ``path``-style, the endpoint for the object looks like
'https://s3.amazonaws.com/bucket/example.img'.
And in ``virtual``-style, the endpoint for the object looks like
'https://bucket.s3.amazonaws.com/example.img'.
If you do not follow the DNS naming convention in the bucket name, you can
get objects in the path style, but not in the virtual style.

Possible values:
    * Any string value of ``auto``, ``virtual``, or ``path``

Related Options:
    * s3_store_bucket

"""),
    cfg.IntOpt('s3_store_large_object_size',
               default=DEFAULT_LARGE_OBJECT_SIZE,
               help="""
What size, in MB, should S3 start chunking image files and do a multipart
upload in S3.

This configuration option takes a threshold in MB to determine whether to
upload the image to S3 as is or to split it (Multipart Upload).

Note: You can only split up to 10,000 images.

Possible values:
    * Any positive integer value

Related Options:
    * s3_store_large_object_chunk_size
    * s3_store_thread_pools

"""),
    cfg.IntOpt('s3_store_large_object_chunk_size',
               default=DEFAULT_LARGE_OBJECT_CHUNK_SIZE,
               help="""
What multipart upload part size, in MB, should S3 use when uploading parts.

This configuration option takes the image split size in MB for Multipart
Upload.

Note: You can only split up to 10,000 images.

Possible values:
    * Any positive integer value (must be greater than or equal to 5M)

Related Options:
    * s3_store_large_object_size
    * s3_store_thread_pools

"""),
    cfg.IntOpt('s3_store_thread_pools',
               default=DEFAULT_THREAD_POOLS,
               help="""
The number of thread pools to perform a multipart upload in S3.

This configuration option takes the number of thread pools when performing a
Multipart Upload.

Possible values:
    * Any positive integer value

Related Options:
    * s3_store_large_object_size
    * s3_store_large_object_chunk_size

"""),
    cfg.StrOpt('s3_store_cacert',
               default='',
               help="""
The path to the CA cert bundle to use. The default value (an empty string)
forces the use of the default CA cert bundle used by botocore.

Possible values:
    * A path to the CA cert bundle to use
    * An empty string to use the default CA cert bundle used by botocore

"""),
]


class UploadPart(object):
    """The class for the upload part."""
    def __init__(self, mpu, fp, partnum, chunks):
        self.mpu = mpu
        self.partnum = partnum
        self.fp = fp
        self.size = 0
        self.chunks = chunks
        self.etag = {}
        self.success = True


def run_upload(s3_client, bucket, key, part):
    """Upload the upload part into S3 and set returned etag and size to its
    part info.

    :param s3_client: An object with credentials to connect to S3
    :param bucket: The S3 bucket name
    :param key: The object name to be stored (image identifier)
    :param part: UploadPart object which used during multipart upload
    """
    pnum = part.partnum
    bsize = part.chunks
    upload_id = part.mpu['UploadId']
    LOG.debug("Uploading upload part in S3 partnum=%(pnum)d, "
              "size=%(bsize)d, key=%(key)s, UploadId=%(UploadId)s",
              {'pnum': pnum, 'bsize': bsize, 'key': key,
               'UploadId': upload_id})

    try:
        key = s3_client.upload_part(Body=part.fp,
                                    Bucket=bucket,
                                    ContentLength=bsize,
                                    Key=key,
                                    PartNumber=pnum,
                                    UploadId=upload_id)
        part.etag[part.partnum] = key['ETag']
        part.size = bsize
    except boto_exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        LOG.warning("Failed to upload part in S3 partnum=%(pnum)d, "
                    "size=%(bsize)d, error code=%(error_code)d, "
                    "error message=%(error_message)s",
                    {'pnum': pnum, 'bsize': bsize, 'error_code': error_code,
                     'error_message': error_message})
        part.success = False
    finally:
        part.fp.close()


class StoreLocation(glance_store.location.StoreLocation):
    """Class describing an S3 URI.

    An S3 URI can look like any of the following:

        s3://accesskey:secretkey@s3.amazonaws.com/bucket/key-id
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
            s3_host = s3_host[len('https://'):].strip('/')
        elif s3_host.startswith('http://'):
            s3_host = s3_host[len('http://'):].strip('/')
        self.s3serviceurl = s3_host.strip('/')

    def _get_credstring(self):
        if self.accesskey:
            return '%s:%s@' % (self.accesskey, self.secretkey)
        return ''

    def get_uri(self):
        return "%s://%s%s/%s/%s" % (self.scheme, self._get_credstring(),
                                    self.s3serviceurl, self.bucket, self.key)

    def parse_uri(self, uri):
        """Parse URLs.

        Note that an Amazon AWS secret key can contain the forward slash,
        which is entirely retarded, and breaks urlparse miserably.
        This function works around that issue.
        """
        # Make sure that URIs that contain multiple schemes, such as:
        # s3://accesskey:secretkey@https://s3.amazonaws.com/bucket/key-id
        # are immediately rejected.
        if uri.count('://') != 1:
            reason = ("URI cannot contain more than one occurrence "
                      "of a scheme. If you have specified a URI like "
                      "s3://accesskey:secretkey@"
                      "https://s3.amazonaws.com/bucket/key-id"
                      ", you need to change it to use the "
                      "s3+https:// scheme, like so: "
                      "s3+https://accesskey:secretkey@"
                      "s3.amazonaws.com/bucket/key-id")
            LOG.info("Invalid store uri: %s", reason)
            raise exceptions.BadStoreUri(uri=uri)

        pieces = urllib.parse.urlparse(uri)
        self.validate_schemas(uri, valid_schemas=(
            's3://', 's3+http://', 's3+https://'))
        self.scheme = pieces.scheme
        path = pieces.path.strip('/')
        netloc = pieces.netloc.strip('/')
        entire_path = (netloc + '/' + path).strip('/')

        if '@' in uri:
            creds, path = entire_path.split('@')
            cred_parts = creds.split(':')

            try:
                self.accesskey = cred_parts[0]
                self.secretkey = cred_parts[1]
            except IndexError:
                LOG.error("Badly formed S3 credentials")
                raise exceptions.BadStoreUri(uri=uri)
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
                LOG.error("Badly formed S3 URI. Missing s3 service URL.")
                raise exceptions.BadStoreUri(uri=uri)
        except IndexError:
            LOG.error("Badly formed S3 URI")
            raise exceptions.BadStoreUri(uri=uri)


class Store(glance_store.driver.Store):
    """An implementation of the s3 adapter."""

    _CAPABILITIES = capabilities.BitMasks.RW_ACCESS
    OPTIONS = _S3_OPTS
    EXAMPLE_URL = "s3://<ACCESS_KEY>:<SECRET_KEY>@<S3_URL>/<BUCKET>/<OBJ>"

    READ_CHUNKSIZE = 64 * units.Ki
    WRITE_CHUNKSIZE = 5 * units.Mi

    @staticmethod
    def get_schemes():
        return 's3', 's3+http', 's3+https'

    def configure_add(self):
        """
        Configure the Store to use the stored configuration options
        Any store that needs special configuration should implement
        this method. If the store was not able to successfully configure
        itself, it should raise `exceptions.BadStoreConfiguration`
        """
        if boto_session is None:
            reason = _("boto3 or botocore is not available.")
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="s3",
                                                   reason=reason)

        self.s3_host = self._option_get('s3_store_host')
        self.region_name = self._option_get('s3_store_region_name')
        self.access_key = self._option_get('s3_store_access_key')
        self.secret_key = self._option_get('s3_store_secret_key')
        self.bucket = self._option_get('s3_store_bucket')

        self.scheme = 's3'
        if self.s3_host.startswith('https://'):
            self.scheme = 's3+https'
            self.full_s3_host = self.s3_host
        elif self.s3_host.startswith('http://'):
            self.full_s3_host = self.s3_host
        else:  # Defaults http
            self.full_s3_host = 'http://' + self.s3_host

        _s3_obj_size = self._option_get('s3_store_large_object_size')
        self.s3_store_large_object_size = _s3_obj_size * units.Mi
        _s3_ck_size = self._option_get('s3_store_large_object_chunk_size')
        _s3_ck_min = DEFAULT_LARGE_OBJECT_MIN_CHUNK_SIZE
        if _s3_ck_size < _s3_ck_min:
            reason = _("s3_store_large_object_chunk_size must be at "
                       "least %d MB.") % _s3_ck_min
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="s3",
                                                   reason=reason)
        self.s3_store_large_object_chunk_size = _s3_ck_size * units.Mi

        self.s3_store_thread_pools = self._option_get('s3_store_thread_pools')
        if self.s3_store_thread_pools <= 0:
            reason = _("s3_store_thread_pools must be a positive "
                       "integer. %s") % self.s3_store_thread_pools
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="s3",
                                                   reason=reason)

        if self.backend_group:
            self._set_url_prefix()

    def _set_url_prefix(self):
        s3_host = self.s3_host
        if s3_host.startswith('http://'):
            s3_host = s3_host[len('http://'):]
        elif s3_host.startswith('https://'):
            s3_host = s3_host[len('https://'):]

        self._url_prefix = "%s://%s:%s@%s/%s" % (self.scheme, self.access_key,
                                                 self.secret_key, s3_host,
                                                 self.bucket)

    def _option_get(self, param):
        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store

        result = getattr(store_conf, param)
        if not result:
            if param == 's3_store_create_bucket_on_put':
                return result
            if param == 's3_store_region_name':
                return result
            if param == 's3_store_cacert':
                return result
            reason = _("Could not find %s in configuration options.") % param
            LOG.error(reason)
            raise exceptions.BadStoreConfiguration(store_name="s3",
                                                   reason=reason)
        return result

    def _create_s3_client(self, loc):
        """Create a client object to use when connecting to S3.

        :param loc: `glance_store.location.Location` object, supplied
                    from glance_store.location.get_location_from_uri()
        :returns: An object with credentials to connect to S3
        """
        s3_host = self._option_get('s3_store_host')
        url_format = self._option_get('s3_store_bucket_url_format')
        calling_format = {'addressing_style': url_format}

        session = boto_session.Session(aws_access_key_id=loc.accesskey,
                                       aws_secret_access_key=loc.secretkey)
        config = boto_client.Config(s3=calling_format)
        location = get_s3_location(s3_host)

        bucket_name = loc.bucket
        if (url_format == 'virtual' and
                not boto_utils.check_dns_name(bucket_name)):
            raise boto_exceptions.InvalidDNSNameError(bucket_name=bucket_name)

        region_name, endpoint_url = None, None
        if self.region_name:
            region_name = self.region_name
            endpoint_url = s3_host
        elif location:
            region_name = location
        else:
            endpoint_url = s3_host

        store_cacert = self._option_get('s3_store_cacert')
        return session.client(
            service_name='s3',
            endpoint_url=endpoint_url,
            region_name=region_name,
            use_ssl=(loc.scheme == 's3+https'),
            verify=None if store_cacert == '' else store_cacert,
            config=config)

    def _operation_set(self, loc):
        """Objects and variables frequently used when operating S3 are
        returned together.

        :param loc: `glance_store.location.Location` object, supplied
                     from glance_store.location.get_location_from_uri()
        "returns: tuple of: (1) S3 client object, (2) Bucket name,
                  (3) Image Object name
        """
        return self._create_s3_client(loc), loc.bucket, loc.key

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location: `glance_store.location.Location` object, supplied
                         from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        """
        loc = location.store_location
        s3_client, bucket, key = self._operation_set(loc)

        if not self._object_exists(s3_client, bucket, key):
            LOG.warning("Could not find key %(key)s in "
                        "bucket %(bucket)s", {'key': key, 'bucket': bucket})
            raise exceptions.NotFound(image=key)

        key = s3_client.get_object(Bucket=bucket, Key=key)

        LOG.debug("Retrieved image object from S3 using s3_host=%(s3_host)s, "
                  "bucket=%(bucket)s key=%(key)s)",
                  {'s3_host': loc.s3serviceurl, 'bucket': bucket, 'key': key})

        cs = self.READ_CHUNKSIZE

        class ResponseIndexable(glance_store.Indexable):
            def another(self):
                try:
                    return next(self.wrapped)
                except StopIteration:
                    return b''

        return (ResponseIndexable(utils.chunkiter(key['Body'], cs),
                                  key['ContentLength']), key['ContentLength'])

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file and returns the image size

        :param location: `glance_store.location.Location` object, supplied
                         from glance_store.location.get_location_from_uri()
        :raises: `glance_store.exceptions.NotFound` if image does not exist
        :rtype: int
        """
        loc = location.store_location
        s3_client, bucket, key = self._operation_set(loc)

        if not self._object_exists(s3_client, bucket, key):
            LOG.warning("Could not find key %(key)s in "
                        "bucket %(bucket)s", {'key': key, 'bucket': bucket})
            raise exceptions.NotFound(image=key)

        key = s3_client.head_object(Bucket=bucket, Key=key)
        return key['ContentLength']

    @capabilities.check
    def add(self, image_id, image_file, image_size, hashing_algo, context=None,
            verifier=None):
        """
        Stores an image file with supplied identifier to the backend
        storage system and returns a tuple containing information
        about the stored image.

        :param image_id: The opaque image identifier
        :param image_file: The image data to write, as a file-like object
        :param image_size: The size of the image data to write, in bytes
        :param hashing_algo: A hashlib algorithm identifier (string)
        :param context: A context object
        :param verifier: An object used to verify signatures for images

        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        :raises: `glance_store.exceptions.Duplicate` if the image already
                 exists
        """
        loc = StoreLocation(store_specs={'scheme': self.scheme,
                                         'bucket': self.bucket,
                                         'key': image_id,
                                         's3serviceurl': self.full_s3_host,
                                         'accesskey': self.access_key,
                                         'secretkey': self.secret_key},
                            conf=self.conf,
                            backend_group=self.backend_group)

        s3_client, bucket, key = self._operation_set(loc)

        if not self._bucket_exists(s3_client, bucket):
            if self._option_get('s3_store_create_bucket_on_put'):
                self._create_bucket(s3_client,
                                    self._option_get('s3_store_host'),
                                    bucket,
                                    self._option_get('s3_store_region_name'))
            else:
                msg = (_("The bucket %s does not exist in "
                         "S3. Please set the "
                         "s3_store_create_bucket_on_put option "
                         "to add bucket to S3 automatically.") % bucket)
                raise glance_store.BackendException(msg)

        LOG.debug("Adding image object to S3 using (s3_host=%(s3_host)s, "
                  "bucket=%(bucket)s, key=%(key)s)",
                  {'s3_host': self.s3_host, 'bucket': bucket, 'key': key})

        if not self._object_exists(s3_client, bucket, key):
            if image_size < self.s3_store_large_object_size:
                return self._add_singlepart(s3_client=s3_client,
                                            image_file=image_file,
                                            bucket=bucket,
                                            key=key,
                                            loc=loc,
                                            hashing_algo=hashing_algo,
                                            verifier=verifier)

            return self._add_multipart(s3_client=s3_client,
                                       image_file=image_file,
                                       image_size=image_size,
                                       bucket=bucket,
                                       key=key,
                                       loc=loc,
                                       hashing_algo=hashing_algo,
                                       verifier=verifier)
        LOG.warning("S3 already has an image with bucket ID %(bucket)s, "
                    "key %(key)s", {'bucket': bucket, 'key': key})
        raise exceptions.Duplicate(image=key)

    def _add_singlepart(self, s3_client, image_file, bucket, key, loc,
                        hashing_algo, verifier):
        """Stores an image file with a single part upload to S3 backend.

        :param s3_client: An object with credentials to connect to S3
        :param image_file: The image data to write, as a file-like object
        :param bucket: S3 bucket name
        :param key: The object name to be stored (image identifier)
        :param loc: `glance_store.location.Location` object, supplied
                    from glance_store.location.get_location_from_uri()
        :param hashing_algo: A hashlib algorithm identifier (string)
        :param verifier: An object used to verify signatures for images
        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        """
        os_hash_value = utils.get_hasher(hashing_algo, False)
        checksum = utils.get_hasher('md5', False)
        image_data = b''
        image_size = 0
        for chunk in utils.chunkreadable(image_file, self.WRITE_CHUNKSIZE):
            image_data += chunk
            image_size += len(chunk)
            os_hash_value.update(chunk)
            checksum.update(chunk)
            if verifier:
                verifier.update(chunk)

        s3_client.put_object(Body=image_data,
                             Bucket=bucket,
                             Key=key)
        hash_hex = os_hash_value.hexdigest()
        checksum_hex = checksum.hexdigest()

        # Add store backend information to location metadata
        metadata = {}
        if self.backend_group:
            metadata['store'] = self.backend_group

        LOG.debug("Wrote %(size)d bytes to S3 key named %(key)s "
                  "with checksum %(checksum)s",
                  {'size': image_size, 'key': key, 'checksum': checksum_hex})

        return loc.get_uri(), image_size, checksum_hex, hash_hex, metadata

    def _add_multipart(self, s3_client, image_file, image_size, bucket,
                       key, loc, hashing_algo, verifier):
        """Stores an image file with a multi part upload to S3 backend.

        :param s3_client: An object with credentials to connect to S3
        :param image_file: The image data to write, as a file-like object
        :param bucket: S3 bucket name
        :param key: The object name to be stored (image identifier)
        :param loc: `glance_store.location.Location` object, supplied
                    from glance_store.location.get_location_from_uri()
        :param hashing_algo: A hashlib algorithm identifier (string)
        :param verifier: An object used to verify signatures for images
        :returns: tuple of: (1) URL in backing store, (2) bytes written,
                  (3) checksum, (4) multihash value, and (5) a dictionary
                  with storage system specific information
        """
        os_hash_value = utils.get_hasher(hashing_algo, False)
        checksum = utils.get_hasher('md5', False)
        pool_size = self.s3_store_thread_pools
        # Replace eventlet.GreenPool with ThreadPoolExecutor
        with futures.ThreadPoolExecutor(
                max_workers=pool_size) as executor:
            # Create a list to store the futures
            futures_list = []
            mpu = s3_client.create_multipart_upload(Bucket=bucket, Key=key)
            upload_id = mpu['UploadId']
            LOG.debug("Multipart initiate key=%(key)s, UploadId=%(UploadId)s",
                      {'key': key, 'UploadId': upload_id})
            cstart = 0
            plist = []

            chunk_size = int(math.ceil(float(image_size) / MAX_PART_NUM))
            write_chunk_size = max(self.s3_store_large_object_chunk_size,
                                   chunk_size)
            it = utils.chunkreadable(image_file, self.WRITE_CHUNKSIZE)
            buffered_chunk = b''
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
                        os_hash_value.update(write_chunk)
                        checksum.update(write_chunk)
                        if verifier:
                            verifier.update(write_chunk)
                        fp = io.BytesIO(write_chunk)
                        fp.seek(0)
                        part = UploadPart(
                            mpu, fp, cstart + 1, len(write_chunk))
                        # Spawn thread to upload part
                        futures_list.append(executor.submit(
                            run_upload, s3_client, bucket, key, part))
                        plist.append(part)
                        cstart += 1
                        buffered_chunk = remained_data
                except StopIteration:
                    if len(buffered_chunk) > 0:
                        # Write the last chunk data
                        write_chunk = buffered_chunk
                        os_hash_value.update(write_chunk)
                        checksum.update(write_chunk)
                        if verifier:
                            verifier.update(write_chunk)
                        fp = io.BytesIO(write_chunk)
                        fp.seek(0)
                        part = UploadPart(
                            mpu, fp, cstart + 1, len(write_chunk))
                        futures_list.append(executor.submit(
                            run_upload, s3_client, bucket, key, part))
                        plist.append(part)
                    break

        # Wait for all uploads to finish
        futures.wait(futures_list)

        # Check success status
        success = all(p.success for p in plist)
        total_size = sum(p.size for p in plist)

        if success:
            # Complete
            pedict = {p.partnum: p.etag[p.partnum] for p in plist}
            mpu_list = self._get_mpu_list(pedict)
            s3_client.complete_multipart_upload(Bucket=bucket,
                                                Key=key,
                                                MultipartUpload=mpu_list,
                                                UploadId=upload_id)
            hash_hex = os_hash_value.hexdigest()
            checksum_hex = checksum.hexdigest()

            # Add store backend information to location metadata
            metadata = {}
            if self.backend_group:
                metadata['store'] = self.backend_group

            LOG.info("Multipart complete key=%(key)s "
                     "UploadId=%(UploadId)s "
                     "Wrote %(total_size)d bytes to S3 key "
                     "named %(key)s "
                     "with checksum %(checksum)s",
                     {'key': key, 'UploadId': upload_id,
                      'total_size': total_size, 'checksum': checksum_hex})
            return loc.get_uri(), total_size, checksum_hex, hash_hex, metadata

        # Abort
        s3_client.abort_multipart_upload(Bucket=bucket, Key=key,
                                         UploadId=upload_id)
        LOG.error("Some parts failed to upload to S3. "
                  "Aborted the key=%s", key)
        msg = _("Failed to add image object to S3. key=%s") % key
        raise glance_store.BackendException(msg)

    @capabilities.check
    def delete(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file to delete.

        :param location: `glance_store.location.Location` object, supplied
                         from glance_store.location.get_location_from_uri()

        :raises: NotFound if image does not exist;
                InUseByStore if image is in use or snapshot unprotect failed
        """
        loc = location.store_location
        s3_client, bucket, key = self._operation_set(loc)

        if not self._object_exists(s3_client, bucket, key):
            LOG.warning("Could not find key %(key)s in bucket %(bucket)s",
                        {'key': key, 'bucket': bucket})
            raise exceptions.NotFound(image=key)

        LOG.debug("Deleting image object from S3 using s3_host=%(s3_host)s, "
                  "bucket=%(bucket)s, key=%(key)s)",
                  {'s3_host': loc.s3serviceurl, 'bucket': bucket, 'key': key})

        return s3_client.delete_object(Bucket=bucket, Key=key)

    @staticmethod
    def _bucket_exists(s3_client, bucket):
        """Check whether bucket exists in the S3.

        :param s3_client: An object with credentials to connect to S3
        :param bucket: S3 bucket name
        :returns: boolean value; If the value is true, the bucket is exist
                  if false, it is not.
        :raises: BadStoreConfiguration if cannot connect to S3 successfully
        """
        try:
            s3_client.head_bucket(Bucket=bucket)
        except boto_exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                return False
            msg = ("Failed to get bucket info: %s" %
                   encodeutils.exception_to_unicode(e))
            LOG.error(msg)
            raise glance_store.BadStoreConfiguration(store_name='s3',
                                                     reason=msg)
        else:
            return True

    @staticmethod
    def _object_exists(s3_client, bucket, key):
        """Check whether object exists in the specific bucket of S3.

        :param s3_client: An object with credentials to connect to S3
        :param bucket: S3 bucket name
        :param key: The image object name
        :returns: boolean value; If the value is true, the object is exist
                  if false, it is not.
        :raises: BadStoreConfiguration if cannot connect to S3 successfully
        """
        try:
            s3_client.head_object(Bucket=bucket, Key=key)
        except boto_exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                return False
            msg = ("Failed to get object info: %s" %
                   encodeutils.exception_to_unicode(e))
            LOG.error(msg)
            raise glance_store.BadStoreConfiguration(store_name='s3',
                                                     reason=msg)
        else:
            return True

    @staticmethod
    def _create_bucket(s3_client, s3_host, bucket, region_name=None):
        """Create bucket into the S3.

        :param s3_client: An object with credentials to connect to S3
        :param s3_host: S3 endpoint url
        :param bucket: S3 bucket name
        :param region_name: An optional region_name. If not provided, will try
               to compute it from s3_host
        :raises: BadStoreConfiguration if cannot connect to S3 successfully
        """
        if region_name:
            region = region_name
        else:
            region = get_s3_location(s3_host)
        try:
            s3_client.create_bucket(
                Bucket=bucket,
            ) if region == '' else s3_client.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={
                    'LocationConstraint': region
                }
            )
        except boto_exceptions.ClientError as e:
            msg = ("Failed to add bucket to S3: %s" %
                   encodeutils.exception_to_unicode(e))
            LOG.error(msg)
            raise glance_store.BadStoreConfiguration(store_name='s3',
                                                     reason=msg)

    @staticmethod
    def _get_mpu_list(pedict):
        """Convert an object type and struct for use in
        boto3.client('s3').complete_multipart_upload.

        :param pedict: dict which containing UploadPart.etag
        :returns: list with pedict converted properly
        """
        return {
            'Parts': [
                {
                    'PartNumber': pnum,
                    'ETag': etag
                } for pnum, etag in pedict.items()
            ]
        }


def get_s3_location(s3_host):
    """Get S3 region information from ``s3_store_host``.

    :param s3_host: S3 endpoint url
    :returns: string value; region information which user wants to use on
              Amazon S3, and if user wants to use S3 compatible storage,
              returns ''
    """
    # NOTE(arnaud): maybe get rid of hardcoded amazon stuff here?
    locations = {
        's3.amazonaws.com': '',
        's3-us-east-1.amazonaws.com': 'us-east-1',
        's3-us-east-2.amazonaws.com': 'us-east-2',
        's3-us-west-1.amazonaws.com': 'us-west-1',
        's3-us-west-2.amazonaws.com': 'us-west-2',
        's3-ap-east-1.amazonaws.com': 'ap-east-1',
        's3-ap-south-1.amazonaws.com': 'ap-south-1',
        's3-ap-northeast-1.amazonaws.com': 'ap-northeast-1',
        's3-ap-northeast-2.amazonaws.com': 'ap-northeast-2',
        's3-ap-northeast-3.amazonaws.com': 'ap-northeast-3',
        's3-ap-southeast-1.amazonaws.com': 'ap-southeast-1',
        's3-ap-southeast-2.amazonaws.com': 'ap-southeast-2',
        's3-ca-central-1.amazonaws.com': 'ca-central-1',
        's3-cn-north-1.amazonaws.com.cn': 'cn-north-1',
        's3-cn-northwest-1.amazonaws.com.cn': 'cn-northwest-1',
        's3-eu-central-1.amazonaws.com': 'eu-central-1',
        's3-eu-west-1.amazonaws.com': 'eu-west-1',
        's3-eu-west-2.amazonaws.com': 'eu-west-2',
        's3-eu-west-3.amazonaws.com': 'eu-west-3',
        's3-eu-north-1.amazonaws.com': 'eu-north-1',
        's3-sa-east-1.amazonaws.com': 'sa-east-1'
    }
    # strip off scheme and port if present
    key = re.sub(r'^(https?://)?(?P<host>[^:]+[^/])(:[0-9]+)?/?$',
                 r'\g<host>',
                 s3_host)
    return locations.get(key, '')
