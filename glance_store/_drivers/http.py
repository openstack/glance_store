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

import logging

from oslo_config import cfg
from oslo_utils import encodeutils

from six.moves import urllib

import requests

from glance_store import capabilities
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _, _LI
import glance_store.location

LOG = logging.getLogger(__name__)


MAX_REDIRECTS = 5

_HTTP_OPTS = [
    cfg.StrOpt('https_ca_certificates_file',
               help="""
Path to the CA bundle file.

This configuration option enables the operator to use a custom
Certificate Authority file to verify the remote server certificate. If
this option is set, the ``https_insecure`` option will be ignored and
the CA file specified will be used to authenticate the server
certificate and establish a secure connection to the server.

Possible values:
    * A valid path to a CA file

Related options:
    * https_insecure

"""),
    cfg.BoolOpt('https_insecure',
                default=True,
                help="""
Set verification of the remote server certificate.

This configuration option takes in a boolean value to determine
whether or not to verify the remote server certificate. If set to
True, the remote server certificate is not verified. If the option is
set to False, then the default CA truststore is used for verification.

This option is ignored if ``https_ca_certificates_file`` is set.
The remote server certificate will then be verified using the file
specified using the ``https_ca_certificates_file`` option.

Possible values:
    * True
    * False

Related options:
    * https_ca_certificates_file

"""),
    cfg.DictOpt('http_proxy_information',
                default={},
                help="""
The http/https proxy information to be used to connect to the remote
server.

This configuration option specifies the http/https proxy information
that should be used to connect to the remote server. The proxy
information should be a key value pair of the scheme and proxy, for
example, http:10.0.0.1:3128. You can also specify proxies for multiple
schemes by separating the key value pairs with a comma, for example,
http:10.0.0.1:3128, https:10.0.0.1:1080.

Possible values:
    * A comma separated list of scheme:proxy pairs as described above

Related options:
    * None

""")]


class StoreLocation(glance_store.location.StoreLocation):

    """Class describing an HTTP(S) URI."""

    def process_specs(self):
        self.scheme = self.specs.get('scheme', 'http')
        self.netloc = self.specs['netloc']
        self.user = self.specs.get('user')
        self.password = self.specs.get('password')
        self.path = self.specs.get('path')

    def _get_credstring(self):
        if self.user:
            return '%s:%s@' % (self.user, self.password)
        return ''

    def get_uri(self):
        return "%s://%s%s%s" % (
            self.scheme,
            self._get_credstring(),
            self.netloc,
            self.path)

    def parse_uri(self, uri):
        """
        Parse URLs. This method fixes an issue where credentials specified
        in the URL are interpreted differently in Python 2.6.1+ than prior
        versions of Python.
        """
        pieces = urllib.parse.urlparse(uri)
        self.validate_schemas(uri, valid_schemas=('https://', 'http://'))
        self.scheme = pieces.scheme
        netloc = pieces.netloc
        path = pieces.path
        try:
            if '@' in netloc:
                creds, netloc = netloc.split('@')
            else:
                creds = None
        except ValueError:
            # Python 2.6.1 compat
            # see lp659445 and Python issue7904
            if '@' in path:
                creds, path = path.split('@')
            else:
                creds = None
        if creds:
            try:
                self.user, self.password = creds.split(':')
            except ValueError:
                reason = _("Credentials are not well-formatted.")
                LOG.info(reason)
                raise exceptions.BadStoreUri(message=reason)
        else:
            self.user = None
        if netloc == '':
            LOG.info(_LI("No address specified in HTTP URL"))
            raise exceptions.BadStoreUri(uri=uri)
        else:
            # IPv6 address has the following format [1223:0:0:..]:<some_port>
            # we need to be sure that we are validating port in both IPv4,IPv6
            delimiter = "]:" if netloc.count(":") > 1 else ":"
            host, dlm, port = netloc.partition(delimiter)
            # if port is present in location then validate port format
            if port and not port.isdigit():
                raise exceptions.BadStoreUri(uri=uri)

        self.netloc = netloc
        self.path = path


def http_response_iterator(conn, response, size):
    """
    Return an iterator for a file-like object.

    :param conn: HTTP(S) Connection
    :param response: urllib3.HTTPResponse object
    :param size: Chunk size to iterate with
    """
    try:
        chunk = response.read(size)
        while chunk:
            yield chunk
            chunk = response.read(size)
    finally:
        conn.close()


class Store(glance_store.driver.Store):

    """An implementation of the HTTP(S) Backend Adapter"""

    _CAPABILITIES = (capabilities.BitMasks.READ_ACCESS |
                     capabilities.BitMasks.DRIVER_REUSABLE)
    OPTIONS = _HTTP_OPTS

    @capabilities.check
    def get(self, location, offset=0, chunk_size=None, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns a tuple of generator
        (for reading the image file) and image_size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        try:
            conn, resp, content_length = self._query(location, 'GET')
        except requests.exceptions.ConnectionError:
            reason = _("Remote server where the image is present "
                       "is unavailable.")
            LOG.exception(reason)
            raise exceptions.RemoteServiceUnavailable(message=reason)

        iterator = http_response_iterator(conn, resp, self.READ_CHUNKSIZE)

        class ResponseIndexable(glance_store.Indexable):
            def another(self):
                try:
                    return next(self.wrapped)
                except StopIteration:
                    return ''

        return (ResponseIndexable(iterator, content_length), content_length)

    def get_schemes(self):
        return ('http', 'https')

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file, and returns the size

        :param location: `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        """
        conn = None
        try:
            conn, resp, size = self._query(location, 'HEAD')
        except requests.exceptions.ConnectionError as exc:
            err_msg = encodeutils.exception_to_unicode(exc)
            reason = _("The HTTP URL is invalid: %s") % err_msg
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)
        finally:
            # NOTE(sabari): Close the connection as the request was made with
            # stream=True
            if conn is not None:
                conn.close()
        return size

    def _query(self, location, verb):
        redirects_followed = 0

        while redirects_followed < MAX_REDIRECTS:
            loc = location.store_location

            conn = self._get_response(loc, verb)

            # NOTE(sigmavirus24): If it was generally successful, break early
            if conn.status_code < 300:
                break

            self._check_store_uri(conn, loc)

            redirects_followed += 1

            # NOTE(sigmavirus24): Close the response so we don't leak sockets
            conn.close()

            location = self._new_location(location, conn.headers['location'])
        else:
            reason = (_("The HTTP URL exceeded %s maximum "
                        "redirects.") % MAX_REDIRECTS)
            LOG.debug(reason)
            raise exceptions.MaxRedirectsExceeded(message=reason)

        resp = conn.raw

        content_length = int(resp.getheader('content-length', 0))
        return (conn, resp, content_length)

    def _new_location(self, old_location, url):
        store_name = old_location.store_name
        store_class = old_location.store_location.__class__
        image_id = old_location.image_id
        store_specs = old_location.store_specs
        return glance_store.location.Location(store_name,
                                              store_class,
                                              self.conf,
                                              uri=url,
                                              image_id=image_id,
                                              store_specs=store_specs,
                                              backend=self.backend_group)

    @staticmethod
    def _check_store_uri(conn, loc):
        # TODO(sigmavirus24): Make this a staticmethod
        # Check for bad status codes
        if conn.status_code >= 400:
            if conn.status_code == requests.codes.not_found:
                reason = _("HTTP datastore could not find image at URI.")
                LOG.debug(reason)
                raise exceptions.NotFound(message=reason)

            reason = (_("HTTP URL %(url)s returned a "
                        "%(status)s status code. \nThe response body:\n"
                        "%(body)s") %
                      {'url': loc.path, 'status': conn.status_code,
                       'body': conn.text})
            LOG.debug(reason)
            raise exceptions.BadStoreUri(message=reason)

        if conn.is_redirect and conn.status_code not in (301, 302):
            reason = (_("The HTTP URL %(url)s attempted to redirect "
                        "with an invalid %(status)s status code."),
                      {'url': loc.path, 'status': conn.status_code})
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)

    def _get_response(self, location, verb):
        if not hasattr(self, 'session'):
            self.session = requests.Session()

        if self.backend_group:
            store_conf = getattr(self.conf, self.backend_group)
        else:
            store_conf = self.conf.glance_store

        ca_bundle = store_conf.https_ca_certificates_file
        disable_https = store_conf.https_insecure
        self.session.verify = ca_bundle if ca_bundle else not disable_https
        self.session.proxies = store_conf.http_proxy_information
        return self.session.request(verb, location.get_uri(), stream=True,
                                    allow_redirects=False)
