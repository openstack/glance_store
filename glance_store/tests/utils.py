# Copyright 2014 Red Hat, Inc.
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

import io
import urllib.parse

from oslo_utils import units
import requests


def sort_url_by_qs_keys(url):
    # NOTE(kragniz): this only sorts the keys of the query string of a url.
    # For example, an input of '/v2/tasks?sort_key=id&sort_dir=asc&limit=10'
    # returns '/v2/tasks?limit=10&sort_dir=asc&sort_key=id'. This is to prevent
    # non-deterministic ordering of the query string causing problems with unit
    # tests.
    parsed = urllib.parse.urlparse(url)
    # In python2.6, for arbitrary url schemes, query string
    # is not parsed from url. http://bugs.python.org/issue9374
    path = parsed.path
    query = parsed.query
    if not query:
        path, query = parsed.path.split('?', 1)
    queries = urllib.parse.parse_qsl(query, True)
    sorted_query = sorted(queries, key=lambda x: x[0])
    encoded_sorted_query = urllib.parse.urlencode(sorted_query, True)
    url_parts = (parsed.scheme, parsed.netloc, path,
                 parsed.params, encoded_sorted_query,
                 parsed.fragment)
    return urllib.parse.urlunparse(url_parts)


class FakeHTTPResponse(object):
    def __init__(self, status=200, headers=None, data=None, *args, **kwargs):
        data = data or 'I am a teapot, short and stout\n'
        self.data = io.StringIO(data)
        self.read = self.data.read
        self.status = status
        self.headers = headers or {'content-length': len(data)}
        if not kwargs.get('no_response_body', False):
            self.body = None

    def getheader(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def getheaders(self):
        return self.headers or {}

    def read(self, amt):
        self.data.read(amt)

    def release_conn(self):
        pass

    def close(self):
        self.data.close()


def fake_response(status_code=200, headers=None, content=None, **kwargs):
    r = requests.models.Response()
    r.status_code = status_code
    r.headers = headers or {}
    r.raw = FakeHTTPResponse(status_code, headers, content, kwargs)
    return r


class FakeData(object):
    """Generate a bunch of data without storing it in memory.

    This acts like a read-only file object which generates fake data
    in chunks when read() is called or it is used as a generator. It
    can generate an arbitrary amount of data without storing it in
    memory.

    :param length: The number of bytes to generate
    :param chunk_size: The chunk size to return in iteration mode, or when
                       read() is called unbounded

    """
    def __init__(self, length, chunk_size=64 * units.Ki):
        self._max = length
        self._chunk_size = chunk_size
        self._len = 0

    def read(self, length=None):
        if length is None:
            length = self._chunk_size

        length = min(length, self._max - self._len)

        self._len += length
        if length == 0:
            return b''
        else:
            return b'0' * length

    def __iter__(self):
        return self

    def __next__(self):
        r = self.read()
        if len(r) == 0:
            raise StopIteration()
        else:
            return r
