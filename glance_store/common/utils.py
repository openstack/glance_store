# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
System-level utilities and helper functions.
"""

import hashlib
import logging
import uuid

from oslo_concurrency import lockutils


LOG = logging.getLogger(__name__)

synchronized = lockutils.synchronized_with_prefix('glance_store-')


def is_uuid_like(val):
    """Returns validation of a value as a UUID.

    For our purposes, a UUID is a canonical form string:
    aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
    """

    try:
        return str(uuid.UUID(val)) == val
    except (TypeError, ValueError, AttributeError):
        return False


def chunkreadable(iter, chunk_size=65536):
    """
    Wrap a readable iterator with a reader yielding chunks of
    a preferred size, otherwise leave iterator unchanged.

    :param iter: an iter which may also be readable
    :param chunk_size: maximum size of chunk
    """
    return chunkiter(iter, chunk_size) if hasattr(iter, 'read') else iter


def chunkiter(fp, chunk_size=65536):
    """
    Return an iterator to a file-like obj which yields fixed size chunks

    :param fp: a file-like object
    :param chunk_size: maximum size of chunk
    """
    while True:
        chunk = fp.read(chunk_size)
        if chunk:
            yield chunk
        else:
            break


def get_hasher(hash_algo, usedforsecurity=True):
    """
    Returns the required hasher, given the hashing algorithm.
    This is primarily to ensure that the hash algorithm is correctly
    chosen when executed on a FIPS enabled system

    :param hash_algo: hash algorithm requested
    :param usedforsecurity: whether the hashes are used in a security context
    """
    if str(hash_algo) == 'md5':
        return hashlib.md5(usedforsecurity=usedforsecurity)
    else:
        return hashlib.new(str(hash_algo))
