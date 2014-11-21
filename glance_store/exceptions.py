# Copyright (c) 2014 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Glance Store exception subclasses"""

import six.moves.urllib.parse as urlparse

from glance_store import i18n

_ = i18n._


class BackendException(Exception):
    pass


class UnsupportedBackend(BackendException):
    pass


class RedirectException(Exception):
    def __init__(self, url):
        self.url = urlparse.urlparse(url)


class GlanceStoreException(Exception):
    """
    Base Glance Store Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = ''

    def __init__(self, **kwargs):
        self.msg = kwargs.pop('message', None) or self.message % kwargs
        super(Exception, self).__init__(self.msg)


class MissingCredentialError(GlanceStoreException):
    message = _("Missing required credential: %(required)s")


class BadAuthStrategy(GlanceStoreException):
    message = _("Incorrect auth strategy, expected \"%(expected)s\" but "
                "received \"%(received)s\"")


class AuthorizationRedirect(GlanceStoreException):
    message = _("Redirecting to %(uri)s for authorization.")


class NotFound(GlanceStoreException):
    message = _("Image %(image)s not found")


class UnknownScheme(GlanceStoreException):
    message = _("Unknown scheme '%(scheme)s' found in URI")


class BadStoreUri(GlanceStoreException):
    message = _("The Store URI was malformed: %(uri)s")


class Duplicate(GlanceStoreException):
    message = _("Image %(image)s already exists")


class Conflict(GlanceStoreException):
    message = _("An object with the same identifier is currently being "
                "operated on.")


class StorageFull(GlanceStoreException):
    message = _("There is not enough disk space on the image storage media.")


class StorageWriteDenied(GlanceStoreException):
    message = _("Permission to write image storage media denied.")


class AuthBadRequest(GlanceStoreException):
    message = _("Connect error/bad request to Auth service at URL %(url)s.")


class AuthUrlNotFound(GlanceStoreException):
    message = _("Auth service at URL %(url)s not found.")


class AuthorizationFailure(GlanceStoreException):
    message = _("Authorization failed.")


class NotAuthenticated(GlanceStoreException):
    message = _("You are not authenticated.")


class Forbidden(GlanceStoreException):
    message = _("You are not authorized to complete this action.")


class ForbiddenPublicImage(Forbidden):
    message = _("You are not authorized to complete this action.")


class ProtectedImageDelete(Forbidden):
    message = _("Image %(image_id)s is protected and cannot be deleted.")


class Invalid(GlanceStoreException):
    message = _("Data supplied was not valid.")


class BadStoreConfiguration(GlanceStoreException):
    message = _("Store %(store_name)s could not be configured correctly. "
                "Reason: %(reason)s")


class DriverLoadFailure(GlanceStoreException):
    message = _("Driver %(driver_name)s could not be loaded.")


class BadDriverConfiguration(GlanceStoreException):
    message = _("Driver %(driver_name)s could not be configured correctly. "
                "Reason: %(reason)s")


class StoreDeleteNotSupported(GlanceStoreException):
    message = _("Deleting images from this store is not supported.")


class StoreGetNotSupported(GlanceStoreException):
    message = _("Getting images from this store is not supported.")


class StoreRandomGetNotSupported(StoreGetNotSupported):
    message = _("Getting images randomly from this store is not supported. "
                "Offset: %(offset)s, length: %(chunk_size)s")


class StoreAddDisabled(GlanceStoreException):
    message = _("Configuration for store failed. Adding images to this "
                "store is disabled.")


class MaxRedirectsExceeded(GlanceStoreException):
    message = _("Maximum redirects (%(redirects)s) was exceeded.")


class InvalidRedirect(GlanceStoreException):
    message = _("Received invalid HTTP redirect.")


class NoServiceEndpoint(GlanceStoreException):
    message = _("Response from Keystone does not contain a Glance endpoint.")


class RegionAmbiguity(GlanceStoreException):
    message = _("Multiple 'image' service matches for region %(region)s. This "
                "generally means that a region is required and you have not "
                "supplied one.")


class RemoteServiceUnavailable(GlanceStoreException):
    message = _("Remote server where the image is present is unavailable.")


class WorkerCreationFailure(GlanceStoreException):
    message = _("Server worker creation failed: %(reason)s.")


class SchemaLoadError(GlanceStoreException):
    message = _("Unable to load schema: %(reason)s")


class InvalidObject(GlanceStoreException):
    message = _("Provided object does not match schema "
                "'%(schema)s': %(reason)s")


class UnsupportedHeaderFeature(GlanceStoreException):
    message = _("Provided header feature is unsupported: %(feature)s")


class InUseByStore(GlanceStoreException):
    message = _("The image cannot be deleted because it is in use through "
                "the backend store outside of Glance.")


class ImageDataNotFound(NotFound):
    message = _("No image data could be found")


class InvalidParameterValue(Invalid):
    message = _("Invalid value '%(value)s' for parameter '%(param)s': "
                "%(extra_msg)s")


class InvalidImageStatusTransition(Invalid):
    message = _("Image status transition from %(cur_status)s to"
                " %(new_status)s is not allowed")
