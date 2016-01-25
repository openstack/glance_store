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

from debtcollector import removals
import six
import six.moves.urllib.parse as urlparse
import warnings

from glance_store import i18n
warnings.simplefilter('always')
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
    message = _("An unknown exception occurred")

    def __init__(self, message=None, **kwargs):
        if not message:
            message = self.message
        try:
            if kwargs:
                message = message % kwargs
        except Exception:
                pass
        self.msg = message
        super(GlanceStoreException, self).__init__(message)

    def __unicode__(self):
        # NOTE(flwang): By default, self.msg is an instance of Message, which
        # can't be converted by str(). Based on the definition of
        # __unicode__, it should return unicode always.
        return six.text_type(self.msg)


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


@removals.remove(version="0.10.0")
class Conflict(GlanceStoreException):
    """DEPRECATED!"""
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


@removals.remove(version="0.10.0")
class ForbiddenPublicImage(Forbidden):
    """DEPRECATED!"""
    message = _("You are not authorized to complete this action.")


@removals.remove(version="0.10.0")
class ProtectedImageDelete(Forbidden):
    """DEPRECATED!"""
    message = _("Image %(image_id)s is protected and cannot be deleted.")


class Invalid(GlanceStoreException):
    # NOTE(NiallBunting) This could be deprecated however the debtcollector
    # seems to have problems deprecating this as well as the subclasses.
    message = _("Data supplied was not valid.")


class BadStoreConfiguration(GlanceStoreException):
    message = _("Store %(store_name)s could not be configured correctly. "
                "Reason: %(reason)s")


class DriverLoadFailure(GlanceStoreException):
    message = _("Driver %(driver_name)s could not be loaded.")


@removals.remove(version="0.10.0")
class BadDriverConfiguration(GlanceStoreException):
    """DEPRECATED!"""
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


@removals.remove(version="0.10.0")
class InvalidRedirect(GlanceStoreException):
    """DEPRECATED!"""
    message = _("Received invalid HTTP redirect.")


class NoServiceEndpoint(GlanceStoreException):
    message = _("Response from Keystone does not contain a Glance endpoint.")


class RegionAmbiguity(GlanceStoreException):
    message = _("Multiple 'image' service matches for region %(region)s. This "
                "generally means that a region is required and you have not "
                "supplied one.")


class RemoteServiceUnavailable(GlanceStoreException):
    message = _("Remote server where the image is present is unavailable.")


@removals.remove(version="0.10.0")
class WorkerCreationFailure(GlanceStoreException):
    """DEPRECATED!"""
    message = _("Server worker creation failed: %(reason)s.")


@removals.remove(version="0.10.0")
class SchemaLoadError(GlanceStoreException):
    """DEPRECATED!"""
    message = _("Unable to load schema: %(reason)s")


@removals.remove(version="0.10.0")
class InvalidObject(GlanceStoreException):
    """DEPRECATED!"""
    message = _("Provided object does not match schema "
                "'%(schema)s': %(reason)s")


@removals.remove(version="0.10.0")
class UnsupportedHeaderFeature(GlanceStoreException):
    """DEPRECATED!"""
    message = _("Provided header feature is unsupported: %(feature)s")


class HasSnapshot(GlanceStoreException):
    message = _("The image cannot be deleted because it has snapshot(s).")


class InUseByStore(GlanceStoreException):
    message = _("The image cannot be deleted because it is in use through "
                "the backend store outside of Glance.")


@removals.remove(version="0.10.0")
class ImageDataNotFound(NotFound):
    """DEPRECATED!"""
    message = _("No image data could be found")


@removals.remove(version="0.10.0")
class InvalidParameterValue(Invalid):
    """DEPRECATED!"""
    message = _("Invalid value '%(value)s' for parameter '%(param)s': "
                "%(extra_msg)s")


@removals.remove(version="0.10.0")
class InvalidImageStatusTransition(Invalid):
    """DEPRECATED!"""
    message = _("Image status transition from %(cur_status)s to"
                " %(new_status)s is not allowed")
