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

"""Storage backend for Cinder"""

import logging

from cinderclient import exceptions as cinder_exception
from cinderclient import service_catalog
from cinderclient.v2 import client as cinderclient
from oslo_config import cfg
from oslo_utils import units

from glance_store import capabilities
from glance_store.common import utils
import glance_store.driver
from glance_store import exceptions
from glance_store.i18n import _
import glance_store.location

LOG = logging.getLogger(__name__)

_CINDER_OPTS = [
    cfg.StrOpt('cinder_catalog_info',
               default='volume:cinder:publicURL',
               help='Info to match when looking for cinder in the service '
                    'catalog. Format is : separated values of the form: '
                    '<service_type>:<service_name>:<endpoint_type>'),
    cfg.StrOpt('cinder_endpoint_template',
               default=None,
               help='Override service catalog lookup with template for cinder '
                    'endpoint e.g. http://localhost:8776/v1/%(project_id)s'),
    cfg.StrOpt('os_region_name',
               default=None,
               help='Region name of this node'),
    cfg.StrOpt('cinder_ca_certificates_file',
               default=None,
               help='Location of ca certicates file to use for cinder client '
                    'requests.'),
    cfg.IntOpt('cinder_http_retries',
               default=3,
               help='Number of cinderclient retries on failed http calls'),
    cfg.BoolOpt('cinder_api_insecure',
                default=False,
                help='Allow to perform insecure SSL requests to cinder'),
]


def get_cinderclient(conf, context):
    if conf.glance_store.cinder_endpoint_template:
        url = conf.glance_store.cinder_endpoint_template % context.to_dict()
    else:
        info = conf.glance_store.cinder_catalog_info
        service_type, service_name, endpoint_type = info.split(':')

        # extract the region if set in configuration
        if conf.glance_store.os_region_name:
            attr = 'region'
            filter_value = conf.glance_store.os_region_name
        else:
            attr = None
            filter_value = None

        # FIXME: the cinderclient ServiceCatalog object is mis-named.
        #        It actually contains the entire access blob.
        # Only needed parts of the service catalog are passed in, see
        # nova/context.py.
        compat_catalog = {
            'access': {'serviceCatalog': context.service_catalog or []}}
        sc = service_catalog.ServiceCatalog(compat_catalog)

        url = sc.url_for(attr=attr,
                         filter_value=filter_value,
                         service_type=service_type,
                         service_name=service_name,
                         endpoint_type=endpoint_type)

    LOG.debug(_('Cinderclient connection created using URL: %s') % url)

    glance_store = conf.glance_store
    c = cinderclient.Client(context.user,
                            context.auth_token,
                            project_id=context.tenant,
                            auth_url=url,
                            insecure=glance_store.cinder_api_insecure,
                            retries=glance_store.cinder_http_retries,
                            cacert=glance_store.cinder_ca_certificates_file)

    # noauth extracts user_id:project_id from auth_token
    c.client.auth_token = context.auth_token or '%s:%s' % (context.user,
                                                           context.tenant)
    c.client.management_url = url
    return c


class StoreLocation(glance_store.location.StoreLocation):

    """Class describing a Cinder URI."""

    def process_specs(self):
        self.scheme = self.specs.get('scheme', 'cinder')
        self.volume_id = self.specs.get('volume_id')

    def get_uri(self):
        return "cinder://%s" % self.volume_id

    def parse_uri(self, uri):
        if not uri.startswith('cinder://'):
            reason = _("URI must start with 'cinder://'")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)

        self.scheme = 'cinder'
        self.volume_id = uri[9:]

        if not utils.is_uuid_like(self.volume_id):
            reason = _("URI contains invalid volume ID")
            LOG.info(reason)
            raise exceptions.BadStoreUri(message=reason)


class Store(glance_store.driver.Store):

    """Cinder backend store adapter."""

    _CAPABILITIES = capabilities.BitMasks.DRIVER_REUSABLE
    OPTIONS = _CINDER_OPTS
    EXAMPLE_URL = "cinder://<VOLUME_ID>"

    def get_schemes(self):
        return ('cinder',)

    def _check_context(self, context):
        """
        Configure the Store to use the stored configuration options
        Any store that needs special configuration should implement
        this method. If the store was not able to successfully configure
        itself, it should raise `exceptions.BadStoreConfiguration`
        """

        if context is None:
            reason = _("Cinder storage requires a context.")
            raise exceptions.BadStoreConfiguration(store_name="cinder",
                                                   reason=reason)
        if context.service_catalog is None:
            reason = _("Cinder storage requires a service catalog.")
            raise exceptions.BadStoreConfiguration(store_name="cinder",
                                                   reason=reason)

    def get_size(self, location, context=None):
        """
        Takes a `glance_store.location.Location` object that indicates
        where to find the image file and returns the image size

        :param location `glance_store.location.Location` object, supplied
                        from glance_store.location.get_location_from_uri()
        :raises `glance_store.exceptions.NotFound` if image does not exist
        :rtype int
        """

        loc = location.store_location

        try:
            self._check_context(context)
            volume = get_cinderclient(self.conf,
                                      context).volumes.get(loc.volume_id)
            # GB unit convert to byte
            return volume.size * units.Gi
        except cinder_exception.NotFound as e:
            reason = _("Failed to get image size due to "
                       "volume can not be found: %s") % self.volume_id
            LOG.error(reason)
            raise exceptions.NotFound(reason)
        except Exception as e:
            LOG.exception(_("Failed to get image size due to "
                            "internal error: %s") % e)
            return 0
