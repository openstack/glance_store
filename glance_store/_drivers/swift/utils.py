#    Copyright 2014 Rackspace
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
import sys

from oslo_config import cfg
from six.moves import configparser

from glance_store import exceptions
from glance_store.i18n import _, _LE

swift_opts = [
    cfg.StrOpt('default_swift_reference',
               default="ref1",
               help="""
Reference to default Swift account/backing store parameters.

Provide a string value representing a reference to the default set
of parameters required for using swift account/backing store for
image storage. The default reference value for this configuration
option is 'ref1'. This configuration option dereferences the
parameters and facilitates image storage in Swift storage backend
every time a new image is added.

Possible values:
    * A valid string value

Related options:
    * None

"""),
    cfg.StrOpt('swift_store_auth_version', default='2',
               help='Version of the authentication service to use. '
                    'Valid versions are 2 and 3 for keystone and 1 '
                    '(deprecated) for swauth and rackspace.',
               deprecated_for_removal=True,
               deprecated_reason="""
The option 'auth_version' in the Swift back-end configuration file is
used instead.
"""),
    cfg.StrOpt('swift_store_auth_address',
               help='The address where the Swift authentication '
                    'service is listening.',
               deprecated_for_removal=True,
               deprecated_reason="""
The option 'auth_address' in the Swift back-end configuration file is
used instead.
"""),
    cfg.StrOpt('swift_store_user', secret=True,
               help='The user to authenticate against the Swift '
                    'authentication service.',
               deprecated_for_removal=True,
               deprecated_reason="""
The option 'user' in the Swift back-end configuration file is set instead.
"""),
    cfg.StrOpt('swift_store_key', secret=True,
               help='Auth key for the user authenticating against the '
                    'Swift authentication service.',
               deprecated_for_removal=True,
               deprecated_reason="""
The option 'key' in the Swift back-end configuration file is used
to set the authentication key instead.
"""),
    cfg.StrOpt('swift_store_config_file',
               default=None,
               help="""
Absolute path to the file containing the swift account(s)
configurations.

Include a string value representing the path to a configuration
file that has references for each of the configured Swift
account(s)/backing stores. By default, no file path is specified
and customized Swift referencing is disabled. Configuring this
option is highly recommended while using Swift storage backend for
image storage as it avoids storage of credentials in the database.

NOTE: Please do not configure this option if you have set
``swift_store_multi_tenant`` to ``True``.

Possible values:
    * String value representing an absolute path on the glance-api
      node

Related options:
    * swift_store_multi_tenant

"""),
]

_config_defaults = {'user_domain_id': 'default',
                    'user_domain_name': 'default',
                    'project_domain_id': 'default',
                    'project_domain_name': 'default'}

if sys.version_info >= (3, 2):
    CONFIG = configparser.ConfigParser(defaults=_config_defaults)
else:
    CONFIG = configparser.SafeConfigParser(defaults=_config_defaults)
LOG = logging.getLogger(__name__)


def is_multiple_swift_store_accounts_enabled(conf, backend=None):
    if backend:
        cfg_file = getattr(conf, backend).swift_store_config_file
    else:
        cfg_file = conf.glance_store.swift_store_config_file

    if cfg_file is None:
        return False
    return True


class SwiftParams(object):
    def __init__(self, conf, backend=None):
        self.conf = conf
        self.backend_group = backend
        if is_multiple_swift_store_accounts_enabled(
                self.conf, backend=backend):
            self.params = self._load_config()
        else:
            self.params = self._form_default_params()

    def _form_default_params(self):
        default = {}
        if self.backend_group:
            glance_store = getattr(self.conf, self.backend_group)
        else:
            glance_store = self.conf.glance_store
        if (
                glance_store.swift_store_user and
                glance_store.swift_store_key and
                glance_store.swift_store_auth_address
        ):

            default['user'] = glance_store.swift_store_user
            default['key'] = glance_store.swift_store_key
            default['auth_address'] = glance_store.swift_store_auth_address
            default['project_domain_id'] = 'default'
            default['project_domain_name'] = None
            default['user_domain_id'] = 'default'
            default['user_domain_name'] = None
            default['auth_version'] = glance_store.swift_store_auth_version
            return {glance_store.default_swift_reference: default}
        return {}

    def _load_config(self):
        if self.backend_group:
            scf = getattr(self.conf,
                          self.backend_group).swift_store_config_file
        else:
            scf = self.conf.glance_store.swift_store_config_file
        try:
            conf_file = self.conf.find_file(scf)
            CONFIG.read(conf_file)
        except Exception as e:
            msg = (_("swift config file "
                     "%(conf)s:%(exc)s not found"),
                   {'conf': scf,
                    'exc': e})
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(store_name='swift',
                                                   reason=msg)
        account_params = {}
        account_references = CONFIG.sections()

        for ref in account_references:
            reference = {}
            try:
                for param in ('auth_address',
                              'user',
                              'key',
                              'project_domain_id',
                              'project_domain_name',
                              'user_domain_id',
                              'user_domain_name'):
                    reference[param] = CONFIG.get(ref, param)

                try:
                    reference['auth_version'] = CONFIG.get(ref, 'auth_version')
                except configparser.NoOptionError:
                    if self.backend_group:
                        av = getattr(
                            self.conf,
                            self.backend_group).swift_store_auth_version
                    else:
                        av = self.conf.glance_store.swift_store_auth_version
                    reference['auth_version'] = av

                account_params[ref] = reference
            except (ValueError, SyntaxError, configparser.NoOptionError) as e:
                LOG.exception(_LE("Invalid format of swift store config cfg"))
        return account_params
