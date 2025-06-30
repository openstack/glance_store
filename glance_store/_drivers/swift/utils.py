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

import configparser
import logging
import warnings

from oslo_config import cfg

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
    cfg.StrOpt('swift_store_auth_version', default='3',
               choices=['3'],
               help='The authentication version to be used. Currently '
                    'The only valid version is 3.',
               deprecated_for_removal=True,
               deprecated_reason="""
This option is kept for backword-compatibility reasons but is no longer
required, because only the single version (3) is supported now.
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


class SwiftConfigParser(configparser.ConfigParser):

    def get(self, *args, **kwargs):
        value = super(configparser.ConfigParser, self).get(*args, **kwargs)
        return self._process_quotes(value)

    @staticmethod
    def _process_quotes(value):
        if value:
            if value[0] in "\"'":
                if len(value) == 1 or value[-1] != value[0]:
                    raise ValueError('Non-closed quote: %s' %
                                     value)
                value = value[1:-1]
        return value


CONFIG = SwiftConfigParser()

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
                for param in ('auth_address', 'user', 'key'):
                    reference[param] = CONFIG.get(ref, param)

                reference['project_domain_name'] = CONFIG.get(
                    ref, 'project_domain_name', fallback=None)
                reference['project_domain_id'] = CONFIG.get(
                    ref, 'project_domain_id', fallback=None)
                if (reference['project_domain_name'] is None and
                        reference['project_domain_id'] is None):
                    reference['project_domain_id'] = 'default'

                reference['user_domain_name'] = CONFIG.get(
                    ref, 'user_domain_name', fallback=None)
                reference['user_domain_id'] = CONFIG.get(
                    ref, 'user_domain_id', fallback=None)
                if (reference['user_domain_name'] is None and
                        reference['user_domain_id'] is None):
                    reference['user_domain_id'] = 'default'

                try:
                    reference['auth_version'] = CONFIG.get(ref, 'auth_version')
                    warnings.warn(
                        'The auth_version option is deprecated. It is kept '
                        'for backword-compatibility reasons but will be '
                        'removed in a future release.',
                        DeprecationWarning)
                except configparser.NoOptionError:
                    if self.backend_group:
                        av = getattr(
                            self.conf,
                            self.backend_group).swift_store_auth_version
                    else:
                        av = self.conf.glance_store.swift_store_auth_version
                    reference['auth_version'] = av

                if reference['auth_version'] != '3':
                    raise ValueError('Unsupported auth_version')

                account_params[ref] = reference
            except (ValueError, SyntaxError, configparser.NoOptionError):
                LOG.exception(_LE("Invalid format of swift store config cfg"))
        return account_params
