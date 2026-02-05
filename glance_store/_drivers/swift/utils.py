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

from glance_store import driver
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
    cfg.StrOpt('swift_store_application_credential_id', secret=True,
               help="""
Application credential ID for authenticating against Swift.

This option specifies the application credential ID to use for
authenticating with the Swift backend. When set along with
swift_store_application_credential_secret, the Swift driver will
use V3ApplicationCredential authentication instead of password
authentication.

This enables Zero Downtime Password Rotation (ZDPR) support for
Swift backend operations, as application credentials are not
affected by password rotation.

If not set, the driver falls back to password authentication
using swift_store_user and swift_store_key.

Possible values:
    * A valid application credential ID string

Related options:
    * swift_store_application_credential_secret

"""),
    cfg.StrOpt('swift_store_application_credential_secret', secret=True,
               help="""
Application credential secret for authenticating against Swift.

This option specifies the application credential secret to use
for authenticating with the Swift backend. When set along with
swift_store_application_credential_id, the Swift driver will
use V3ApplicationCredential authentication instead of password
authentication.

This enables Zero Downtime Password Rotation (ZDPR) support for
Swift backend operations, as application credentials are not
affected by password rotation.

If not set, the driver falls back to password authentication
using swift_store_user and swift_store_key.

Possible values:
    * A valid application credential secret string

Related options:
    * swift_store_application_credential_id

"""),
    cfg.StrOpt('swift_store_project_name',
               help='Project name for authenticating with application '
                    'credentials against the Swift authentication service.',
               deprecated_for_removal=True,
               deprecated_reason="""
The option 'project_name' in the Swift back-end configuration file is
used instead.
"""),
    cfg.StrOpt('swift_store_project_id',
               help='Project ID for authenticating with application '
                    'credentials against the Swift authentication service.',
               deprecated_for_removal=True,
               deprecated_reason="""
The option 'project_id' in the Swift back-end configuration file is
used instead.
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
        from glance_store._drivers.swift import store as swift_store
        store_opts = swift_store._SWIFT_OPTS + swift_opts
        if self.backend_group:
            glance_store = driver.BackendGroupConfiguration(
                store_opts, self.backend_group, conf=self.conf)
        else:
            glance_store = self.conf.glance_store
        if (
                glance_store.swift_store_application_credential_id and
                glance_store.swift_store_application_credential_secret and
                glance_store.swift_store_auth_address
        ):
            default['application_credential_id'] = (
                glance_store.swift_store_application_credential_id)
            default['application_credential_secret'] = (
                glance_store.swift_store_application_credential_secret)
            default['auth_address'] = glance_store.swift_store_auth_address
            default['project_domain_id'] = 'default'
            default['project_domain_name'] = None
            default['user_domain_id'] = 'default'
            default['user_domain_name'] = None
            default['auth_version'] = glance_store.swift_store_auth_version
            if hasattr(glance_store, 'swift_store_project_name'):
                default['project_name'] = glance_store.swift_store_project_name
            if hasattr(glance_store, 'swift_store_project_id'):
                default['project_id'] = glance_store.swift_store_project_id
            return {glance_store.default_swift_reference: default}
        elif (
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
                try:
                    reference['application_credential_id'] = CONFIG.get(
                        ref, 'application_credential_id')
                    reference['application_credential_secret'] = CONFIG.get(
                        ref, 'application_credential_secret')
                    reference['auth_address'] = CONFIG.get(ref, 'auth_address')
                    reference['project_name'] = CONFIG.get(
                        ref, 'project_name', fallback=None)
                    reference['project_id'] = CONFIG.get(
                        ref, 'project_id', fallback=None)
                except configparser.NoOptionError:
                    reference['application_credential_id'] = None
                    reference['application_credential_secret'] = None
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
                        conf_group = getattr(self.conf, self.backend_group)
                    else:
                        conf_group = self.conf.glance_store
                    try:
                        av = getattr(conf_group, 'swift_store_auth_version')
                    except AttributeError:
                        av = '3'
                    reference['auth_version'] = av or '3'

                if reference.get('auth_version') != '3':
                    reference['auth_version'] = '3'

                account_params[ref] = reference
            except (ValueError, SyntaxError, configparser.NoOptionError):
                LOG.exception(_LE("Invalid format of swift store config cfg"))
        return account_params
