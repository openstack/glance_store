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

from collections import OrderedDict

from oslo_config import cfg
from six.moves import configparser

from glance_store import exceptions
from glance_store import i18n

swift_opts = [
    cfg.StrOpt('default_swift_reference',
               default="ref1",
               help=i18n._('The reference to the default swift account/backing'
                           ' store parameters to use for adding new images.')),
    cfg.StrOpt('swift_store_auth_version', default='2',
               help=i18n._('Version of the authentication service to use. '
                           'Valid versions are 2 and 3 for keystone and 1 '
                           '(deprecated) for swauth and rackspace.'),
               deprecated_for_removal=True,
               deprecated_reason=i18n._('Use "auth_version" in '
                                        'swift_store_config_file.')
               ),
    cfg.StrOpt('swift_store_auth_address',
               help=i18n._('The address where the Swift authentication '
                           'service is listening.'),
               deprecated_for_removal=True,
               deprecated_reason=i18n._('Use "auth_address" in '
                                        'swift_store_config_file')
               ),
    cfg.StrOpt('swift_store_user', secret=True,
               help=i18n._('The user to authenticate against the Swift '
                           'authentication service.'),
               deprecated_for_removal=True,
               deprecated_reason=i18n._('Use "user" in '
                                        'swift_store_config_file.')),
    cfg.StrOpt('swift_store_key', secret=True,
               help=i18n._('Auth key for the user authenticating against the '
                           'Swift authentication service.'),
               deprecated_for_removal=True,
               deprecated_reason=i18n._('Use "key" in '
                                        'swift_store_config_file.')
               ),
    cfg.StrOpt('swift_store_config_file', secret=True,
               help=i18n._('The config file that has the swift account(s)'
                           'configs.')),
]

_config_defaults = {'user_domain_id': 'default',
                    'user_domain_name': None,
                    'project_domain_id': 'default',
                    'project_domain_name': None}

# NOTE(bourke): The default dict_type is collections.OrderedDict in py27, but
# we must set manually for compatibility with py26
CONFIG = configparser.SafeConfigParser(defaults=_config_defaults,
                                       dict_type=OrderedDict)
LOG = logging.getLogger(__name__)


def is_multiple_swift_store_accounts_enabled(conf):
    if conf.glance_store.swift_store_config_file is None:
        return False
    return True


class SwiftParams(object):
    def __init__(self, conf):
        self.conf = conf
        if is_multiple_swift_store_accounts_enabled(self.conf):
            self.params = self._load_config()
        else:
            self.params = self._form_default_params()

    def _form_default_params(self):
        default = {}

        if (
            self.conf.glance_store.swift_store_user and
            self.conf.glance_store.swift_store_key and
            self.conf.glance_store.swift_store_auth_address
        ):

            glance_store = self.conf.glance_store
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
        try:
            scf = self.conf.glance_store.swift_store_config_file
            conf_file = self.conf.find_file(scf)
            CONFIG.read(conf_file)
        except Exception as e:
            msg = (i18n._("swift config file "
                          "%(conf)s:%(exc)s not found") %
                   {'conf': self.conf.glance_store.swift_store_config_file,
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
                    av = self.conf.glance_store.swift_store_auth_version
                    reference['auth_version'] = av

                account_params[ref] = reference
            except (ValueError, SyntaxError, configparser.NoOptionError) as e:
                LOG.exception(i18n._("Invalid format of swift store config"
                                     "cfg"))
        return account_params
