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

import ConfigParser
import logging

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

from oslo.config import cfg

from glance_store import exceptions
from glance_store import i18n

swift_opts = [
    cfg.StrOpt('default_swift_reference',
               default="ref1",
               help=i18n._('The reference to the default swift account/backing'
                           ' store parameters to use for adding new images.')),
    cfg.StrOpt('swift_store_auth_address',
               help=i18n._('The address where the Swift authentication '
                           'service is listening.(deprecated)')),
    cfg.StrOpt('swift_store_user', secret=True,
               help=i18n._('The user to authenticate against the Swift '
                           'authentication service (deprecated)')),
    cfg.StrOpt('swift_store_key', secret=True,
               help=i18n._('Auth key for the user authenticating against the '
                           'Swift authentication service. (deprecated)')),
    cfg.StrOpt('swift_store_config_file', secret=True,
               help=i18n._('The config file that has the swift account(s)'
                           'configs.')),
]

# NOTE(bourke): The default dict_type is collections.OrderedDict in py27, but
# we must set manually for compatibility with py26
CONFIG = ConfigParser.SafeConfigParser(dict_type=OrderedDict)
LOG = logging.getLogger(__name__)


CONF = cfg.CONF
for opt in swift_opts:
    opt.deprecated_opts = [cfg.DeprecatedOpt(opt.name,
                                             group='DEFAULT')]
    CONF.register_opt(opt, group='glance_store')


def is_multiple_swift_store_accounts_enabled():
    if CONF.glance_store.swift_store_config_file is None:
        return False
    return True


class SwiftParams(object):
    def __init__(self):
        if is_multiple_swift_store_accounts_enabled():
            self.params = self._load_config()
        else:
            self.params = self._form_default_params()

    def _form_default_params(self):
        default = {}

        if (
            CONF.glance_store.swift_store_user and
            CONF.glance_store.swift_store_key and
            CONF.glance_store.swift_store_auth_address
        ):

            glance_store = CONF.glance_store
            default['user'] = glance_store.swift_store_user
            default['key'] = glance_store.swift_store_key
            default['auth_address'] = glance_store.swift_store_auth_address
            return {glance_store.default_swift_reference: default}
        return {}

    def _load_config(self):
        try:
            scf = CONF.glance_store.swift_store_config_file
            conf_file = CONF.find_file(scf)
            CONFIG.read(conf_file)
        except Exception as e:
            msg = (i18n._("swift config file "
                          "%(conf_file)s:%(exc)s not found") %
                   {'conf_file': CONF.glance_store.swift_store_config_file,
                    'exc': e})
            LOG.error(msg)
            raise exceptions.BadStoreConfiguration(store_name='swift',
                                                   reason=msg)
        account_params = {}
        account_references = CONFIG.sections()
        for ref in account_references:
            reference = {}
            try:
                reference['auth_address'] = CONFIG.get(ref, 'auth_address')
                reference['user'] = CONFIG.get(ref, 'user')
                reference['key'] = CONFIG.get(ref, 'key')
                account_params[ref] = reference
            except (ValueError, SyntaxError, ConfigParser.NoOptionError) as e:
                LOG.exception(i18n._("Invalid format of swift store config"
                                     "cfg"))
        return account_params
