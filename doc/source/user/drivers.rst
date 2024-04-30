
Glance Store Drivers
====================

Glance store supports several different drivers. These drivers live
within the library's code base and they are maintained by either
members of the Glance community or OpenStack in general. Please, find
below the table of supported drivers and maintainers:

.. list-table::
   :header-rows: 1

   * - Driver
     - Status
     - Maintainer
     - Email
     - IRC Nick
   * - File System
     - Supported
     - Glance Team
     - openstack-discuss@lists.openstack.org
     - openstack-glance
   * - HTTP
     - Supported
     - Glance Team
     - openstack-discuss@lists.openstack.org
     - openstack-glance
   * - RBD
     - Supported
     - Glance Team
     - openstack-discuss@lists.openstack.org
     - openstack-glance
   * - Cinder
     - Supported
     - Rajat Dhasmana
     - rajatdhasmana@gmail.com
     - whoami-rajat
   * - Swift
     - Supported
     - Matthew Oliver
     - matt@oliver.net.au
     - mattoliverau
   * - VMware
     - Deprecated
     - N/A
     - N/A
     -
   * - S3
     - Supported
     - Naohiro Sameshima
     - naohiro.sameshima@global.ntt
     - nao-shark

.. note::
  VMWare driver was deprecated in 2024.1 release, because of lack of CI and
  active maintainers
