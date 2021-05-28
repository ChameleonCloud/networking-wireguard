# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['networking_wireguard',
 'networking_wireguard.common',
 'networking_wireguard.l3',
 'networking_wireguard.ml2']

package_data = \
{'': ['*']}

install_requires = \
['keystoneauth1>=4.3.1,<5.0.0',
 'neutron-lib>=2.11.0,<3.0.0',
 'neutron>=18.0.0,<19.0.0']

setup_kwargs = {
    'name': 'networking-wireguard',
    'version': '0.1.0',
    'description': '"Openstack Neutron Plugin to enable Wireguard VPN"',
    'long_description': None,
    'author': 'Michael Sherman',
    'author_email': 'shermanm@uchicago.edu',
    'maintainer': None,
    'maintainer_email': None,
    'url': None,
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'python_requires': '>=3.6,<4.0',
}


setup(**setup_kwargs)
