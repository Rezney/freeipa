#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import time
import logging

from ipatests.pytest_plugins.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipaplatform.paths import paths

from itertools import chain, repeat

logger = logging.getLogger(__name__)

IPA_CA = 'ipa_ca.crt'
ROOT_CA = 'root_ca.crt'

PKI_START_STR = 'Started pki_tomcatd'


# by default ExternalCA module is using CN 'example.test'.
def check_CA_flag(host, nssdb=paths.PKI_TOMCAT_ALIAS_DIR,
                  nickname='example.test'):
    result = host.run_command(['certutil', '-L', '-d', nssdb])
    output = result.stdout_text.split()
    logger.debug(output)
    for line in output:
        if line[0:-2].startswith(nickname):
            if line[-1].startswith('C'):
                return True

    return False


def match_in_journal(host, string, since='today',
                     services=('certmonger', 'renew_ca_cert')):
    # prepend '-u' before every service name
    services_args = list(chain.from_iterable(zip(repeat('-u'), services)))
    result = host.run_command(['journalctl', '--since={}'.format(since),
                               services_args])
    output = result.stdout_text
    logger.debug(output)
    traceback = re.compile(string)
    match = re.search(traceback, output)

    return match


class TestExternalCA(IntegrationTest):
    """
    Test of FreeIPA server installation with exernal CA
    """
    @tasks.collect_logs
    def test_external_ca(self):
        # Step 1 of ipa-server-install
        self.master.run_command([
            'ipa-server-install', '-U',
            '-a', self.master.config.admin_password,
            '-p', self.master.config.dirman_password,
            '--setup-dns', '--no-forwarders',
            '-n', self.master.domain.name,
            '-r', self.master.domain.realm,
            '--domain-level=%i' % self.master.config.domain_level,
            '--external-ca'
        ])

        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA)

        # Step 2 of ipa-server-install
        self.master.run_command([
            'ipa-server-install',
            '-a', self.master.config.admin_password,
            '-p', self.master.config.dirman_password,
            '--external-cert-file', ipa_ca_fname,
            '--external-cert-file', root_ca_fname
        ])

        # Make sure IPA server is working properly
        tasks.kinit_admin(self.master)
        result = self.master.run_command(['ipa', 'user-show', 'admin'])
        assert 'User login: admin' in result.stdout_text


class TestSelfExternalSelf(IntegrationTest):
    """
    Test self-signed > external CA > self-signed test case.
    """
    def test_install_master(self):
        result = tasks.install_master(self.master)
        assert result.returncode == 0

    def test_switch_to_external_ca(self):

        result = self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                         '--external-ca'])
        assert result.returncode == 0

        # Sign CA, transport it to the host and get ipa a root ca paths.
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            self.master, paths.IPA_CA_CSR, ROOT_CA, IPA_CA)

        # renew CA with externally signed one
        result = self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                          '--external-cert-file={}'.
                                          format(ipa_ca_fname),
                                          '--external-cert-file={}'.
                                          format(root_ca_fname)])
        assert result.returncode == 0

        # update IPA certificate databases
        result = self.master.run_command([paths.IPA_CERTUPDATE])
        assert result.returncode == 0

    def test_switch_back_to_self_signed(self):

        switch_time = time.strftime('%H:%M:%S')
        # switch back to self-signed CA
        result = self.master.run_command([paths.IPA_CACERT_MANAGE, 'renew',
                                          '--self-signed'])
        assert result.returncode == 0

        # Check if external CA have "C" flag after the switch
        assert check_CA_flag(self.master), 'External CA does not have "C" flag'

        # Check if there is any traceback in the journal
        result = match_in_journal(self.master, since=switch_time,
                                  string='Traceback')
        assert bool(result), ('Traceback keyword found in the journal. Please'
                              'check further')

        # Check if pki-tomcatd was started after switching back.
        result = match_in_journal(self.host, since=switch_time,
                                  string=PKI_START_STR)
        assert bool(result), ('pki_tomcatd not started after switching back to'
                              'self-signed CA')

        result = self.master.run_command([paths.IPA_CERTUPDATE])
        assert result.returncode == 0
