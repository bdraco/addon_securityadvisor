package Cpanel::Security::Advisor::Assessors::Apache;

# Copyright (c) 2013, cPanel, Inc.
# All rights reserved.
# http://cpanel.net
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the owner nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL  BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::Version         ();
use Cpanel::Config::Sources ();
use Cpanel::HttpRequest     ();
use Cpanel::SafeRun::Errors ();

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_apache_chroot();
    $self->_check_for_easyapache_build();
}

sub estimated_runtime {

    # These checks have to connect out to the cpanel mirrors to verify the current version
    return 5;
}

sub _check_for_apache_chroot {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( $security_advisor_obj->{'cpconf'}->{'jailapache'} ) {
        $security_advisor_obj->add_advice(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['Jailed Apache is enabled'],
            }
        );
    }
    elsif ( -x '/usr/bin/cagefsctl' ) {
        $security_advisor_obj->add_advice(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['CageFS is enabled'],
            }
        );
    }
    else {

        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['Apache vhosts are not chroot()ed.'],
                'suggestion' => [
                    (
                        $Cpanel::Version::MAJORVERSION > 11.37
                        ? 'Enable “Jail Apache” in the “[output,url,_1,Tweak Settings,_4,_5]” area, and change users to jailshell in the “[output,url,_2,Manage Shell Access,_4,_5]” area.  Consider a more robust solution by using “[output,url,_3,CageFS on CloudLinux,_4,_5]”'
                        : 'Upgrade to cPanel 11.38 or later, then enable “Jail Apache” in the “[output,url,_1,Tweak Settings,_4,_5]” area, and change users to jailshell in the “[output,url,_2,Manage Shell Access,_4,_5]” area.  Consider a more robust solution by using “[output,url,_3,CageFS on CloudLinux,_4,_5]”'

                    ),
                    '../scripts2/tweaksettings?find=jailapache',
                    '../scripts2/manageshells',
                    'http://cpanel.net/cpanel-whm/cloudlinux/',
                    'target',
                    '_blank'
                ],
            }
        );
    }

}

sub _check_for_easyapache_build {
    my $self                 = shift;
    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $cpsources          = Cpanel::Config::Sources::loadcpsources();
    my $ea_update_server   = defined $cpsources->{'EASOURCES'} ? $cpsources->{'EASOURCES'} : $cpsources->{'HTTPUPDATE'};
    my $httprequest_obj    = Cpanel::HttpRequest->new( 'hideOutput' => 1 );
    my $latest_ea3_version = '';
    eval { $latest_ea3_version = $httprequest_obj->request( 'host' => $ea_update_server, 'url' => '/cpanelsync/easy/version_easy', 'protocol' => 0, ); };
    chomp($latest_ea3_version);

    my $installed_version = Cpanel::SafeRun::Errors::saferunallerrors( '/usr/local/apache/bin/httpd', '-v' );
    $installed_version = $installed_version =~ /Cpanel::Easy::Apache v([\d.]+)/s ? $1 : '';

    if ( $latest_ea3_version && $installed_version && $latest_ea3_version ne $installed_version ) {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                'text'       => ['EasyApache3 has updates available.'],
                'suggestion' => [
                    '[output,url,_1,EasyApache3,_2,_3] needs to be run periodically to update Apache, PHP and other public server functionality to the latest versions. Updates to EasyApache3 often fix security vulnernabilities in this software.',
                    '../cgi/easyapache.pl?action=_pre_cpanel_sync_screen',
                    'target',
                    '_blank'
                ],
            }
        );
    }
}

1;
