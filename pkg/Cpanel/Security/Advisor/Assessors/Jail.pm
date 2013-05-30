package Cpanel::Security::Advisor::Assessors::Jail;

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
use Cpanel::Config::LoadCpConf ();
use Cpanel::PwCache            ();
use Cpanel::Config::Users      ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_unjailed_users();
}

sub _check_for_unjailed_users {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( !-x '/usr/bin/cagefsctl' ) {
        if ( -e '/var/cpanel/conf/jail/flags/mount_usr_bin_suid' ) {
            $security_advisor_obj->add_advice(
                {
                    'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text'       => ['Jailshell is mounting /usr/bin suid, which allows escaping the jail via crontab.'],
                    'suggestion' => [
                        'Disable “Jailed /usr/bin mounted suid" in the “[output,url,_1,Tweak Settings,_2,_3]” area',
                        "../scripts2/tweaksettings?find=jailmountusrbinsuid",
                        'target',
                        '_blank'
                    ],
                }
            );
        }

        Cpanel::PwCache::init_passwdless_pwcache();
        my %cpusers = map { $_ => undef } Cpanel::Config::Users::getcpusers();

        my $pwcache_ref = Cpanel::PwCache::fetch_pwcache();
        my @users_without_jail = map { $_->[0] } grep { exists $cpusers{ $_->[0] } && $_->[8] && $_->[8] !~ m{(?:no|jail)shell} } @$pwcache_ref;    #aka users without jail or noshell

        if ( scalar @users_without_jail > 100 ) {
            splice( @users_without_jail, 100 );
            push @users_without_jail, '..truncated..';
        }

        if (@users_without_jail) {
            $security_advisor_obj->add_advice(
                {
                    'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                    'text'       => [ 'Users running outside of the jail: [list_and,_1].', \@users_without_jail ],
                    'suggestion' => [
                        'Change these users to jailshell or noshell in the “[output,url,_1,Manage Shell Access,_2,_3]” area.',
                        '../scripts2/manageshells',
                        'target',
                        '_blank'

                    ],
                }
            );
        }
    }

}

1;
