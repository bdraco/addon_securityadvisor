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

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_apache_chroot();
}

sub _check_for_apache_chroot {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( $security_advisor_obj->{'cpconf'}->{'jailapache'} ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['Jailed Apache is enabled'],
            }
        );
    }
    elsif ( -x '/usr/bin/cagefsctl' ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['CageFS is enabled'],
            }
        );
    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['Apache vhosts are not chroot()ed.'],
                'suggestion' => [
                    'Enable “Jail Apache” in the “[output,url,_1,Tweak Settings,_4,_5]” area, and change users to jailshell in the “[output,url,_2,Manage Shell Access,_4,_5]” area.  Consider a more robust solution by using “[output,url,_3,CageFS on CloudLinux,_4,_5]”',
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

1;
