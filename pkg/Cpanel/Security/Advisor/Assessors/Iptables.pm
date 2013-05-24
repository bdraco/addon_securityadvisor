package Cpanel::Security::Advisor::Assessors::Iptables;

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
use Cpanel::SafeRun::Simple;

sub generate_advice {
    my ($self) = @_;
    $self->_is_iptables_active();
}

sub _is_iptables_active {

    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( -x '/etc/init.d/iptables' ) {
        my $status_check = `/etc/init.d/iptables status`;

        # need a better way to check this
        if ( $status_check =~ m/not running/i ) {
            $security_advisor_obj->add_advice(
                {
                    'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text'       => ['Firewall is not running'],
                    'suggestion' => [
                        'This might be a simple matter of executing "/etc/init.d/iptables start"'
                    ],
                },
            );
        }
    }
}

1;
