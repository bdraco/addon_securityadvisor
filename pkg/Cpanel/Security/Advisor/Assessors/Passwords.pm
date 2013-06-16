package Cpanel::Security::Advisor::Assessors::Passwords;

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

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_low_pwstrength;
}

sub _check_for_low_pwstrength {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( !$security_advisor_obj->{'cpconf'}->{'minpwstrength'} || $security_advisor_obj->{'cpconf'}->{'minpwstrength'} < 25 ) {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['Trivially weak passwords are permitted.'],
                'suggestion' => [
                    'Configure Password Strength requirements in the “[output,url,_1,Password Strength Configuration,_2,_3]” area',
                    $self->base_path('scripts/minpwstrength'),
                    'target',
                    '_blank'
                ],
            }
        );

    }
    elsif ( $security_advisor_obj->{'cpconf'}->{'minpwstrength'} < 50 ) {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                'text'       => ['Password strength requirements are low.'],
                'suggestion' => [
                    'Configure a Default Password Strength of at least 50 in the “[output,url,_1,Password Strength Configuration,_2,_3]” area',
                    $self->base_path('scripts/minpwstrength'),
                    'target',
                    '_blank'
                ],
            }
        );

    }
    elsif ( $security_advisor_obj->{'cpconf'}->{'minpwstrength'} < 65 ) {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_INFO,
                'text'       => ['Password strength requirements are moderate.'],
                'suggestion' => [
                    'Configure a Default Password Strength of at least 65 in the “[output,url,_1,Password Strength Configuration,_2,_3]” area',
                    $self->base_path('scripts/minpwstrength'),
                    'target',
                    '_blank'
                ],
            }
        );

    }
    else {
        $security_advisor_obj->add_advice(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['Password strength requirements are strong.'],
            }
        );
    }

}

1;
