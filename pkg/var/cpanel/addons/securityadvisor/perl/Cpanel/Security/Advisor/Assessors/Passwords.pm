package Cpanel::Security::Advisor::Assessors::Passwords;

# cpanel - Cpanel/Security/Advisor/Assessors/Passwords.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_low_pwstrength;
}

sub _check_for_low_pwstrength {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( !$security_advisor_obj->{'cpconf'}->{'minpwstrength'} || $security_advisor_obj->{'cpconf'}->{'minpwstrength'} < 25 ) {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['Trivially weak passwords are permitted.'],
                'suggestion' => [
                    'Configure Password Strength requirements in the “[output,url,_1,Password Strength Configuration,_2,_3]” area',
                    $security_advisor_obj->security_token() . "/scripts/minpwstrength",
                    'target',
                    '_blank'
                ],
            }
        );

    }
    elsif ( $security_advisor_obj->{'cpconf'}->{'minpwstrength'} < 50 ) {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                'text'       => ['Password strength requirements are low.'],
                'suggestion' => [
                    'Configure a Default Password Strength of at least 50 in the “[output,url,_1,Password Strength Configuration,_2,_3]” area',
                    $security_advisor_obj->security_token() . "/scripts/minpwstrength",
                    'target',
                    '_blank'
                ],
            }
        );

    }
    elsif ( $security_advisor_obj->{'cpconf'}->{'minpwstrength'} < 65 ) {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_INFO,
                'text'       => ['Password strength requirements are moderate.'],
                'suggestion' => [
                    'Configure a Default Password Strength of at least 65 in the “[output,url,_1,Password Strength Configuration,_2,_3]” area',
                    $security_advisor_obj->security_token() . "/scripts/minpwstrength",
                    'target',
                    '_blank'
                ],
            }
        );

    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['Password strength requirements are strong.'],
            }
        );
    }

}

1;
