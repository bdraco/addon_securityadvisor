package Cpanel::Security::Advisor::Assessors::Brute;

# cpanel - Cpanel/Security/Advisor/Assessors/Brute.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use Cpanel::Config::Hulk ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_brute_force_protection();
}

sub _check_for_brute_force_protection {
    my ($self) = @_;

    my $cphulk_enabled = Cpanel::Config::Hulk::is_enabled();

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ($cphulk_enabled) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['cPHulk Brute Force Protection is enabled.'],
            }
        );

    }
    elsif ( -e "/etc/csf" ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['CSF is installed'],
            }
        );

    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['No brute force protection detected'],
                'suggestion' => [
                    'Enable cPHulk Brute Force Protection in the “[output,url,_1,cPHulk Brute Force Protection,_2,_3]” area.',
                    $security_advisor_obj->security_token()
                      . "/cgi/tweakcphulk.cgi",
                    'target',
                    '_blank'

                ],
            }
        );
    }

}

1;
