package Cpanel::Security::Advisor::Assessors::Frontpage;

# cpanel - Cpanel/Security/Advisor/Assessors/PHP.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::SafeRun::Simple;

sub generate_advise {
    my ($self) = @_;
    $self->_is_frontpage_installed();
}

sub _is_frontpage_installed{

    my( $self ) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( -e '/usr/local/frontpage/version5.0/bin/owsadm.exe' ){
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text' => ['Frontpage is installed'],
                'suggestion' => [
                    '1. Rebuild EasyApache without Frontpage selected 2. Uninstall the Frontpage RPM (rpm -e frontpage)',
                ],
            }
        );
    }

}

1;
