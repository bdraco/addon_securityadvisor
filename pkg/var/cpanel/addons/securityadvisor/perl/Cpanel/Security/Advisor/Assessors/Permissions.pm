package Cpanel::Security::Advisor::Assessors::Permissions;

# cpanel - Cpanel/Security/Advisor/Assessors/Permissions.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_unsafe_permissions();
}

sub _check_for_unsafe_permissions {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $mode = (stat('/etc/shadow'))[2];
    if ( $mode & 007 ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text' => ['/etc/shadow has unsafe permissions'],
                'suggestion' => ['Reset the permissions on /etc/shadow']
            }
        );
    }
}

1;
