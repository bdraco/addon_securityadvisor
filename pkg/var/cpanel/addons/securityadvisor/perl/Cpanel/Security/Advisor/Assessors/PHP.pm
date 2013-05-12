package Cpanel::Security::Advisor::Assessors::PHP;

# cpanel - Cpanel/Security/Advisor/Assessors/PHP.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_php_running_as_nobody();
}

sub _check_for_php_running_as_nobody {

    # unimplemented

}

1;
