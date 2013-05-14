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
    return if ($^O ne 'linux');

    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    # Warn if /etc/shadow is world readable, world writeable, or world executable
    my $mode = (stat('/etc/shadow'))[2];
    if ($mode & 007) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text' => ['/etc/shadow has unsafe permissions'],
                'suggestion' => ['Reset the permissions on /etc/shadow']
            }
        );
    }

    # Warn if /etc/shadow has a user or group which is not root
    my ($uid, $gid) = (stat('/etc/shadow'))[4,5];

    if ($uid != 0 or $gid != 0) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text' => ['/etc/shadow is owned by a user and/or group which is not root'],
                'suggestion' => ['Reset the ownership permissions on /etc/shadow']
            }
        );
    }
}

1;
