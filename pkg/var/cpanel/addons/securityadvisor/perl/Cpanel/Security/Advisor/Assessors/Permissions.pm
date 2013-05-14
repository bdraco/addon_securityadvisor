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

    my @files = qw( /etc/shadow /etc/passwd );

    for my $file (@files) {
        my $mode = (stat($file))[2];

        # Warn if /etc/shadow is world readable, world writable, or world executable,
        # or if /etc/passwd is world writable
        if (($file eq '/etc/shadow' and $mode & 007) or ($file eq '/etc/passwd' and $mode & 002)) {
            $security_advisor_obj->add_advise(
                {
                    'type' => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text' => ["$file has unsafe permissions"],
                    'suggestion' => ["Reset the permissions on $file"]
                }
            );
        }

        # Warn if /etc/shadow or /etc/passwd aren't root.root
        my ($uid, $gid) = (stat($file))[4,5];

        if ($uid != 0 or $gid != 0) {
            $security_advisor_obj->add_advise(
                {
                    'type' => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text' => ["$file is owned by a user and/or group which is not root"],
                    'suggestion' => ["Reset the ownership permissions on $file"]
                }
            );
        }
    }
}

1;
