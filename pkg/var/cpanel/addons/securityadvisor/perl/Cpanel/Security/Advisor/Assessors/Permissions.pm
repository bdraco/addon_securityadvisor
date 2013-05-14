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


    my %test_files = (
        '/etc/shadow' => { 'perms' => '0600', 'uid' => 0, 'gid' => 0 },
        '/etc/passwd' => { 'perms' => '0644', 'uid' => 0, 'gid' => 0 }
        );

    for my $file (keys %test_files) {
        my $mode = (stat($file))[2] & 07777;
        $mode = sprintf "%lo", $mode;
        my ($uid,$gid) = (stat($file))[4,5];


        if ($mode != $test_files{$file}->{'perms'} ) {
            $security_advisor_obj->add_advise(
                {
                    'type' => $Cpanel::Security::Advisor::ADVISE_WARN,
                    'text' => ["$file has non default permissions"],
                    'suggestion' => ["Review the permissions on $file to ensure they are safe"]
                }
            );
        }

        if ($uid != $test_files{$uid} or $gid != $test_files{$gid}) {
            $security_advisor_obj->add_advise(
                {
                    'type' => $Cpanel::Security::Advisor::ADVISE_WARN,
                    'text' => ["$file has non root user and/or group"],
                    'suggestion' => ["Review the ownership permissions on $file"]
                }
            );
        }
    }
}

1;
