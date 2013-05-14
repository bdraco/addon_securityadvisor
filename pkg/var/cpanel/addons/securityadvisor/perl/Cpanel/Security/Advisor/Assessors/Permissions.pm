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
    return if ( $^O ne 'linux' );

    my ($self) = @_;

    my %test_files = (
        '/etc/shadow' => { 'perms' => 0600, 'uid' => 0, 'gid' => 0 },
        '/etc/passwd' => { 'perms' => 0644, 'uid' => 0, 'gid' => 0 }
    );

    for my $file ( keys %test_files ) {
        my $expected_attributes = $test_files{$file};
        my ( $current_mode, $uid, $gid ) = ( stat($file) )[ 2, 4, 5 ];
        if ( ( $expected_attributes->{'perms'} & 07777 ) != ( $current_mode & 07777 ) ) {
            my $expected_mode = sprintf( "%04o", $expected_attributes->{'perms'} );
            my $actual_mode   = sprintf( "%04o", $current_mode & 07777 );
            $self->add_warn_advise(
                'text'       => ["$file has non default permissions.  Expected: $expected_mode, Actual: $actual_mode."],
                'suggestion' => ["Review the permissions on $file to ensure they are safe"]
            );
        }

        if ( $uid != $expected_attributes->{'uid'} or $gid != $expected_attributes->{'gid'} ) {
            $self->add_warn_advise(
                'text'       => ["$file has non root user and/or group"],
                'suggestion' => ["Review the ownership permissions on $file"]
            );
        }
    }
}

1;
