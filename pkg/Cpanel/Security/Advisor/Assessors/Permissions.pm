package Cpanel::Security::Advisor::Assessors::Permissions;

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
            $self->add_warn_advice(
                'text'       => ["$file has non default permissions.  Expected: $expected_mode, Actual: $actual_mode."],
                'suggestion' => ["Review the permissions on $file to ensure they are safe"]
            );
        }

        if ( $uid != $expected_attributes->{'uid'} or $gid != $expected_attributes->{'gid'} ) {
            $self->add_warn_advice(
                'text'       => ["$file has non root user and/or group"],
                'suggestion' => ["Review the ownership permissions on $file"]
            );
        }
    }
}

1;
