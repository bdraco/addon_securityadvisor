package Cpanel::Security::Advisor::Assessors::Trojans;

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
use Cpanel::SafeFind ();
use base 'Cpanel::Security::Advisor::Assessors';

sub version {
    return '1.00';
}

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_libkeyutils();

    return 1;
}

sub _check_for_libkeyutils {
    my ($self) = @_;

    my @search_dirs = ('/lib');
    push @search_dirs, '/lib64' if -e '/lib64';

    Cpanel::SafeFind::find(
        {
            'wanted' => sub {
                if ( $File::Find::name =~ m/libkeyutils.so/ ) {
                    my $res = Cpanel::SafeRun::Simple::saferun( '/bin/rpm', '-qf', $File::Find::name );
                    chomp($res);

                    if ( $res =~ m/file.*is not owned by any package/ ) {
                        $self->add_bad_advice(
                            'text'       => [ "Libkeyutils check: “[_1]” is not owned by any system packages. This indicates a possible server compromise.", $File::Find::name ],
                            'suggestion' => [
                                'Check the following to determine if this server is compromised "[output,url,_1,Determine your Systems Status,_2,_3]"',
                                'http://docs.cpanel.net/twiki/bin/view/AllDocumentation/CompSystem',
                                'target',
                                '_blank'
                            ],
                        );
                    }
                }
            },
            'no_chdir' => 1,
        },
        @search_dirs,
    );

    return 1;

}

1;
