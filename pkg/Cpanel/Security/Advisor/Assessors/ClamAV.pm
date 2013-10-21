package Cpanel::Security::Advisor::Assessors::ClamAV;

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
use warnings;
use Cpanel::FindBin         ();
use Cpanel::SafeRun::Errors ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;

    return 0 if $self->_check_clamav();

    return 1;
}

sub _check_clamav {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    $self->_find_clamav();

    if ( !$self->{clamav}{clamscan}{bin} && !$self->{clamav}{freshclam}{bin} ) {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['ClamAV is not installed.'],
                'suggestion' => [
                    'Install ClamAV within "[output,url,_1,Manage Plugins,_2,_3]".',
                    $self->base_path('scripts2/getthemes?modules=1'), 'target', '_blank',
                ],
            }
        );
    }
    elsif ( !$self->{clamav}{clamscan}{bin} ) {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => [q{ClamAV clamscan binary is not installed.}],
                'suggestion' => [
                    'Install ClamAV within "[output,url,_1,Manage Plugins,_2,_3]".',
                    $self->base_path('scripts2/getthemes?modules=1'), 'target', '_blank',
                ],
            }
        );
    }
    elsif ( !$self->{clamav}{freshclam}{bin} ) {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => [q{ClamAV freshclam binary is not installed.}],
                'suggestion' => [
                    'Install ClamAV within "[output,url,_1,Manage Plugins,_2,_3]".',
                    $self->base_path('scripts2/getthemes?modules=1'), 'target', '_blank',
                ],
            }
        );
    }
    else {
        $self->_get_clam_version();
        if ( $self->{clamav}{clamscan}{version} ne $self->{clamav}{freshclam}{version} ) {
            $security_advisor_obj->add_advice(
                {
                    'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                    'text'       => [q{ClamAV freshclam and clamscan binaries are different versions.}],
                    'suggestion' => [
                        'Install ClamAV within "[output,url,_1,Manage Plugins,_2,_3]".',
                        $self->base_path('scripts2/getthemes?modules=1'), 'target', '_blank',
                    ],
                }
            );
        }
    }
    return $self;
}

sub _find_clamav {
    my ($self) = @_;

    my @paths = qw{ /usr/local/cpanel/3rdparty/bin /usr/bin /usr/local/bin /bin /sbin /usr/sbin /usr/local/sbin };

    $self->{clamav}{clamscan}{bin}  = Cpanel::FindBin::findbin( 'clamscan',  'path' => @paths );
    $self->{clamav}{freshclam}{bin} = Cpanel::FindBin::findbin( 'freshclam', 'path' => @paths );

    return $self;
}

sub _get_clam_version {
    my ($self) = @_;

    chomp( my $version = Cpanel::SafeRun::Errors::saferunnoerror( $self->{clamav}{clamscan}{bin}, '-V' ) );
    if ( $version =~ /^ClamAV (\d\.\d{1,3}\.\d{1,2}\/\d{1,7})\/(.*)/m ) {
        $self->{clamav}{clamscan}{version}    = $1;
        $self->{clamav}{clamscan}{build_date} = $2;
    }
    chomp( $version = Cpanel::SafeRun::Errors::saferunnoerror( $self->{clamav}{freshclam}{bin}, '-V' ) );
    if ( $version =~ /^ClamAV (\d\.\d{1,3}\.\d{1,2}\/\d{1,7})\/(.*)/m ) {
        $self->{clamav}{freshclam}{version}    = $1;
        $self->{clamav}{freshclam}{build_date} = $2;
    }
    return $self;
}

1;
