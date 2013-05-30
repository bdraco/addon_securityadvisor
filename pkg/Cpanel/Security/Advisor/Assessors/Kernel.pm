package Cpanel::Security::Advisor::Assessors::Kernel;

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
use Cpanel::OSSys ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_kernel_version;
}

sub _check_for_kernel_version {
    my ($self) = @_;
    my ( $latest_kernelversion, $current_kernelversion );

    my $installed_rpms = $self->get_installed_rpms();
    my $available_rpms = $self->get_available_rpms();

    my $running_kernelversion = ( Cpanel::OSSys::uname() )[2];
    my $running_kernelversion_without_release = ( split( m/-/, $running_kernelversion ) )[0];

    my $current_kernelversion = $installed_rpms->{'kernel'};

    my $latest_kernelversion = $available_rpms->{'kernel'};
    my $latest_kernelversion_without_release = ( split( m/-/, $latest_kernelversion ) )[0];

    if ( length $current_kernelversion && length $latest_kernelversion ) {
        if ( $running_kernelversion_without_release ne $latest_kernelversion_without_release ) {
            $self->add_info_advice( 'text' => [ 'Custom kernel version cannot be checked to see if it is up to date: ' . $running_kernelversion ] );
        }
        elsif ( $current_kernelversion ne $latest_kernelversion ) {
            $self->add_bad_advice(
                'text'       => ["Current kernel version is out of date. current: $current_kernelversion, expected: $latest_kernelversion"],
                'suggestion' => [
                    'Update current system software in the "[output,url,_1,Update System Software,_2,_3]" area, and then reboot the system in the "[output,url,_4,Graceful Server Reboot,_5,_6]" area.',
                    '../scripts/dialog?dialog=updatesyssoftware',
                    'target',
                    '_blank',
                    '../scripts/dialog?dialog=reboot',
                    'target',
                    '_blank'
                ],
            );
        }
        elsif ( $running_kernelversion ne $latest_kernelversion ) {
            $self->add_bad_advice(
                'text'       => ["A newer kernel is installed, however the system has not been rebooted. running: $current_kernelversion, installed: $current_kernelversion"],
                'suggestion' => [
                    'Reboot the system in the "[output,url,_1,Graceful Server Reboot,_2,_3]" area.',
                    '../scripts/dialog?dialog=reboot',
                    'target',
                    '_blank'
                ],
            );
        }
        else {
            $self->add_good_advice( 'text' => [ 'Current running kernel version is up to date: ' . $current_kernelversion ] );
        }
    }
    else {
        $self->add_warn_advice( 'text' => ['Unable to determine kernel version'], 'suggestion' => ['Ensure that yum and rpm are working on your system.'] );
    }

}

1;
