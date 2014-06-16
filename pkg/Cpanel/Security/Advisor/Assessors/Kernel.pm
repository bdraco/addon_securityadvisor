package Cpanel::Security::Advisor::Assessors::Kernel;

# Copyright (c) 2014, cPanel, Inc.
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
use Cpanel::SafeRun::Errors ();
use Cpanel::OSSys           ();
use Cpanel::OSSys::Env      ();

sub version {
    return '1.01.2';
}

sub generate_advice {
    my ($self) = @_;
    $self->_check_for_kernel_version;

    return 1;
}

sub _check_for_kernel_version {
    my ($self) = @_;

    my %kernel_update = kernel_updates();
    my @kernel_update = ();
    if ( ( keys %kernel_update ) ) {
        foreach my $update ( keys %kernel_update ) {
            unshift( @kernel_update, $kernel_update{$update} );
        }
    }

    my $latest_kernelversion  = installed_kernels();
    my $running_kernelversion = ( Cpanel::OSSys::uname() )[2];
    $running_kernelversion =~ s/\.(?:noarch|x86_64|i.86)$//;

    if ( ( ( ( Cpanel::OSSys::uname() )[2] ) =~ m/\.(?:noarch|x86_64|i.86).+$/ ) ) {
        $self->add_info_advice( 'text' => [ 'Custom kernel version cannot be checked to see if it is up to date: [_1]', $running_kernelversion ] );
    }
    elsif ( Cpanel::OSSys::Env::get_envtype() eq 'virtuozzo' ) {
        $self->add_info_advice( 'text' => ['Kernel updates are not supported on this virtualization platform. Be sure to keep the host’s kernel up to date.'] );
    }
    elsif ( (@kernel_update) ) {
        $self->add_bad_advice(
            'text' => [
                'Current kernel version is out of date. running kernel: [_1], most recent kernel: [list_and,_2]',
                $running_kernelversion,
                \@kernel_update,
            ],
            'suggestion' => ['Update the system’s software by running ’yum update’ from the command line and reboot the system.'],
        );
    }
    elsif ( ( $running_kernelversion ne $latest_kernelversion ) ) {
        $self->add_bad_advice(
            'text' => [
                'A newer kernel is installed, however the system has not been rebooted. running kernel: [_1], most recent installed kernel: [_2]',
                $running_kernelversion,
                $latest_kernelversion
            ],
            'suggestion' => [
                'Reboot the system in the "[output,url,_1,Graceful Server Reboot,_2,_3]" area.
                Check the boot configuration in grub.conf if the new kernel is not loaded after a reboot.',
                $self->base_path('scripts/dialog?dialog=reboot'),
                'target',
                '_blank'
            ],
        );
    }
    elsif ( ( ( $running_kernelversion eq $latest_kernelversion ) && !(@kernel_update) ) ) {
        $self->add_good_advice( 'text' => [ 'Current running kernel version is up to date: [_1]', $running_kernelversion ] );
    }
    else {
        $self->add_warn_advice( 'text' => ['Unable to determine kernel version'], 'suggestion' => ['Ensure that yum and rpm are working on your system.'] );
    }

    return 1;
}

sub kernel_updates {
    my %kernel_update;
    my @args         = qw(yum -d 0 info updates kernel);
    my @yum_response = Cpanel::SafeRun::Errors::saferunnoerror(@args);
    my ( $rpm, $version, $release );

    foreach my $element ( 0 .. $#yum_response ) {
        $rpm     = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Name/ ) );
        $version = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Version/ ) );
        $release = ( split( /:/, $yum_response[$element] ) )[1] if ( ( $yum_response[$element] =~ m/^Release/ ) );
        if ( ( ($rpm) && ($version) && ($release) ) ) {
            s/\s//g foreach ( $rpm, $version, $release );
            $kernel_update{ $rpm . " " . $version . "-" . $release } = $version . "-" . $release;
            $rpm                                                     = undef;
            $version                                                 = undef;
            $release                                                 = undef;
        }
    }
    return %kernel_update;
}    # end of sub

sub installed_kernels {
    my %installed_kernels;
    my $recent_kernel;
    my $recent_buildtime = 0;
    my @args             = ( 'rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE} %{BUILDTIME}\n', 'kernel' );
    my @rpm_response     = Cpanel::SafeRun::Errors::saferunnoerror(@args);
    if (@rpm_response) {
        foreach my $version_check (@rpm_response) {
            my ( $rpm, $version, $buildtime ) = split( qr/\s+/, $version_check );
            if ( ($rpm) && ($version) && ( $version =~ m/\d/ ) && ($buildtime) ) {
                $installed_kernels{$version} = $buildtime;
            }    # End valid version
        }    # next rpm and version to check
    }    # end of if rpm_response
    foreach my $version ( keys %installed_kernels ) {
        if ( ( $installed_kernels{$version} > $recent_buildtime ) ) {
            $recent_kernel    = $version;
            $recent_buildtime = $installed_kernels{$version};
        }
    }
    return $recent_kernel;
}

1;

__END__
