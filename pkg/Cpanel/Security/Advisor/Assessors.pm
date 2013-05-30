package Cpanel::Security::Advisor::Assessors;

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

our $VERISON = 1.1;

use Cpanel::SafeRun::Full    ();
use Cpanel::Version::Compare ();

sub new {
    my ( $class, $security_advisor_obj ) = @_;

    my $self = bless {
        'security_advisor_obj' => $security_advisor_obj,
        '_version'             => $VERISON
    }, $class;

    return $self;
}

sub add_advice {
    my ( $self, %opts ) = @_;

    $self->{'security_advisor_obj'}->add_advice( {%opts} );
}

sub add_good_advice {
    my ( $self, %opts ) = @_;

    $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_GOOD );
}

sub add_info_advice {
    my ( $self, %opts ) = @_;

    $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_INFO );
}

sub add_warn_advice {
    my ( $self, %opts ) = @_;

    $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_WARN );
}

sub add_bad_advice {
    my ( $self, %opts ) = @_;

    $self->add_advice( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_BAD );
}

sub get_available_rpms {
    my ($self) = @_;

    return $self->{'available_rpms'} if $self->{'available_rpms'};

    my $output = Cpanel::SafeRun::Full::run(
        'program' => Cpanel::FindBin::findbin('yum'),
        'args'    => [
            '-d', '0', 'list', 'all',
        ],
        'timeout' => 90,
    );

    if ( $output->{'status'} ) {
        $self->{'available_rpms'} = {
            map { m{\A(\S+)\.[^.\s]+\s+(\S+)} ? ( $1 => $2 ) : () }
              split( m/\n/, $output->{'stdout'} )
        };
    }

    return $self->{'available_rpms'};
}

sub get_installed_rpms {
    my ($self) = @_;

    return $self->{'installed_rpms'} if $self->{'installed_rpms'};

    my $output = Cpanel::SafeRun::Full::run(
        'program' => Cpanel::FindBin::findbin('rpm'),
        'args'    => [
            '-qa', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE}\n'
        ],
        'timeout' => 30,
    );

    if ( $output->{'status'} ) {
        my %installed;
        for my $line ( split( "\n", $output->{'stdout'} ) ) {
            chomp $line;
            my ( $rpm, $version ) = split( qr/\s+/, $line, 2 );
            if ( $installed{$rpm} ) {
                my ( $this_version,      $this_release )      = split( m/-/, $version,         2 );
                my ( $installed_version, $installed_release ) = split( m/-/, $installed{$rpm}, 2 );

                if (
                    Cpanel::Version::Compare::compare( $installed_version, '>', $this_version )
                    ||

                    ( $this_version eq $installed_version && Cpanel::Version::Compare::compare( $installed_release, '>', $this_release ) )
                  ) {
                    next;
                }
            }
            $installed{$rpm} = $version;
        }
        $self->{'installed_rpms'} = \%installed;
    }

    return $self->{'installed_rpms'};
}

1;
