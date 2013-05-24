package Cpanel::Security::Advisor;

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

our $VERISON = 1.0;

use Cpanel::Config::LoadCpConf ();
use Cpanel::Logger             ();

our $ADVISE_GOOD = 1;
our $ADVISE_INFO = 2;
our $ADVISE_WARN = 4;
our $ADVISE_BAD  = 8;

sub new {
    my ($class) = @_;

    opendir( my $advisor_module_dir, "/var/cpanel/addons/securityadvisor/perl/Cpanel/Security/Advisor/Assessors" );
    my @modules = sort grep { m/\.pm$/ } readdir($advisor_module_dir);
    closedir($advisor_module_dir);

    my @assessors;

    my $self = bless {
        'assessors' => \@assessors,
        'logger'    => Cpanel::Logger->new(),
        'cpconf'    => scalar Cpanel::Config::LoadCpConf::loadcpconf(),
        '_version'  => $VERISON,
    }, $class;

    foreach my $module (@modules) {
        my $module_name = $module;
        $module_name =~ s/\.pm$//g;
        eval "require Cpanel::Security::Advisor::Assessors::$module_name;";
        if ( !$@ ) {
            push @assessors, "Cpanel::Security::Advisor::Assessors::$module_name"->new($self);
        }
        else {
            $self->{'logger'}->warn("Failed to load Cpanel::Security::Advisor::Assessors::$module_name: $@");
        }
    }

    return $self;
}

sub generate_advice {
    my ($self) = @_;

    $self->{'advice'} = {};

    foreach my $mod ( @{ $self->{'assessors'} } ) {
        $mod->generate_advice();
    }

    return $self->{'advice'};
}

sub add_advice {
    my ( $self, $advice ) = @_;

    my $function = ( split( m{::}, ( caller(1) )[3] ) )[-1];
    push @{ $self->{'advice'}->{ ( caller(1) )[0] }->{$function} }, $advice;
}

1;
