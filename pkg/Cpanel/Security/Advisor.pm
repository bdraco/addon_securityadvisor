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
use Cpanel::JSON               ();
use Cpanel::Locale             ();

our $ADVISE_GOOD = 1;
our $ADVISE_INFO = 2;
our $ADVISE_WARN = 4;
our $ADVISE_BAD  = 8;

sub new {
    my ( $class, %options ) = @_;

    die "No comet object provided"  unless ( $options{'comet'} );
    die "No comet channel provided" unless ( $options{'channel'} );

    opendir( my $advisor_module_dir, "/var/cpanel/addons/securityadvisor/perl/Cpanel/Security/Advisor/Assessors" );
    my @modules = sort grep { m/\.pm$/ } readdir($advisor_module_dir);
    closedir($advisor_module_dir);

    my @assessors;

    my $self = bless {
        'assessors' => \@assessors,
        'logger'    => Cpanel::Logger->new(),
        'cpconf'    => scalar Cpanel::Config::LoadCpConf::loadcpconf(),
        '_version'  => $VERISON,
        'comet'     => $options{'comet'},
        'channel'   => $options{'channel'},
        'locale'    => Cpanel::Locale->get_handle(),
    }, $class;

    foreach my $module (@modules) {
        my $module_name = $module;
        $module_name =~ s/(.*)\.pm$/Cpanel::Security::Advisor::Assessors::$1/g;
        my $object;
        eval "require $module_name; \$object = $module_name->new(\$self);";
        if ( !$@ ) {
            push @assessors, { name => $module_name, object => $object };
            my $runtime = ( $object->can('estimated_runtime') ? $object->estimated_runtime() : 1 );
            $self->_internal_message( { type => 'mod_load', state => 1, module => $module_name, runtime => $runtime } );
        }
        else {
            $self->_internal_message( { type => 'mod_load', state => 0, module => $module_name, message => "$@" } );
        }
    }

    return $self;
}

sub generate_advice {
    my ($self) = @_;

    $self->_internal_message( { type => 'scan_run', state => 0 } );
    foreach my $mod ( @{ $self->{'assessors'} } ) {
        $self->_internal_message( { type => 'mod_run', state => 0, module => $mod->{name} } );
        eval { $mod->{object}->generate_advice(); };
        $self->_internal_message( { type => 'mod_run', state => ( $@ ? -1 : 1 ), module => $mod->{name}, message => "$@" } );
    }
    $self->_internal_message( { type => 'scan_run', state => 1 } );
    $self->{'comet'}->purgeclient();
}

sub _internal_message {
    my ( $self, $data ) = @_;
    $self->{'comet'}->add_message(
        $self->{'channel'},
        Cpanel::JSON::Dump(
            {
                channel => $self->{'channel'},
                data    => $data
            }
        ),
    );
}

sub add_advice {
    my ( $self, $advice ) = @_;

    my $caller = ( caller(1) )[3];
    $caller =~ /(.+)::([^:]+)$/;

    my $module   = $1;
    my $function = $2;
    $self->expand_advice_maketext($advice);
    $self->{'comet'}->add_message(
        $self->{'channel'},
        Cpanel::JSON::Dump(
            {
                channel => $self->{'channel'},
                data    => {
                    type     => 'mod_advice',
                    module   => $module,
                    function => $function,
                    advice   => $advice,
                }
            }
        ),
    );
}

sub expand_advice_maketext {
    my ( $self, $advice ) = @_;
    foreach my $param (qw(text suggestion)) {
        next unless defined $advice->{$param};
        $advice->{$param} = $self->{'locale'}->maketext( ref $advice->{$param} eq 'ARRAY' ? @{ $advice->{$param} } : $advice->{$param} );
    }
}

1;
