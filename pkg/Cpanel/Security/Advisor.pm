package Cpanel::Security::Advisor;

# Copyright (c) 2016, cPanel, Inc.
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

=pod

=encoding utf-8

=head1 NAME

Cpanel::Security::Advisor - cPanel Security Advisor

=head1 SYNOPSYS

    my $comet = Cpanel::Comet::Mock->new();

    Cpanel::LoadModule::load_perl_module('Cpanel::Security::Advisor');
    my $advisor = Cpanel::Security::Advisor->new( 'comet' => $comet, 'channel' => $CHANNEL );

    my ( $merged, @result ) = Capture::Tiny::capture_merged(
        sub {
            $advisor->generate_advice();
        }
    );

    my $msgs = $comet->get_messages($CHANNEL);
    foreach my $msg ( @{$msgs} ) {
        my $msg_ref = Cpanel::AdminBin::Serializer::Load($msg);

        ....

    }

=cut

use strict;

our $VERSION = 1.03;

use Cpanel::Config::LoadCpConf ();
use Cpanel::Logger             ();
use Cpanel::JSON               ();
use Cpanel::Locale             ();

our $ADVISE_GOOD = 1;
our $ADVISE_INFO = 2;
our $ADVISE_WARN = 4;
our $ADVISE_BAD  = 8;

=head1 ADVISE TYPES

=head2 ADVISE_GOOD

=over

Changes DO NOT send iContact notices

=back

All is well

=head2 ADVISE_INFO

=over

Changes send iContact notices for 11.56.0.14 and below, Changes DO NOT send iContact notices for 11.56.0.15 and above

=back

For items that may not be be actionable soon but should know about.
If there is uncertainty if the admin has control over the item or
if we have less than 90% confidence that its not a false positive.

=head2 ADVISE_WARN

=over

Changes send iContact notices

=back

For items that should be actioned soon.  These should be
95% confidence or better that it is not a false positive.

=head2 ADVISE_BAD

=over

Changes send iContact notices

=back

For items that should be actioned now.  These should be 99%
confidence or better that it is not a false positive.

=cut

sub new {
    my ( $class, %options ) = @_;

    die "No comet object provided"  unless ( $options{'comet'} );
    die "No comet channel provided" unless ( $options{'channel'} );

    my %all_modules;
    foreach my $dir ( '/usr/local/cpanel/Cpanel/Security/Advisor/Assessors', '/var/cpanel/addons/securityadvisor/perl/Cpanel/Security/Advisor/Assessors' ) {
        if ( opendir( my $advisor_module_dir, $dir ) ) {
            foreach my $mod ( readdir($advisor_module_dir) ) {
                next if $mod !~ m/\.pm$/;
                $all_modules{$mod} = 1;
            }
            closedir($advisor_module_dir);
        }
    }
    my @modules = sort keys %all_modules;
    my @assessors;

    my $self = bless {
        'assessors' => \@assessors,
        'logger'    => Cpanel::Logger->new(),
        'cpconf'    => scalar Cpanel::Config::LoadCpConf::loadcpconf(),
        '_version'  => $VERSION,
        '_cache'    => {},
        'comet'     => $options{'comet'},
        'channel'   => $options{'channel'},
        'locale'    => Cpanel::Locale->get_handle(),
    }, $class;

    foreach my $module (@modules) {
        my $module_name = $module;
        $module_name =~ s/(.*)\.pm$/Cpanel::Security::Advisor::Assessors::$1/g;

        eval "require $module_name;";
        if ($@) {
            $self->{'logger'}->warn("Failed to load $module_name: $@");
            $self->_internal_message( { type => 'mod_load', state => 0, module => $module_name, message => "$@" } );
            next;
        }
        my $object = eval { "$module_name"->new($self); };
        if ($@) {
            $self->{'logger'}->warn("Failed to new $module_name: $@");
            $self->_internal_message( { type => 'mod_load', state => 0, module => $module_name, message => "$@" } );
            next;
        }

        push @assessors, { name => $module_name, object => $object };
        my $runtime = ( $object->can('estimated_runtime') ? $object->estimated_runtime() : 1 );
        $self->_internal_message( { type => 'mod_load', state => 1, module => $module_name, runtime => $runtime } );
    }

    return $self;
}

sub generate_advice {
    my ($self) = @_;

    $self->_internal_message( { type => 'scan_run', state => 0 } );
    foreach my $mod ( @{ $self->{'assessors'} } ) {
        my $module         = $mod->{'name'};
        my $version_ref    = "$module"->can('version');
        my $module_version = $version_ref ? $version_ref->() : '';

        $self->_internal_message( { type => 'mod_run', state => 0, module => $mod->{name}, 'version' => $module_version } );
        eval { $mod->{object}->generate_advice(); };
        $self->_internal_message( { type => 'mod_run', state => ( $@ ? -1 : 1 ), module => $mod->{name}, message => "$@", 'version' => $module_version } );
    }
    $self->_internal_message( { type => 'scan_run', state => 1 } );
    $self->{'comet'}->purgeclient();
    return;
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
    return;
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
    return;
}

sub expand_advice_maketext {
    my ( $self, $advice ) = @_;
    foreach my $param (qw(text suggestion)) {
        next unless defined $advice->{$param};
        $advice->{$param} = $self->{'locale'}->maketext( ref $advice->{$param} eq 'ARRAY' ? @{ $advice->{$param} } : $advice->{$param} );
    }

    return;
}

1;
