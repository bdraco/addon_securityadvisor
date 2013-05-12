package Cpanel::Security::Advisor;

# cpanel - Cpanel/Security/Advisor.pm             Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;

our $VERISON = 1.0;

use Cpanel::Config::LoadCpConf ();
use Cpanel::Logger             ();

our $ADVISE_GOOD = 1;
our $ADVISE_WARN = 2;
our $ADVISE_BAD  = 4;
our $ADVISE_INFO = 8;

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

sub generate_advise {
    my ($self) = @_;

    $self->{'advise'} = {};

    foreach my $mod ( @{ $self->{'assessors'} } ) {
        $mod->generate_advise();
    }

    return $self->{'advise'};
}

sub add_advise {
    my ( $self, $advise ) = @_;

    my $function = ( split( m{::}, ( caller(1) )[3] ) )[-1];

    push @{ $self->{'advise'}->{ ( caller(1) )[0] }->{$function} }, $advise;
}

sub security_token {
    return ( $ENV{'cp_security_token'} || '' );
}

1;
