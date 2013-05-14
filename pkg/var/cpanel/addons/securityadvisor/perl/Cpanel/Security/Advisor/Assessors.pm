package Cpanel::Security::Advisor::Assessors;

# cpanel - Cpanel/Security/Advisor/Assessors.pm             Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;

our $VERISON = 1.0;

sub new {
    my ( $class, $security_advisor_obj ) = @_;

    my $self = bless {
        'security_advisor_obj' => $security_advisor_obj,
        '_version'             => $VERISON
    }, $class;

    return $self;
}

sub add_advise {
    my ( $self, %opts ) = @_;

    $self->{'security_advisor_obj'}->add_advise( {%opts} );
}

sub add_good_advise {
    my ( $self, %opts ) = @_;

    $self->add_advise( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_GOOD );
}

sub add_info_advise {
    my ( $self, %opts ) = @_;

    $self->add_advise( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_INFO );
}

sub add_warn_advise {
    my ( $self, %opts ) = @_;

    $self->add_advise( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_WARN );
}

sub add_bad_advise {
    my ( $self, %opts ) = @_;

    $self->add_advise( %opts, 'type' => $Cpanel::Security::Advisor::ADVISE_BAD );
}

1;
