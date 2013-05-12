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

1;
