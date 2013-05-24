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

our $VERISON = 1.0;

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

1;
