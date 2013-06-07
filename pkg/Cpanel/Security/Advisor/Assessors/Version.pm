package Cpanel::Security::Advisor::Assessors::Version;

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
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::Version         ();
use Cpanel::Config::Sources ();
use Cpanel::HttpRequest     ();
use Cpanel::Update::Config  ();

sub generate_advice {
    my ($self) = @_;
    $self->_check_cpanel_version();
}

sub _check_cpanel_version {
    my $self = shift;

    my $cpsources       = Cpanel::Config::Sources::loadcpsources();
    my $update_server   = defined $cpsources->{'HTTPUPDATE'} ? $cpsources->{'HTTPUPDATE'} : 'http://httpupdate.cpanel.net/';
    my $httprequest_obj = Cpanel::HttpRequest->new( 'hideOutput' => 1 );

    my $config          = Cpanel::Update::Config::load;
    my $current_tier    = $config->{'CPANEL'};
    my $current_version = Cpanel::Version::get_version_full();

    my $latest_version = '';
    eval { $latest_version = $httprequest_obj->request( 'host' => $update_server, 'url' => '/cpanelsync/TIERS', 'protocol' => 0, ); };
    chomp($latest_version);
    $latest_version =~ /$current_tier:([0-9.]+)/;
    $latest_version = $1;

    if ( $current_version lt $latest_version ) {
        $self->add_bad_advice(
            'text'       => ["Current cPanel version is out of date. Current: $current_version, latest: $latest_version"],
            'suggestion' => [
                'Update cPanel software in the "[output,url,_1,Upgrade to Latest Version,_2,_3]" area',
                '../scripts2/upcpform',
                'target',
                'blank'
            ],
        );
    }
    elsif ( $current_version ge $latest_version ) {
        $self->add_good_advice(
            'text' => [ "Current cPanel version is up to date: " . $current_version ],
        );
    }
}

1;
