#!/bin/sh
eval 'if [ -x /usr/local/cpanel/3rdparty/bin/perl ]; then exec /usr/local/cpanel/3rdparty/bin/perl -x -- $0 ${1+"$@"}; else exec /usr/bin/perl -x $0 ${1+"$@"}; fi;'    ## no critic qw(ProhibitStringyEval RequireUseStrict) -*-mode:perl-*-
  if 0;

#!/usr/bin/perl
#WHMADDON:addonupdates:Security Advisor Tool
#ACLS:all

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

package cgi::addon_securityadvisor;

use strict;

BEGIN {
    unshift @INC, '/var/cpanel/addons/securityadvisor/perl', '/usr/local/cpanel';
}

use Whostmgr::ACLS          ();
use Whostmgr::HTMLInterface ();
use Cpanel::Form            ();
use Cpanel::Template        ();
use Cpanel::Comet           ();
use Cpanel::Rlimit          ();
use Cpanel::Encoder::URI    ();
use POSIX                   ();

# from /var/cpanel/addons/securityadvisor/perl
use Cpanel::Security::Advisor ();

run(@ARGV) unless caller();

sub run {
    _check_acls();
    my $form = Cpanel::Form::parseform();
    if ( $form->{'start_scan'} ) {
        _start_scan( $form->{'channel'} );
        exit;
    }
    else {
        _headers("text/html");

        my $template_file =
          -e '/var/cpanel/addons/securityadvisor/templates/main.tmpl'
          ? '/var/cpanel/addons/securityadvisor/templates/main.tmpl'
          : '/usr/local/cpanel/whostmgr/docroot/templates/securityadvisor/main.tmpl';

        Cpanel::Template::process_template(
            'whostmgr',
            {
                'template_file'            => $template_file,
                'security_advisor_version' => $Cpanel::Security::Advisor::VERSION,
            },
        );
    }

    return 1;
}

sub _check_acls {
    Whostmgr::ACLS::init_acls();

    if ( !Whostmgr::ACLS::hasroot() ) {
        _headers('text/html');
        Whostmgr::HTMLInterface::defheader('cPanel Security Advisor');
        print <<'EOM';
<br />
<br />
<div align="center"><h1>Permission denied</h1></div>
</body>
</html>
EOM
        exit;
    }
}

sub _headers {
    my $content_type = shift;

    print "Content-type: ${content_type}; charset=utf-8\r\n\r\n";

    return 1;
}

# Start a new scan writing to the comet channel specified
sub _start_scan {
    Cpanel::Rlimit::set_rlimit_to_infinity();    # we need to run yum :)

    my $channel = shift;
    _headers('text/json');

    if ( !$channel ) {
        print qq({"status":0,"message":"No scan channel was specified."}\n);
        return;
    }
    if ( $channel !~ m{\A[/A-Za-z_0-9]+\z} ) {
        print qq({"status":0,"message":"Invalid channel name."}\n);
        return;
    }

    my $comet = Cpanel::Comet->new();
    if ( !$comet->subscribe($channel) ) {
        print qq({"status":0,"message":"Failed to subscribe to channel."}\n);
        return;
    }

    my $pid = fork();
    if ( !defined $pid ) {
        print qq({"status":0,"message":"Failed to fork scanning subprocess."}\n);
        return;
    }
    elsif ($pid) {
        print qq({"status":1,"message":"Scan started."}\n);
        return;
    }
    else {
        POSIX::setsid();
        open STDOUT, ">&STDERR" or die "Could not redirect STDOUT to STDERR";
        open STDIN, "<", "/dev/null" or die "Could not attach STDIN to /dev/null";
        my $advisor = Cpanel::Security::Advisor->new( 'comet' => $comet, 'channel' => $channel );

        $advisor->generate_advice();
        exit;
    }
}

