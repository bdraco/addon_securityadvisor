#!/bin/sh
eval 'if [ -x /usr/local/cpanel/3rdparty/bin/perl ]; then exec /usr/local/cpanel/3rdparty/bin/perl -x -- $0 ${1+"$@"}; else exec /usr/bin/perl -x $0 ${1+"$@"}; fi;'
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

BEGIN {
    unshift @INC, '/var/cpanel/addons/securityadvisor/perl', '/usr/local/cpanel';

    # can go away after rt 85588 is in place
    require Cpanel::Locale;
    no warnings 'once';
    *Cpanel::Locale::makevar = sub {
        return shift->maketext( ref $_[0] ? @{ $_[0] } : @_ );    ## no extract maketext
    };
}

use Whostmgr::ACLS          ();
use Whostmgr::HTMLInterface ();
use Cpanel::Form            ();
use Cpanel::Template        ();

# from /var/cpanel/addons/securityadvisor/perl
use Cpanel::Security::Advisor ();

run(@ARGV) unless caller();

sub run {
    print _headers();
    _check_acls();

    my $form = Cpanel::Form::parseform();

    my $advisor = Cpanel::Security::Advisor->new();

    my $advice = $advisor->generate_advice();

    Cpanel::Template::process_template(
        'whostmgr',
        {
            'template_file' => '/var/cpanel/addons/securityadvisor/templates/main.tmpl',
            'data'          => {
                'form'   => $form,
                'advice' => $advice,
            },
        },
    );
}

sub _check_acls {
    Whostmgr::ACLS::init_acls();

    if ( !Whostmgr::ACLS::hasroot() ) {
        Whostmgr::HTMLInterface::defheader( 'cPanel Security Advisor', '', '/cgi/addon_securityadvisor.cgi' );
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
    return "Content-type: text/html\r\n\r\n";
}

