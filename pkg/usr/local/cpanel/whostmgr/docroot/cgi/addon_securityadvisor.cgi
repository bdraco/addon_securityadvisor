#!/usr/local/cpanel/3rdparty/bin/perl
#WHMADDON:addonupdates:Security Advisor Tool
#ACLS:all
# cpanel - whostmgr/docroot/cgi/addon_securityadvisor.cgi    Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

package cgi::addon_securityadvisor;

BEGIN {
    unshift @INC, '/var/cpanel/addons/securityadvisor/perl';

    require Cpanel::Locale;

    *Cpanel::Locale::maketext_ref = sub {
        return shift->maketext( ref $_[0] ? @{ $_[0] } : @_ );
    };
}

use Whostmgr::ACLS          ();
use Whostmgr::HTMLInterface ();
use Cpanel::Form            ();

# from /var/cpanel/addons/securityadvisor/perl
use Cpanel::Security::Advisor ();

run(@ARGV) unless caller();

sub run {
    print _headers();
    _check_acls();

    my $form = Cpanel::Form::parseform();

    my $advisor = Cpanel::Security::Advisor->new();

    my $advise = $advisor->generate_advise();

    Cpanel::Template::process_template(
        'whostmgr',
        {
            'template_file' => '/var/cpanel/addons/securityadvisor/templates/main.tmpl',
            'data'          => {
                'form'   => $form,
                'advise' => $advise,
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

