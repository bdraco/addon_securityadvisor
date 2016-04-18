package Cpanel::Security::Advisor::Assessors::Mysql;

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
use Cpanel::Hostname                ();
use Cpanel::IP::Loopback            ();
use Cpanel::IP::Parse               ();
use Cpanel::MysqlUtils              ();
use Cpanel::MysqlUtils::MyCnf::Full ();
use Cpanel::SafeRun::Errors         ();
eval { local $SIG{__DIE__}; require Cpanel::MysqlUtils::Connect; };

use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;

    eval { Cpanel::MysqlUtils::Connect::connect(); } if $INC{'Cpanel/MysqlUtils/Connect.pm'};

    if ( !Cpanel::MysqlUtils::sqlcmd('SELECT 1;') ) {
        $self->add_bad_advice(
            'text'       => ['Cannot connect to MySQL server.'],
            'suggestion' => [
                'Enable MySQL database service',
                $self->base_path('scripts/srvmng'),
                'target',
                '_blank'
            ],

        );
        return;
    }

    $self->_check_for_db_test();
    $self->_check_for_anonymous_users();
    $self->_check_for_public_bind_address();

    return 1;
}

sub _check_for_db_test {

    my $self = shift;

    my $exists = Cpanel::MysqlUtils::sqlcmd(qq{show databases like 'test'});

    if ( !$exists ) {
        $self->add_good_advice( text => "MySQL test database doesn't exist." );
    }
    else {
        $self->add_bad_advice(
            text       => "MySQL test database exists.",
            suggestion => q{MySQL test database is used by numerous attacks and should be removed.
				> mysql -e 'drop database test'
			}
        );

    }

    return 1;
}

sub _check_for_anonymous_users {
    my $self = shift;

    my $ok  = 1;
    my $ano = Cpanel::MysqlUtils::sqlcmd(qq{select 1 from mysql.user where user="" limit 1});
    if ($ano) {
        $ok = 0;
    }

    for my $h ( 'localhost', Cpanel::Hostname::gethostname ) {
        eval {
            my $grant = Cpanel::MysqlUtils::sqlcmd(qq{SHOW GRANTS FOR ''\@'$h'});
            $ok = 0 if $grant;
        };
    }

    if ($ok) {
        $self->add_good_advice( text => "MySQL check for anonymous users" );
    }
    else {
        $self->add_bad_advice(
            text       => "You have some anonymous mysql users",
            suggestion => q{Remove mysql anonymous mysql users: > mysql -e 'drop user ""'}
        );
    }

    return 1;
}

sub _check_for_public_bind_address {
    my $self = shift;

    my $mycnf        = Cpanel::MysqlUtils::MyCnf::Full::etc_my_cnf();
    my $bind_address = $mycnf->{'mysqld'}->{'bind-address'};
    my $port         = $mycnf->{'mysqld'}->{'port'} || '3306';

    my @deny_rules   = grep { /--dport \Q$port\E/ && /-j (DROP|REJECT)/ } split /\n/, Cpanel::SafeRun::Errors::saferunnoerror( '/sbin/iptables',  '--list-rules' );
    my @deny_rules_6 = grep { /--dport \Q$port\E/ && /-j (DROP|REJECT)/ } split /\n/, Cpanel::SafeRun::Errors::saferunnoerror( '/sbin/ip6tables', '--list-rules' );

    # From: http://dev.mysql.com/doc/refman/5.5/en/server-options.html
    # The server treats different types of addresses as follows:
    #
    # If the address is *, the server accepts TCP/IP connections on all server
    # host IPv6 and IPv4 interfaces if the server host supports IPv6, or accepts
    # TCP/IP connections on all IPv4 addresses otherwise. Use this address to
    # permit both IPv4 and IPv6 connections on all server interfaces. This value
    # is permitted (and is the default) as of MySQL 5.6.6.
    #
    # If the address is 0.0.0.0, the server accepts TCP/IP connections on all
    # server host IPv4 interfaces. This is the default before MySQL 5.6.6.
    #
    # If the address is ::, the server accepts TCP/IP connections on all server
    # host IPv4 and IPv6 interfaces.
    #
    # If the address is an IPv4-mapped address, the server accepts TCP/IP
    # connections for that address, in either IPv4 or IPv6 format. For example,
    # if the server is bound to ::ffff:127.0.0.1, clients can connect using
    # --host=127.0.0.1 or --host=::ffff:127.0.0.1.
    #
    # If the address is a “regular” IPv4 or IPv6 address (such as 127.0.0.1 or
    # ::1), the server accepts TCP/IP connections only for that IPv4 or IPv6
    # address.

    if ( defined($bind_address) ) {
        my $version = ( Cpanel::IP::Parse::parse($bind_address) )[0];

        if ( Cpanel::IP::Loopback::is_loopback($bind_address) ) {
            $self->add_good_advice( text => "MySQL is listening only on a local address." );
        }
        elsif ( ( ( $version == 4 ) && @deny_rules && ( ( $bind_address =~ /ffff/i ) ? @deny_rules_6 : 1 ) ) || ( ( $version == 6 ) && @deny_rules_6 ) ) {
            $self->add_good_advice( text => "The MySQL port is blocked by the firewall, effectively allowing only local connections." );
        }
        else {
            $self->add_bad_advice(
                text       => "The MySQL service is currently configured to listen on a public address: (bind-address=$bind_address)",
                suggestion => 'Configure bind-address=127.0.0.1 in /etc/my.cnf',
            );
        }
    }
    else {
        if ( @deny_rules && @deny_rules_6 ) {
            $self->add_good_advice( text => "The MySQL port is blocked by the firewall, effectively allowing only local connections." );
        }
        else {
            $self->add_bad_advice(
                text       => 'The MySQL service is currently configured to listen on all interfaces: (bind-address=*)',
                suggestion => 'Configure bind-address=127.0.0.1 in /etc/my.cnf',
            );
        }
    }

    return 1;
}

sub _check_for_mysql_users {

    # TODO
    return 1;
}

sub _check_for_mysql_settings {
    my ($self) = @_;

    # TODO
    return 1;
}

1;
