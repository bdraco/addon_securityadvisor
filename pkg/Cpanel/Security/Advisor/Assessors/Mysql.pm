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
use Cpanel::MysqlUtils ();
use Cpanel::Hostname   ();
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
