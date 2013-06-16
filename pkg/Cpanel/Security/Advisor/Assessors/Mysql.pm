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
use Cpanel::Mysql    ();
use Cpanel::Hostname ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advice {
    my ($self) = @_;

    $self->{msq} = Cpanel::Mysql->new();

    # check if we can connect to dbh
    if ( !$self->_check_for_mysql_connection ) {
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

    return;
}

sub dbh {
    my $self = shift;

    return $self->{msq}->{dbh};
}

sub _check_for_mysql_connection {
    my $self = shift;

    my $dbh = $self->dbh();
    return $dbh && ref $dbh && $dbh->ping();
}

sub _check_for_db_test {

    my $self = shift;

    my ($exists) = $self->dbh->selectrow_array(qq{show databases like 'test'});

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

}

sub _check_for_anonymous_users {
    my $self = shift;

    my $ok  = 1;
    my $ano = $self->dbh->selectrow_arrayref(qq{select 1 from mysql.user where user="" limit 1});
    if ( $ano && $ano->[0] ) {
        $ok = 0;
    }

    for my $h ( 'localhost', Cpanel::Hostname::gethostname ) {
        eval {
            my ($grant) = $self->dbh->selectrow_array(qq{SHOW GRANTS FOR ''\@'$h'});
            $ok = 0 if ($grant);
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

    return;
}

sub _check_for_mysql_users {

    # TODO
}

sub _check_for_mysql_settings {
    my ($self) = @_;

    # TODO
}

1;
