package Cpanel::Security::Advisor::Assessors::Mysql;

# cpanel - Cpanel/Security/Advisor/Assessors/SSH.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use Cpanel::Mysql    ();
use Cpanel::Hostname ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;

    $self->{msq} = Cpanel::Mysql->new();

    # check if we can connect to dbh
    if ( !$self->_check_for_mysql_connection ) {
        $self->add_bad_advise(
            'text'       => ['Cannot connect to MySQL server.'],
            'suggestion' => [
                'Enable MySQL database service',
                "~token~/scripts/srvmng",
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
        $self->add_good_advise( text => "MySQL test database doesn't exist." );
    }
    else {
        $self->add_bad_advise(
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
        $self->add_good_advise( text => "MySQL check for anonymous users" );
    }
    else {
        $self->add_bad_advise(
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
