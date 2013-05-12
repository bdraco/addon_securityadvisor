package Cpanel::Security::Advisor::Assessors::Jail;

# cpanel - Cpanel/Security/Advisor/Assessors/Jail.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use Cpanel::Config::LoadCpConf ();
use Cpanel::PwCache            ();
use Cpanel::Config::Users      ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_unjailed_users();
}

sub _check_for_unjailed_users {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( !-x '/usr/bin/cagefsctl' ) {
        Cpanel::PwCache::init_passwdless_pwcache();
        my %cpusers = map { $_ => undef } Cpanel::Config::Users::getcpusers();

        my $pwcache_ref = Cpanel::PwCache::fetch_pwcache();
        my @users_without_jail = map { $_->[0] } grep { exists $cpusers{ $_->[0] } && $_->[8] && $_->[8] !~ m{(?:no|jail)shell} } @$pwcache_ref;    #aka users without jail or noshell

        if (@users_without_jail) {
            $security_advisor_obj->add_advise(
                {
                    'type'       => $Cpanel::Security::Advisor::ADVISE_WARN,
                    'text'       => [ 'Users running outside of the jail: [list_and,_1].', \@users_without_jail ],
                    'suggestion' => [
                        'Change these users to jailshell in the “[output,url,_1,Manage Shell Access,_2,_3]” area.',
                        $security_advisor_obj->security_token() . "/scripts2/manageshells",
                        'target',
                        '_blank'

                    ],
                }
            );
        }
    }

}

1;
