package Cpanel::Security::Advisor::Assessors::Apache;

# cpanel - Cpanel/Security/Advisor/Assessors/Apache.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_apache_chroot();
}

sub _check_for_apache_chroot {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( $security_advisor_obj->{'cpconf'}->{'jailapache'} ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['Jailed Apache is enabled'],
            }
        );
    }
    elsif ( -x '/usr/bin/cagefsctl' ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['CageFS is enabled'],
            }
        );
    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['Apache vhosts are not chroot()ed.'],
                'suggestion' => [
                    'Enable “Jail Apache” in the “[output,url,_1,Tweak Settings,_4,_5]” area, and change users to jailshell in the “[output,url,_2,Manage Shell Access,_4,_5]” area.  Consider a more robust solution by using “[output,url,_3,CageFS on CloudLinux,_4,_5]”',
                    '../scripts2/tweaksettings?find=jailapache',
                    '../scripts2/manageshells',
                    'http://cpanel.net/cpanel-whm/cloudlinux/',
                    'target',
                    '_blank'
                ],
            }
        );
    }

}

1;
