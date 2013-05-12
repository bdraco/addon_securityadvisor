package Cpanel::Security::Advisor::Assessors::SSH;

# cpanel - Cpanel/Security/Advisor/Assessors/SSH.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use Whostmgr::Services::SSH::Config ();
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_ssh_settings;
}

sub _check_for_ssh_settings {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $sshd_config = Whostmgr::Services::SSH::Config::get_config();

    if ( $sshd_config->{'PasswordAuthentication'} =~ m/yes/i || $sshd_config->{'ChallengeResponseAuthentication'} =~ m/yes/i ) {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['SSH password authentication is enabled.'],
                'suggestion' => [
                    'Disable SSH password authentication in the “[output,url,_1,SSH Password Authorization Tweak,_2,_3]” area',
                    $security_advisor_obj->security_token() . "/scripts2/tweaksshauth",
                    'target',
                    '_blank'
                ],
            }
        );
    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['SSH password authentication is disabled.'],
            }
        );

    }

    if ( $sshd_config->{'PermitRootLogin'} =~ m/yes/i || !$sshd_config->{'PermitRootLogin'} ) {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['SSH direct root logins are permitted.'],
                'suggestion' => [
                    'Manually edit /etc/ssh/sshd_config and change PermitRootLogin to “no”, then restart SSH in the “[output,url,_1,Restart SSH,_2,_3]” area',
                    $security_advisor_obj->security_token() . "/scripts/ressshd",
                    'target',
                    '_blank'
                ],
            }
        );
    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['SSH direct root logins are disabled.'],
            }
        );

    }
}

1;
