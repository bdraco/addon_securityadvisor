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

    my $sshd_config = Whostmgr::Services::SSH::Config::get_config();

    if ( $sshd_config->{'PasswordAuthentication'} =~ m/yes/i || $sshd_config->{'ChallengeResponseAuthentication'} =~ m/yes/i ) {
        $self->add_bad_advise(
            'text'       => ['SSH password authentication is enabled.'],
            'suggestion' => [
                'Disable SSH password authentication in the “[output,url,_1,SSH Password Authorization Tweak,_2,_3]” area',
                "~token~/scripts2/tweaksshauth",
                'target',
                '_blank'
            ],
        );
    }
    else {
        $self->add_good_advise(
            'text' => ['SSH password authentication is disabled.'],
        );

    }

    if ( $sshd_config->{'PermitRootLogin'} =~ m/yes/i || !$sshd_config->{'PermitRootLogin'} ) {
        $self->add_bad_advise(
            'text'       => ['SSH direct root logins are permitted.'],
            'suggestion' => [
                'Manually edit /etc/ssh/sshd_config and change PermitRootLogin to “no”, then restart SSH in the “[output,url,_1,Restart SSH,_2,_3]” area',
                "~token~/scripts/ressshd",
                'target',
                '_blank'
            ],
        );
    }
    else {
        $self->add_goof_advise(
            'text' => ['SSH direct root logins are disabled.'],
        );

    }
}

1;
