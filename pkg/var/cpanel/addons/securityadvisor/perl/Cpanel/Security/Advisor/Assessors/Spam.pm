package Cpanel::Security::Advisor::Assessors::Spam;

# cpanel - Cpanel/Security/Advisor/Assessors/Spam.pm Copyright(c) 2013 cPanel, Inc.
#                                                           All rights Reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use base 'Cpanel::Security::Advisor::Assessors';

sub generate_advise {
    my ($self) = @_;
    $self->_check_for_nobody_tracking();
}

sub _check_for_nobody_tracking {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    if ( $security_advisor_obj->{'cpconf'}->{'nobodyspam'} ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['The psuedo-user “nobody” is not permitted to send email.'],
            }
        );
    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['The psuedo-user “nobody” is permitted to send email.'],
                'suggestion' => [
                    'Enable “Prevent "nobody" from sending mail” in the “[output,url,_1,Tweak Settings,_2,_3]” area',
                    $security_advisor_obj->security_token() . "/scripts2/tweaksettings?find=nobodyspam",
                    'target',
                    '_blank'
                ],
            }
        );
    }

    if ( -e '/var/cpanel/smtpgidonlytweak' ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['Outbound SMTP connections are restricted.'],
            }
        );

    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['Outbound SMTP connections are unrestricted.'],
                'suggestion' => [
                    'Enable SMTP Restrictions in the “[output,url,_1,SMTP Restrictions,_2,_3]” area',
                    $security_advisor_obj->security_token() . "/scripts2/smtpmailgidonly",
                    'target',
                    '_blank'
                ],

            }
        );

    }

    if ( -e '/var/cpanel/config/email/query_apache_for_nobody_senders' ) {
        $security_advisor_obj->add_advise(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['Apache is being queried to determine the actual sender when mail originates from the “nobody” pseudo-user.'],
            }
        );
    }
    else {
        $security_advisor_obj->add_advise(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['Apache is not being queried to determine the actual sender when mail originates from the “nobody” psuedo-user.'],
                'suggestion' => [
                    'Enable “Query Apache server status to determine the sender of email sent from processes running as nobody” in the “[output,url,_1,Exim Configuration Manager,_2,_3]” area\'s “Basic Editory”',
                    $security_advisor_obj->security_token() . "/scripts2/displayeximconfforedit",
                    'target',
                    '_blank'
                ],
            }
        );

    }

}

1;
