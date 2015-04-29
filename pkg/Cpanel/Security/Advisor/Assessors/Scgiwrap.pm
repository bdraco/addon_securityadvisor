package Cpanel::Security::Advisor::Assessors::Scgiwrap;

# Copyright (c) 2015, cPanel, Inc.
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
use base 'Cpanel::Security::Advisor::Assessors';
use Cpanel::Config::Httpd ();

sub generate_advice {
    my ($self) = @_;
    $self->_check_scgiwrap;

    return 1;
}

sub _check_scgiwrap {
    my ($self) = @_;

    my $security_advisor_obj = $self->{'security_advisor_obj'};

    my $suexec = "/usr/local/apache/bin/suexec";    # In ea3 this is always the same, in ea4 it is determined by the RPM in question.
    if ( defined &Cpanel::Config::Httpd::is_ea4 ) {
        if ( Cpanel::Config::Httpd::is_ea4() ) {
            require Cpanel::ConfigFiles::Apache;
            $suexec = Cpanel::ConfigFiles::Apache->new()->bin_suexec();
        }
    }

    my $scgiwrap = "/usr/local/cpanel/cgi-sys/scgiwrap";

    #check for sticky bit on file to see if it is enabled or not.
    my $suenabled   = ( ( stat $suexec )[2]   || 0 ) & 04000;
    my $scgienabled = ( ( stat $scgiwrap )[2] || 0 ) & 04000;

    my ($ruid) = ( grep { /ruid2_module/ } split( /\n/, Cpanel::SafeRun::Simple::saferun( '/usr/local/apache/bin/httpd', '-M' ) ) );

    if ( $suenabled && !$scgienabled ) {
        $security_advisor_obj->add_advice(
            {
                'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                'text' => ['SCGI is disabled, currently using the recommended suEXEC.'],
            }
        );
    }
    elsif ( $suenabled && $scgienabled ) {
        if ( !$ruid ) {
            $security_advisor_obj->add_advice(
                {
                    'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text'       => ['Both SCGI and suEXEC are enabled.'],
                    'suggestion' => [
                        'On the “[output,url,_1,Configure PHP and suEXEC,_2,_3]” page toggle “Apache suEXEC” off then back on to disable SCGI.',
                        $self->base_path('scripts2/phpandsuexecconf'),
                        'target',
                        '_blank'
                    ],
                }
            );
        }
        else {
            $security_advisor_obj->add_advice(
                {
                    'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                    'text' => ['SCGI, suEXEC, and mod_ruid2 are enabled.'],
                }
            );
        }
    }
    elsif ( !$suenabled || -f "$suexec.disable" ) {
        if ( !$ruid ) {
            $security_advisor_obj->add_advice(
                {
                    'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                    'text'       => ['suEXEC is disabled.'],
                    'suggestion' => [
                        'Enable suEXEC on the “[output,url,_1,Configure PHP and suEXEC,_2,_3]” page.',
                        $self->base_path('scripts2/phpandsuexecconf'),
                        'target',
                        '_blank'
                    ],
                }
            );
        }
        else {
            $security_advisor_obj->add_advice(
                {
                    'type' => $Cpanel::Security::Advisor::ADVISE_GOOD,
                    'text' => ['suEXEC is disabled; however mod_ruid2 is installed.'],
                }
            );
        }
    }
    else {
        $security_advisor_obj->add_advice(
            {
                'type'       => $Cpanel::Security::Advisor::ADVISE_BAD,
                'text'       => ['SCGI is enabled.'],
                'suggestion' => [
                    'Turn off SCGI and enable the more secure suEXEC in the “[output,url,_1,Configure PHP and suEXEC,_2,_3]” page.',
                    $self->base_path('scripts2/phpandsuexecconf'),
                    'target',
                    '_blank'
                ],
            }
        );

    }

    return 1;
}
1;
