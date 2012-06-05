use inc::Module::Install;

RTx('RT-Authen-ExternalAuth');

license('GPL version 2');
author('Mike Peachey <zordrak@cpan.org>');

all_from('lib/RT/Authen/ExternalAuth.pm');
readme_from;

feature 'SSL LDAP Connections' =>
    -default => 0,
    recommends('Net::SSLeay' => 0),
    ;

feature 'External LDAP Sources' => 
    -default => 1,
    recommends('Net::LDAP' => 0),
    ;

feature 'External DBI Sources' =>
    -default => 1,
    recommends('DBI' => 0),
    ;

feature 'SSO Cookie Sources' => 
    -default => 1,
    recommends('CGI::Cookie' => 0),
    ;

recursive_author_tests('xt');

requires_rt('3.8.2');

&auto_install();

sign;
&WriteAll;
