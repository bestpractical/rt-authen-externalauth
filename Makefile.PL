use inc::Module::Install;

RTx('RT-Authen-ExternalAuth');

license('GPL version 2');
author('Mike Peachey <zordrak@cpan.org>');

all_from('lib/RT/Authen/ExternalAuth.pm');

requires('RT');
requires('Net::LDAP');

features(
  'SSL LDAP Connections' => [
    -default => 0,
    'Net::SSLeay' => 0]
);
&WriteAll;
