use inc::Module::Install;

RTx('RT-Authen-ExternalAuth');

license('GPL version 2');
author('Mike Peachey <zordrak@cpan.org>');

all_from('lib/RT/Authen/ExternalAuth.pm');

requires('RT');

features(
  'SSL LDAP Connections' => [
    -default => 0,
    'Net::SSLeay' => 0],
  'External LDAP Sources' => [
    -default => 1,
    'Net::LDAP' => 0],
  'External DBI Sources' => [
    -default => 1,
    'DBI' => 0]
);
&WriteAll;
