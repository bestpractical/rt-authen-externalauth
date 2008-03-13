use inc::Module::Install;

RTx('RT-Authen-ExternalAuth');

license('GPL version 2');
author('Mike Peachey <zordrak@cpan.org>');

all_from('lib/RT/Authen/ExternalAuth.pm');

requires('RT');

&WriteAll;
