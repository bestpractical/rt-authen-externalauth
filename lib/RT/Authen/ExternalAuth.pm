package RT::Authen::ExternalAuth;

our $VERSION = '0.01';

=head1 NAME

  RT::Authen::ExternalAuth - RT Authentication using External Sources

=head1 DESCRIPTION

  A complete package for adding external authentication mechanisms
  to RT. It currently supports LDAP via Net::LDAP and External Database
  authentication for any database with an installed DBI driver.

  It also allows for authenticating cookie information against an
  external database through the use of the RT-Authen-CookieAuth extension.

=begin testing

ok(require RT::Authen::ExternalAuth);

=end testing

1;
