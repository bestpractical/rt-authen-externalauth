use strict;
use warnings;

use RT::Test tests => 6;
use Net::LDAP;
use RT::Authen::ExternalAuth;

eval { require Net::LDAP::Server::Test; 1; } or do {
    plan skip_all => 'Unable to test without Net::Server::LDAP::Test';
};


my $ldap_port = 1024 + int rand(10000) + $$ % 1024;
ok( my $server = Net::LDAP::Server::Test->new( $ldap_port, auto_schema => 1 ),
    "spawned test LDAP server on port $ldap_port" );

my $ldap = Net::LDAP->new("localhost:$ldap_port");
$ldap->bind();
my $username = "testuser";
my $dn       = "uid=$username,dc=bestpractical,dc=com";
my $entry    = {
    cn           => $username,
    mail         => "$username\@invalid.tld",
    uid          => $username,
    objectClass  => 'User',
    userPassword => 'password',
};
$ldap->add( $dn, attr => [%$entry] );

RT->Config->Set( Plugins                     => 'RT::Authen::ExternalAuth' );
RT->Config->Set( ExternalAuthPriority        => ['My_LDAP'] );
RT->Config->Set( ExternalServiceUsesSSLorTLS => 0 );
RT->Config->Set( AutoCreateNonExternalUsers  => 0 );
RT->Config->Set(
    ExternalSettings => {    # AN EXAMPLE DB SERVICE
        'My_LDAP' => {
            'type'            => 'ldap',
            'server'          => "127.0.0.1:$ldap_port",
            'base'            => 'dc=bestpractical,dc=com',
            'filter'          => '()',
            'd_filter'        => '(objectClass=*)',
            'tls'             => 0,
            'net_ldap_args'   => [ version => 3 ],
            'attr_match_list' => [ 'uid', 'EmailAddress' ],
            'attr_map'        => {
                'Name'         => 'uid',
                'EmailAddress' => 'mail',
            }
        },
    }
);
my ( $baseurl, $m ) = RT::Test->started_ok();
ok( !$m->login( 'fakeuser', 'password' ), 'not logged in with fake user' );
ok( $m->login( 'testuser', 'password' ), 'logged in' );
$m->logout;

$m->get_ok( $baseurl, 'base url' );
$m->submit_form(
    form_number => 1,
    fields      => { user => 'testuser', pass => 'password', },
);
$m->text_contains('Logout', 'logged in via form');

$ldap->unbind();
