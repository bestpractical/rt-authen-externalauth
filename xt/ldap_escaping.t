use strict;
use warnings;

use RT::Test tests => undef, testing => 'RT::Authen::ExternalAuth';
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

my $users_dn = "ou=users,dc=bestpractical,dc=com";
my $group_dn = "cn=test group,ou=groups,dc=bestpractical,dc=com";

$ldap->add(
    "cn=Smith\\, John,$users_dn",
    attr => [
        cn           => 'Smith\\, John',
        mail         => 'jsmith@example.com',
        uid          => 'jsmith',
        objectClass  => 'User',
        userPassword => 'password',
    ]
);
$ldap->add(
    $group_dn,
    attr => [
        cn          => "test group",
        memberDN    => [ "cn=Smith\\, John,$users_dn" ],
        objectClass => 'Group',
    ],
);

RT->Config->Set( ExternalAuthPriority        => ['My_LDAP'] );
RT->Config->Set( ExternalInfoPriority        => ['My_LDAP'] );
RT->Config->Set( ExternalServiceUsesSSLorTLS => 0 );
RT->Config->Set( AutoCreateNonExternalUsers  => 0 );
RT->Config->Set( AutoCreate  => undef );
RT->Config->Set(
    ExternalSettings => {
        'My_LDAP' => {
            'type'            => 'ldap',
            'server'          => "127.0.0.1:$ldap_port",
            'base'            => $users_dn,
            'filter'          => '(objectClass=*)',
            'd_filter'        => '()',
            'group'           => $group_dn,
            'group_attr'      => 'memberDN',
            'tls'             => 0,
            'net_ldap_args'   => [ version => 3 ],
            'attr_match_list' => [ 'Name', 'EmailAddress' ],
            'attr_map'        => {
                'Name'         => 'uid',
                'EmailAddress' => 'mail',
            }
        },
    }
);

my ( $baseurl, $m ) = RT::Test->started_ok();

diag "comma in the DN";
{
    ok( $m->login( 'jsmith', 'password' ), 'logged in' );

    my $testuser = RT::User->new($RT::SystemUser);
    my ($ok,$msg) = $testuser->Load( 'jsmith' );
    ok($ok,$msg);
    is($testuser->EmailAddress,'jsmith@example.com');
}

$ldap->unbind();

undef $m;
done_testing;
