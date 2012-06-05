use strict;
use warnings;

use RT::Authen::ExternalAuth::Test ldap => 1, tests => 15;
my $class = 'RT::Authen::ExternalAuth::Test';


my ($server, $client) = $class->bootstrap_ldap_basics;
ok( $server, "spawned test LDAP server" );

my $username = "testuser";
$class->add_ldap_user(
    uid  => $username,
    mail => "$username\@invalid.tld",
);

RT->Config->Set( AutoCreate                  => { Privileged => 1 } );

my ( $baseurl, $m ) = RT::Test->started_ok();

diag "test uri login";
{
    ok( !$m->login( 'fakeuser', 'password' ), 'not logged in with fake user' );
    ok( $m->login( 'testuser', 'password' ), 'logged in' );
}

diag "test user creation";
{
    my $testuser = RT::User->new($RT::SystemUser);
    my ($ok,$msg) = $testuser->Load( 'testuser' );
    ok($ok,$msg);
    is($testuser->EmailAddress,'testuser@invalid.tld');
}


diag "test form login";
{
    $m->logout;
    $m->get_ok( $baseurl, 'base url' );
    $m->submit_form(
        form_number => 1,
        fields      => { user => 'testuser', pass => 'password', },
    );
    $m->text_contains( 'Logout', 'logged in via form' );
}

like( $m->uri, qr!$baseurl/(index\.html)?!, 'privileged home page' );

$client->unbind();

$m->get_warnings;
