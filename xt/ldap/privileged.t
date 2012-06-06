use strict;
use warnings;

use RT::Authen::ExternalAuth::Test ldap => 1, tests => 19;
my $class = 'RT::Authen::ExternalAuth::Test';

my ($server, $client) = $class->bootstrap_ldap_basics;
ok( $server, "spawned test LDAP server" );

RT->Config->Set( AutoCreate                  => { Privileged => 1 } );

RT::Test->set_rights(
    { Principal => 'Everyone', Right => [qw(SeeQueue ShowTicket CreateTicket)] },
);

my ( $baseurl, $m ) = RT::Test->started_ok();


diag "login, make sure user privileged";
{
    my $username = $class->add_ldap_user_simple;
    ok( $m->login( $username, 'password' ), 'logged in' );

    {
        my $user = RT::User->new($RT::SystemUser);
        my ($ok,$msg) = $user->Load( $username );
        ok($user->id);
        is($user->EmailAddress, "$username\@invalid.tld");
        ok($user->Privileged, 'privileged user');
    }

    unlike( $m->uri, qr!SelfService!, 'privileged home page' );
}

diag "send mail, make sure user privileged";
{
    my $username = $class->add_ldap_user_simple;
    {
        my $mail = << "MAIL";
Subject: Test
From: $username\@invalid.tld

test
MAIL

        my ($status, $id) = RT::Test->send_via_mailgate($mail);
        is ($status >> 8, 0, "The mail gateway exited normally");
        ok ($id, "got id of a newly created ticket - $id");

        my $ticket = RT::Ticket->new( $RT::SystemUser );
        $ticket->Load( $id );
        ok ($ticket->id, 'loaded ticket');

        my $user = $ticket->CreatorObj;
        is($user->EmailAddress, "$username\@invalid.tld");
        ok($user->Privileged, 'privileged user');
    }
    {
        ok( $m->login( $username, 'password', logout => 1 ), 'logged in' );
        unlike( $m->uri, qr!SelfService!, 'privileged home page' );
    }
}

$client->unbind();
