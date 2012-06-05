use strict;
use warnings;

use RT::Authen::ExternalAuth::Test ldap => 1, tests => 20;
my $class = 'RT::Authen::ExternalAuth::Test';

my ($server, $client) = $class->bootstrap_ldap_basics;
ok( $server, "spawned test LDAP server" );

my $queue = RT::Test->load_or_create_queue(Name => 'General');
ok($queue->id, "loaded the General queue");

RT->Config->Set( AutoCreate                  => { Privileged => 1 } );

RT::Test->set_rights(
    { Principal => 'Everyone', Right => [qw(SeeQueue ShowTicket CreateTicket)] },
);

my ( $baseurl, $m ) = RT::Test->started_ok();

diag "first via email - a new ticket";
{
    my $username = new_user();

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
    is( $user->Name, $username );
    is( $user->EmailAddress, "$username\@invalid.tld" );
}

diag "first web login with username";
{
    my $username = new_user();
    ok( $m->login( $username, 'password' ), 'logged in' );

    ok( $m->goto_create_ticket( $queue ), "go to create ticket" );
    $m->form_name('TicketCreate');
    $m->submit;

    my ($id) = ($m->content =~ /.*Ticket (\d+) created.*/g);
    ok $id, "created a ticket";

    my $ticket = RT::Ticket->new( $RT::SystemUser );
    $ticket->Load( $id );
    ok ($ticket->id, 'loaded ticket');

    my $user = $ticket->CreatorObj;
    is( $user->Name, $username );
    is( $user->EmailAddress, "$username\@invalid.tld" );
}

$client->unbind;
$m->get_warnings;


my $i = 0;
sub new_user {
    my $name = "testuser". ++$i;
    $class->add_ldap_user(
        cn   => $name,
        mail => "$name\@invalid.tld",
    );
    return $name;
}

END {
    $client->unbind if $client;
}
