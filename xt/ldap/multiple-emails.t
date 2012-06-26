use strict;
use warnings;

use RT::Authen::ExternalAuth::Test ldap => 1, tests => 50;
my $class = 'RT::Authen::ExternalAuth::Test';

my ($server, $client) = $class->bootstrap_ldap_basics;
ok( $server, "spawned test LDAP server" );

my $queue = RT::Test->load_or_create_queue(Name => 'General');
ok($queue->id, "loaded the General queue");

RT->Config->Set( AutoCreate                  => { Privileged => 1 } );

RT->Config->Get('ExternalSettings')->{'My_LDAP'}{'attr_map'}{'EmailAddress'}
    = ['mail', 'alias', 'proxyAddresses', 'foo'];

RT->Config->Get('ExternalSettings')->{'My_LDAP'}{'attr_prefix'}{'proxyAddresses'}
    = [ 'smtp:', 'SMTP:', 'X400:', '' ];

RT::Test->set_rights(
    { Principal => 'Everyone', Right => [qw(SeeQueue ShowTicket CreateTicket)] },
);

my ( $baseurl, $m ) = RT::Test->started_ok();

diag "login then send emails from different addresses";
{
    my $username = new_user();
    my $first_user;
    {
        ok( $m->login( $username, 'password' ), 'logged in' );

        ok( $m->goto_create_ticket( $queue ), "go to create ticket" );
        $m->form_name('TicketCreate');
        $m->submit;

        my ($id) = ($m->content =~ /.*Ticket (\d+) created.*/g);
        ok $id, "created a ticket";

        my $ticket = RT::Ticket->new( $RT::SystemUser );
        $ticket->Load( $id );
        ok ($ticket->id, 'loaded ticket');

        my $user = $first_user = $ticket->CreatorObj;
        is( $user->Name, $username );
        is( $user->EmailAddress, "$username\@invalid.tld" );
    }

    diag "Send first email from initial address.";
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
        is( $user->id, $first_user->id );
        is( $user->Name, $username );
        is( $user->EmailAddress, "$username\@invalid.tld" );
    }

    diag "Send email from alias address.";
    {
        my $mail = << "MAIL";
Subject: Test
From: $username\@alternative.tld

test
MAIL

        my ($status, $id) = RT::Test->send_via_mailgate($mail);
        is ($status >> 8, 0, "The mail gateway exited normally");
        ok ($id, "got id of a newly created ticket - $id");

        my $ticket = RT::Ticket->new( $RT::SystemUser );
        $ticket->Load( $id );
        ok ($ticket->id, 'loaded ticket');

        my $user = $ticket->CreatorObj;
        is( $user->id, $first_user->id );
        is( $user->Name, $username );
        is( $user->EmailAddress, "$username\@invalid.tld" );
    }

    diag "Send email from smtp: address.";
    my $smtp = substr($username, 1);
    {
        my $mail = << "MAIL";
Subject: Test
From: $smtp\@alternative.tld

test
MAIL

        my ($status, $id) = RT::Test->send_via_mailgate($mail);
        is ($status >> 8, 0, "The mail gateway exited normally");
        ok ($id, "got id of a newly created ticket - $id");

        my $ticket = RT::Ticket->new( $RT::SystemUser );
        $ticket->Load( $id );
        ok ($ticket->id, 'loaded ticket');

        my $user = $ticket->CreatorObj;
        is( $user->id, $first_user->id );
        is( $user->Name, $username );
        is( $user->EmailAddress, "$username\@invalid.tld", "Got original email address with smtp email." );
    }

}

diag "send a mail from alternative address, then try other credentials";
{
    my $username = new_user();
    my $first_user;
    {
        my $mail = << "MAIL";
Subject: Test
From: $username\@alternative.tld

test
MAIL

        my ($status, $id) = RT::Test->send_via_mailgate($mail);
        is ($status >> 8, 0, "The mail gateway exited normally");
        ok ($id, "got id of a newly created ticket - $id");

        my $ticket = RT::Ticket->new( $RT::SystemUser );
        $ticket->Load( $id );
        ok ($ticket->id, 'loaded ticket');

        my $user = $first_user = $ticket->CreatorObj;
        is( $user->Name, $username );
        is( $user->EmailAddress, "$username\@alternative.tld" );
    }

    {
        ok( $m->login( $username, 'password', logout => 1 ), 'logged in' );

        ok( $m->goto_create_ticket( $queue ), "go to create ticket" );
        $m->form_name('TicketCreate');
        $m->submit;

        my ($id) = ($m->content =~ /.*Ticket (\d+) created.*/g);
        ok $id, "created a ticket";

        my $ticket = RT::Ticket->new( $RT::SystemUser );
        $ticket->Load( $id );
        ok ($ticket->id, 'loaded ticket');

        my $user = $ticket->CreatorObj;
        is( $user->id, $first_user->id );
        is( $user->Name, $username );
        is( $user->EmailAddress, "$username\@alternative.tld" );
    }

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
        is( $user->id, $user->id );
        is( $user->Name, $username );
        is( $user->EmailAddress, "$username\@alternative.tld" );
    }
}

$client->unbind();

sub new_user { return $class->add_ldap_user_simple( alias => '%name@alternative.tld',
						    add_proxy_addresses => 'alternative.tld') }

