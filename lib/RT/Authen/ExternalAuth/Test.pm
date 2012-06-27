use strict;
use warnings;

### after: use lib qw(@RT_LIB_PATH@);
use lib qw(/opt/rt4/local/lib /opt/rt4/lib);

package RT::Authen::ExternalAuth::Test;

our @ISA;
BEGIN {
    local $@;
    eval { require RT::Test; 1 } or do {
        require Test::More;
        Test::More::BAIL_OUT(
            "requires 3.8 to run tests. Error:\n$@\n"
            ."You may need to set PERL5LIB=/path/to/rt/lib"
        );
    };
    push @ISA, 'RT::Test';
}

sub import {
    my $class = shift;
    my %args  = @_;

    $args{'requires'} ||= [];
    if ( $args{'testing'} ) {
        unshift @{ $args{'requires'} }, 'RT::Authen::ExternalAuth';
    } else {
        $args{'testing'} = 'RT::Authen::ExternalAuth';
    }

    if ( delete $args{'ldap'} ) {
        local $@;
        eval {
            require Net::LDAP;
            require Net::LDAP::Server::Test;
            1;
        } or do {
            require Test::More;
            Test::More::plan( skip_all => 'Unable to test without LDAP modules: '. $@ );
            exit;
        }
    }
    if ( my $driver = delete $args{'dbi'} ) {
        local $@;
        eval {
            require DBI;
            require File::Temp;
            require Digest::MD5;
            require File::Spec;
            eval "require DBD::$driver; 1";
        } or do {
            require Test::More;
            Test::More::plan( skip_all => 'Unable to test without DB modules: '. $@ );
            exit;
        }
    }

    $class->SUPER::import( %args );
    $class->export_to_level(1);

    require RT::Authen::ExternalAuth;
}

my %ldap;
sub bootstrap_ldap_server {
    my $self = shift;

    my $port = $self->generate_port;

    require Net::LDAP::Server::Test;
    my $server = Net::LDAP::Server::Test->new( $port, auto_schema => 1 );
    return () unless $server;

    my $client = Net::LDAP->new( "localhost:$port" );
    $client->bind;

    @ldap{'server','client'} = ($server, $client);
    return ($server, $client, "localhost:$port", $port);
}

sub bootstrap_ldap_basics {
    my $self = shift;
    my ($server, $client, $address, $port) = $self->bootstrap_ldap_server;

    RT->Config->Set( Plugins                     => 'RT::Authen::ExternalAuth' );
    RT->Config->Set( ExternalAuthPriority        => ['My_LDAP'] );
    RT->Config->Set( ExternalInfoPriority        => ['My_LDAP'] );
    RT->Config->Set( ExternalServiceUsesSSLorTLS => 0 );
    RT->Config->Set( AutoCreateNonExternalUsers  => 0 );
    RT->Config->Set( AutoCreate  => undef );
    RT->Config->Set(
        ExternalSettings => {
            'My_LDAP' => {
                'type'            => 'ldap',
                'server'          => $address,
                'base'            => 'dc=bestpractical,dc=com',
                'filter'          => '(objectClass=*)',
                'd_filter'        => '()',
                'tls'             => 0,
                'net_ldap_args'   => [ version => 3 ],
                'attr_match_list' => [ 'Name', 'EmailAddress' ],
                'attr_map'        => {
                    'Name'         => 'uid',
                    'EmailAddress' => 'mail',
                },
            },
        },
    );
    return ($server, $client);
}

sub generate_port {
    return 1024 + int rand(10000) + $$ % 1024;
}

sub add_ldap_user {
    my $self = shift;
    my %args = @_;

    $args{'uid'} ||= $args{'cn'};
    $args{'cn'} ||= $args{'uid'};

    my $dn = delete $args{'dn'};
    $dn ||= "uid=". $args{'uid'} .",dc=bestpractical,dc=com";

    $args{'objectClass'} ||= 'User';
    $args{'userPassword'} ||= 'password';

    return $ldap{'client'}->add( $dn, attr => [%args] );
}

=head1 add_ldap_user_simple

Create a test username and add a test user to the test LDAP directory
for testing. Accepts a hash of ldap entries and values.

The %name placeholder in test email addresses is replaced
with the generated test username before the LDAP entries are added
to the test server.

Pass add_proxy_addresses => 'test.com' to have proxyAddresses entries created to
simulate AD. This option will add the following:

    proxyAddresses smtp:testuser1@test.com
    proxyAddresses smtp:estuser1@test.com
    proxyAddresses SMTP:testuser1@test.com

Returns the test username generated.

=cut

{ my $i = 0;
sub add_ldap_user_simple {
    my $self = shift;
    my %args = @_;

    my $name = delete $args{'cn'} || "testuser". ++$i;

    s/\%name\b/$name/g foreach grep defined, values %args;

    # The goal is to make these entries look like 'typical' AD
    if( exists $args{add_proxy_addresses} && $args{add_proxy_addresses} ){
        $args{proxyAddresses} = [
           'smtp:' . $name . '@' . $args{add_proxy_addresses},
           'smtp:' . substr($name,1) . '@' . $args{add_proxy_addresses},
           'SMTP:' . $name . '@' . $args{add_proxy_addresses},
       ];
    }

    delete $args{add_proxy_addresses}; # Don't want this in the LDAP entry

    $self->add_ldap_user(
        cn    => $name,
        mail  => "$name\@invalid.tld",
        %args,
    );
    return $name;
} }

1;
