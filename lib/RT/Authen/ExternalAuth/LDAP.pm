package RT::Authen::ExternalAuth::LDAP;

use Net::LDAP qw(LDAP_SUCCESS LDAP_PARTIAL_RESULTS);
use Net::LDAP::Util qw(ldap_error_name escape_filter_value);
use Net::LDAP::Filter;

use strict;

require Net::SSLeay if $RT::ExternalServiceUsesSSLorTLS;

sub GetAuth {
    my ($service, $username, $password) = @_;
    
    my $config = $RT::ExternalSettings->{$service};
    $RT::Logger->debug( "Trying external auth service:",$service);

    my $base            = $config->{'base'};
    my $filter          = $config->{'filter'};
    my $group           = $config->{'group'};
    my $group_attr      = $config->{'group_attr'};
    my $group_attr_val  = $config->{'group_attr_value'} || 'dn';
    my $attr_map        = $config->{'attr_map'};
    my @attrs           = ('dn');

    # Make sure we fetch the user attribute we'll need for the group check
    push @attrs, $group_attr_val
        unless lc $group_attr_val eq 'dn';

    # Empty parentheses as filters cause Net::LDAP to barf.
    # We take care of this by using Net::LDAP::Filter, but
    # there's no harm in fixing this right now.
    if ($filter eq "()") { undef($filter) };

    # Now let's get connected
    my $ldap = _GetBoundLdapObj($config);
    return 0 unless ($ldap);

    $filter = '(&'
        .'('.  $attr_map->{'Name'} .  '=' .  escape_filter_value( $username ) .  ')' . 
        $filter
    .')';

    my $ldap_msg = PerformSearch(
        $ldap,
        base   => $base,
        filter => $filter,
        attrs  => \@attrs
    ) or return 0;;

    unless ($ldap_msg->count == 1) {
        $RT::Logger->info(  $service,
                            "AUTH FAILED:", 
                            $username,
                            "User not found or more than one user found");
        # We got no user, or too many users.. jump straight to the next external auth service
        return 0;
    }

    my $ldap_entry = $ldap_msg->first_entry;
    my $ldap_dn    = $ldap_entry->dn;

    $RT::Logger->debug( "Found LDAP DN:", 
                        $ldap_dn);

    # THIS bind determines success or failure on the password.
    $ldap_msg = $ldap->bind($ldap_dn, password => $password);

    unless ($ldap_msg->code == LDAP_SUCCESS) {
        $RT::Logger->info(  $service,
                            "AUTH FAILED", 
                            $username, 
                            "(can't bind:", 
                            ldap_error_name($ldap_msg->code), 
                            $ldap_msg->code, 
                            ")");
        # Could not bind to the LDAP server as the user we found with the password
        # we were given, therefore the password must be wrong so we fail and
        # jump straight to the next external auth service
        return 0;
    }

    # The user is authenticated ok, but is there an LDAP Group to check?
    if ($group) {
        my $group_val = lc $group_attr_val eq 'dn'
                            ? $ldap_dn
                            : $ldap_entry->get_value($group_attr_val);

        # Fallback to the DN if the user record doesn't have a value
        unless (defined $group_val) {
            $group_val = $ldap_dn;
            $RT::Logger->debug("Attribute '$group_attr_val' has no value; falling back to '$group_val'");
        }

        # We only need the dn for the actual group since all we care about is existence
        @attrs  = qw(dn);
        $ldap_msg = PerformSearch(
            $ldap,
            base   => $group,
            filter => "(${group_attr}=" . escape_filter_value($group_val) . ")",
            attrs  => \@attrs,
            scope  => 'base'
        ) or return 0;

        unless ($ldap_msg->count == 1) {
            $RT::Logger->debug(
                "LDAP group membership check returned",
                $ldap_msg->count, "results"
            );
            $RT::Logger->info(  $service,
                                "AUTH FAILED:", 
                                $username);
                                
            # Fail auth - jump to next external auth service
            return 0;
        }
    }
    
    # Any other checks you want to add? Add them here.

    # If we've survived to this point, we're good.
    $RT::Logger->info(  (caller(0))[3], 
                        "External Auth OK (",
                        $service,
                        "):", 
                        $username);
    return 1;

}


sub CanonicalizeUserInfo {
    
    my ($service, $key, $value, $attrs) = @_;

    # Load the config
    my $config = $RT::ExternalSettings->{$service};

    # Default smtp: as the most common case
    my %filter_prefix = (
                        proxyAddresses => [ 'smtp:'],
                        %{$config->{'attr_prefix'}}
                        );

    # Build the LDAP filters
    my @filter_list;
    foreach my $filter_key ( ref $key ? @$key : ($key) ){
        push @filter_list, "($filter_key=" . escape_filter_value( $value ) . ")";

        # Prepend prefixes for AD
        if( exists $filter_prefix{$filter_key} ){
            foreach my $prefix ( @{ $filter_prefix{$filter_key} } ){
                push @filter_list, "($filter_key=" . escape_filter_value( $prefix . $value ) . ")";
           }
        }
    }

    my $filter = JoinFilters(
        '&',
        JoinFilters('|', @filter_list ),
        $config->{'filter'},
    ) or return (0);

    my $base = $config->{'base'};
    unless (defined($base)) {
        $RT::Logger->critical(  (caller(0))[3],
                                "LDAP baseDN not defined");
        # Drop out to the next external information service
        return (0);
    }

    # Get a Net::LDAP object based on the config we provide
    my $ldap = _GetBoundLdapObj($config);

    # Jump to the next external information service if we can't get one, 
    # errors should be logged by _GetBoundLdapObj so we don't have to.
    return (0) unless ($ldap);

    my $ldap_msg = PerformSearch(
        $ldap,
        base   => $base,
        filter => $filter,
        attrs  => $attrs
    );
    
    # If there's only one match, we're good; more than one and
    # we don't know which is the right one so we skip it.
    unless ($ldap_msg && $ldap_msg->count == 1) {
        Unbind( $ldap );
        return (0);
    }

    my %res;
    my $entry = $ldap_msg->first_entry;
    foreach my $attr ( @$attrs ) {
        # XXX TODO: This if branch was inactive for a while
        # now it works, but is it right thing to do? entry->dn
        # is it at all diiferent from get_value('dn')?
        if ( $attr eq 'dn' ) {
            $res{ $attr } = $entry->dn;
        } else {
            $res{ $attr } = ($entry->get_value( $attr ))[0];
        }
    }
    Unbind( $ldap );
    return (1, %res);
}

sub UserExists {
    my ($username,$service) = @_;
   $RT::Logger->debug("UserExists params:\nusername: $username , service: $service"); 
    my $config              = $RT::ExternalSettings->{$service};
    
    my $filter              = $config->{'filter'};

    # While LDAP filters must be surrounded by parentheses, an empty set
    # of parentheses is an invalid filter and will cause failure
    # This shouldn't matter since we are now using Net::LDAP::Filter below,
    # but there's no harm in doing this to be sure
    if ($filter eq "()") { undef($filter) };

    if (defined($config->{'attr_map'}->{'Name'})) {
        # Construct the complex filter
        $filter = Net::LDAP::Filter->new(           '(&' . 
                                                    $filter . 
                                                    '(' . 
                                                    $config->{'attr_map'}->{'Name'} . 
                                                    '=' . 
                                                    escape_filter_value($username) . 
                                                    '))'
                                        );
    }

    my $ldap = _GetBoundLdapObj($config);
    return unless $ldap;

    # Check that the user exists in the LDAP service
    my $user_found = PerformSearch(
        $ldap,
        base    => $config->{'base'},
        filter  => $filter,
        attrs   => ['uid'],
    ) or return 0;

    if($user_found->count < 1) {
        # If 0 or negative integer, no user found or major failure
        $RT::Logger->debug( "User Check Failed :: (",
                            $service,
                            ")",
                            $username,
                            "User not found");   
        return 0;  
    } elsif ($user_found->count > 1) {
        # If more than one result returned, die because we the username field should be unique!
        $RT::Logger->debug( "User Check Failed :: (",
                            $service,
                            ")",
                            $username,
                            "More than one user with that username!");
        return 0;
    }
    undef $user_found;
    
    # If we havent returned now, there must be a valid user.
    return 1;
}

sub UserDisabled {

    my ($username,$service) = @_;

    # FIRST, check that the user exists in the LDAP service
    unless(UserExists($username,$service)) {
        $RT::Logger->debug("User (",$username,") doesn't exist! - Assuming not disabled for the purposes of disable checking");
        return 0;
    }
    
    my $config          = $RT::ExternalSettings->{$service};
    my $base            = $config->{'base'};
    my $filter          = $config->{'filter'};
    my $d_filter        = $config->{'d_filter'};
    my $search_filter;

    # While LDAP filters must be surrounded by parentheses, an empty set
    # of parentheses is an invalid filter and will cause failure
    # This shouldn't matter since we are now using Net::LDAP::Filter below,
    # but there's no harm in doing this to be sure
    if ($filter eq "()") { undef($filter) };
    if ($d_filter eq "()") { undef($d_filter) };

    unless ($d_filter) {
        # If we don't know how to check for disabled users, consider them all enabled.
        $RT::Logger->debug("No d_filter specified for this LDAP service (",
                            $service,
                            "), so considering all users enabled");
        return 0;
    }

    if (defined($config->{'attr_map'}->{'Name'})) {
        # Construct the complex filter
        $search_filter = Net::LDAP::Filter->new(   '(&' . 
                                                    $filter . 
                                                    $d_filter . 
                                                    '(' . 
                                                    $config->{'attr_map'}->{'Name'} . 
                                                    '=' . 
                                                    escape_filter_value($username) . 
                                                    '))'
                                                );
    } else {
        $RT::Logger->debug("You haven't specified an LDAP attribute to match the RT \"Name\" attribute for this service (",
                            $service,
                            "), so it's impossible look up the disabled status of this user (",
                            $username,
                            ") so I'm just going to assume the user is not disabled");
        return 0;
        
    }

    my $ldap = _GetBoundLdapObj($config);
    next unless $ldap;

    my $disabled_users = PerformSearch(
        $ldap,
        base   => $base, 
        filter => $search_filter, 
        attrs  => ['uid'], # We only need the UID for confirmation now
    ) or return 0;

    # If ANY results are returned, 
    # we are going to assume the user should be disabled
    if ($disabled_users->count) {
        undef $disabled_users;
        return 1;
    } else {
        undef $disabled_users;
        return 0;
    }
}
# {{{ sub _GetBoundLdapObj

sub _GetBoundLdapObj {

    # Config as hashref
    my $config = shift;

    # Figure out what's what
    my $ldap_server     = $config->{'server'};
    my $ldap_user       = $config->{'user'};
    my $ldap_pass       = $config->{'pass'};
    my $ldap_tls        = $config->{'tls'};
    my $ldap_ssl_ver    = $config->{'ssl_version'};
    my $ldap_args       = $config->{'net_ldap_args'};
    
    my $ldap = new Net::LDAP($ldap_server, @$ldap_args);
    
    unless ($ldap) {
        $RT::Logger->critical(  (caller(0))[3],
                                ": Cannot connect to",
                                $ldap_server);
        return undef;
    }

    if ($ldap_tls) {
        $Net::SSLeay::ssl_version = $ldap_ssl_ver;
        # Thanks to David Narayan for the fault tolerance bits
        eval { $ldap->start_tls; };
        if ($@) {
            $RT::Logger->critical(  (caller(0))[3], 
                                    "Can't start TLS: ",
                                    $@);
            return;
        }

    }

    my $msg = undef;

    if (($ldap_user) and ($ldap_pass)) {
        $msg = $ldap->bind($ldap_user, password => $ldap_pass);
    } elsif (($ldap_user) and ( ! $ldap_pass)) {
        $msg = $ldap->bind($ldap_user);
    } else {
        $msg = $ldap->bind;
    }

    unless ($msg->code == LDAP_SUCCESS) {
        $RT::Logger->critical(  (caller(0))[3], 
                                "Can't bind:", 
                                ldap_error_name($msg->code), 
                                $msg->code);
        return undef;
    } else {
        return $ldap;
    }
}

sub Unbind {
    my $ldap = shift;
    my $res = $ldap->unbind;
    return $res if !$res || $res->code == LDAP_SUCCESS;

    $RT::Logger->error(
        (caller(1))[3], ": Could not unbind: ", 
        ldap_error_name($res->code), 
        $res->code
    );
    return $res;
}

sub PerformSearch {
    my $ldap = shift;
    my %args = @_;

    $args{'filter'} = Net::LDAP::Filter->new($args{'filter'})
        if $args{'filter'} && !ref $args{'filter'};

    $RT::Logger->debug(
        "LDAP Search === ",
        $args{'base'}? ("Base:", $args{'base'}) : (),
        $args{'filter'}? ("== Filter:", $args{'filter'}->as_string) : (),
        $args{'attrs'}? ("== Attrs:", join ',', @{ $args{'attrs'} }) : (),
    );
    
    my $res = $ldap->search( %args );
    return undef unless $res;

    unless (
        $res->code == LDAP_SUCCESS
        || $res->code == LDAP_PARTIAL_RESULTS
    ) {
        $RT::Logger->error(
            "Search for", $args{'filter'}->as_string, "failed:",
            ldap_error_name($res->code), $res->code
        );

        return undef;
    }
    return $res;
}

sub JoinFilters {
    my $op = shift;
    my @list =
        grep defined && length && $_ ne '()',
        map ref $_? $_->as_string : $_,
        @_;
    return undef unless @list;

    my $str = @list > 1
        ? "($op". join( '', @list ) .')'
        : $list[0]
    ;
    my $obj = Net::LDAP::Filter->new( $str );
    $RT::Logger->error("'$str' is not valid LDAP filter")
        unless $obj;

    return $obj;
}

# }}}

1;
