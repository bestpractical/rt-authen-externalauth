package RT::Authen::ExternalAuth;

our $VERSION = '0.07_01';

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
ok(require RT::Authen::ExternalAuth::LDAP);
ok(require RT::Authen::ExternalAuth::DBI);

=end testing
    
use RT::Authen::ExternalAuth::LDAP;
use RT::Authen::ExternalAuth::DBI;

=cut

sub UpdateUserInfo {
    my $username        = shift;

    # Prepare for the worst...
    my $found           = 0;
    my $updated         = 0;
    my $msg             = "User NOT updated";

    my $user_disabled 	= RT::Authen::ExternalAuth->UserDisabled($username);

    my $UserObj = RT::User->new($RT::SystemUser);
    $UserObj->Load($username);        

    # If user is disabled, set the RT::Principle to disabled and return out of the function.
    # I think it's a waste of time and energy to update a user's information if they are disabled
    # and it could be a security risk if they've updated their external information with some 
    # carefully concocted code to try to break RT - worst case scenario, but they have been 
    # denied access after all, don't take any chances.
     
    # If someone gives me a good enough reason to do it, 
    # then I'll update all the info for disabled users

    if ($user_disabled) {
        # Make sure principle is disabled in RT
        my ($val, $message) = $UserObj->SetDisabled(1);
        # Log what has happened
        $RT::Logger->info("User marked as DISABLED (",
                            $username,
                            ") per External Service", 
                            "($val, $message)\n");
        $msg = "User Disabled";
        
        return ($updated, $msg);
    }    
        
    # Make sure principle is not disabled in RT
    my ($val, $message) = $UserObj->SetDisabled(0);
    # Log what has happened
    $RT::Logger->info("User marked as ENABLED (",
                        $username,
                        ") per External Service",
                        "($val, $message)\n");

    # Update their info from external service using the username as the lookup key
    # CanonicalizeUserInfo will work out for itself which service to use
    # Passing it a service instead could break other RT code
    my %args = (Name => $username);
    $UserObj->CanonicalizeUserInfo(\%args);

    # For each piece of information returned by CanonicalizeUserInfo,
    # run the Set method for that piece of info to change it for the user
    foreach my $key (sort(keys(%args))) {
        next unless $args{$key};
        my $method = "Set$key";
        # We do this on the UserObj from above, not self so that there 
        # are no permission restrictions on setting information
        my ($method_success,$method_msg) = $UserObj->$method($args{$key});
        
        # If your user information is not getting updated, 
        # uncomment the following logging statements
        if ($method_success) {
            # At DEBUG level, log that method succeeded
            # $RT::Logger->debug((caller(0))[3],"$method Succeeded. $method_msg");
        } else {
            # At DEBUG level, log that method failed
            # $RT::Logger->debug((caller(0))[3],"$method Failed. $method_msg");
        }
    }

    # Confirm update success
    $updated = 1;
    $RT::Logger->debug( "UPDATED user (",
                        $username,
                        ") from External Service\n");
    $msg = 'User updated';

    return ($updated, $msg);
}

sub UserExists {

    my $username = shift;
    my $user_exists_externally = 0;   

    my @auth_services = @$RT::ExternalAuthPriority;
    foreach my $service (@auth_services) {
        my $config = $RT::Settings->{$service};
        if ($config->{'type'} eq 'db') {    
            $user_exists_externally = RT::Authen::ExternalAuth::DBI->UserExists($service,$user);
            last if $user_exists_externally;
        } elsif ($config->{'type'} eq 'ldap') {
            $user_exists_externally = RT::Authen::ExternalAuth::LDAP->UserExists($service,$user);
            last if $user_exists_externally;
        } else {
            $RT::Logger->error("Invalid type specification in config for service:",$service);
        }
    }
    
    return $user_exists_externally;
}

sub GetAuth {
    
    my ($username,$password) = @_;
    
    # Get the prioritised list of external authentication services
    my @auth_services = @$RT::ExternalAuthPriority;
    
    # For each of those services..
    foreach my $service (@auth_services) {

        # Get the full configuration for that service as a hashref
        my $config = $RT::ExternalSettings->{$service};
        $RT::Logger->debug( "Attempting to use external auth service:",
                            $service);
        
        # And then act accordingly depending on what type of service it is.
        # Right now, there is only code for DBI and LDAP services
        if ($config->{'type'} eq 'db') {    
            my $success = RT::Authen::ExternalAuth::DBI->GetAuth($service,$username,$password);
            return 1 if $success;
            next;
            
        } elsif ($config->{'type'} eq 'ldap') {
            my $success = RT::Authen::ExternalAuth::LDAP->GetAuth($service,$username,$password);
            return 1 if $success;
            next;
                    
        } else {
            $RT::Logger->error("Invalid type specification in config for service:",
                                $service,
                                "- Skipping...");
        }
    }
    
    # No success by now = failure.
    return 0; 

}

sub UserDisabled {
    
    my $username = shift;
    my $user_disabled = 0;
    
    my @info_services = $RT::ExternalInfoPriority ? @{$RT::ExternalInfoPriority} : undef;

    # For each named service in the list
    # Check to see if the user is found in the external service
    # If not found, jump to next service
    # If found, check to see if user is considered disabled by the service
    # Then update the user's info in RT and return
    foreach my $service (@info_services) {
        
        # Get the external config for this service as a hashref        
        my $config = $RT::ExternalSettings->{$service};
        
        # If the config doesn't exist, don't bother doing anything, skip to next in list.
        unless(defined($config)) {
            $RT::Logger->debug("You haven't defined a configuration for the service named \"",
                                $service,
                                "\" so I'm not going to try to get user information from it. Skipping...");
            next;
        }
        
        # If it's a DBI config:
        if ($config->{'type'} eq 'db') {
            
            unless(RT::Authen::ExternalAuth::DBI->UserExists($username,$service)) {
                $RT::Logger->debug("User (",
                                    $username,
                                    ") doesn't exist in service (",
                                    $service,
                                    ") - Cannot update information - Skipping...");
                next;
            }
            $user_disabled = RT::Authen::ExternalAuth::DBI->UserDisabled($username,$service);
            
        } elsif ($config->{'type'} eq 'ldap') {
            
            unless(RT::Authen::ExternalAuth::LDAP->UserExists($username,$service)) {
                $RT::Logger->debug("User (",
                                    $username,
                                    ") doesn't exist in service (",
                                    $service,
                                    ") - Cannot update information - Skipping...");
                next;
            }
            $user_disabled = RT::Authen::ExternalAuth::LDAP->UserDisabled($username,$service);
            
        } else {
            # The type of external service doesn't currently have any methods associated with it. Or it's a typo.
            RT::Logger->error("Invalid type specification for config %config->{'name'}");
            # Drop out to next service in list
            next;
        }
    
    }
    return $user_disabled;
}

sub CanonicalizeUserInfo {
    
    # Careful, this $args hashref was given to RT::User::CanonicalizeUserInfo and
    # then transparently passed on to this function. The whole purpose is to update
    # the original hash as whatever passed it to RT::User is expecting to continue its
    # code with an update args hash.
    
    my $UserObj = shift;
    my $args    = shift;
    
    my $found   = 0;
    my %params  = (Name         => undef,
                  EmailAddress => undef,
                  RealName     => undef);
    
    $RT::Logger->debug( (caller(0))[3], 
                        "called by", 
                        caller, 
                        "with:", 
                        join(", ", map {sprintf("%s: %s", $_, $args->{$_})}
                            sort(keys(%$args))));

    # Get the list of defined external services
    my @info_services = $RT::ExternalInfoPriority ? @{$RT::ExternalInfoPriority} : undef;
    # For each external service...
    foreach my $service (@info_services) {
        
        $RT::Logger->debug( "Attempting to get user info using this external service:",
                            $service);
        
        # Get the config for the service so that we know what attrs we can canonicalize
        my $config = $RT::ExternalSettings->{$service};
        
        # For each attr we've been told to canonicalize in the match list
        foreach my $rt_attr (@{$config->{'attr_match_list'}}) {
            # Jump to the next attr in $args if this one isn't in the attr_match_list
            $RT::Logger->debug( "Attempting to use this canonicalization key:",$rt_attr);
            unless(defined($args->{$rt_attr})) {
                $RT::Logger->debug("This attribute (",
                                    $rt_attr,
                                    ") is not defined in the attr_match_list for this service (",
                                    $service,
                                    ")");
                next;
            }
                               
            # Else, use it as a canonicalization key and lookup the user info    
            my $key = $config->{'attr_map'}->{$rt_attr};
            my $value = $args->{$rt_attr};
            
            # Check to see that the key being asked for is defined in the config's attr_map
            my $valid = 0;
            my ($attr_key, $attr_value);
            my $attr_map = $config->{'attr_map'};
            while (($attr_key, $attr_value) = each %$attr_map) {
                $valid = 1 if ($key eq $attr_value);
            }
            unless ($valid){
                $RT::Logger->debug( "This key (",
                                    $key,
                                    "is not a valid attribute key (",
                                    $service,
                                    ")");
                next;
            }
            
            # Use an if/elsif structure to do a lookup with any custom code needed 
            # for any given type of external service, or die if no code exists for
            # the service requested.
            
            if($config->{'type'} eq 'ldap'){    
                ($found, %params) = RT::Authen::ExternalAuth::LDAP->CanonicalizeUserInfo($service,$key,$value);
            } elsif ($config->{'type'} eq 'db') {
                ($found, %params) = RT::Authen::ExternalAuth::DBI->CanonicalizeUserInfo($service,$key,$value);
            } else {
                $RT::Logger->debug( (caller(0))[3],
                                    "does not consider",
                                    $service,
                                    "a valid information service");
            }
       
            # Don't Check any more attributes
            last if $found;
        }
        # Don't Check any more services
        last if $found;
    }
    
    # If found, Canonicalize Email Address and 
    # update the args hash that we were given the hashref for
    if ($found) {
        # It's important that we always have a canonical email address
        if ($params{'EmailAddress'}) {
            $params{'EmailAddress'} = $self->CanonicalizeEmailAddress($params{'EmailAddress'});
        } 
        %$args = (%$args, %params);
    }

    $RT::Logger->info(  (caller(0))[3], 
                        "returning", 
                        join(", ", map {sprintf("%s: %s", $_, $args->{$_})} 
                            sort(keys(%$args))));

    ### HACK: The config var below is to overcome the (IMO) bug in
    ### RT::User::Create() which expects this function to always
    ### return true or rejects the user for creation. This should be
    ### a different config var (CreateUncanonicalizedUsers) and 
    ### should be honored in RT::User::Create()
    return($found || $RT::AutoCreateNonExternalUsers);
   
}
1;
