### User_Local.pm overlay for External Service authentication and information
###
### CREDITS
#
# Based on User_Local.pm for LDAP created by JimMeyer and found at:
#   http://wiki.bestpractical.com/view/LdapUserLocalOverlay
#
# His Credits:
#
#   IsLDAPPassword() based on implementation of IsPassword() found at:
#
#   http://www.justatheory.com/computers/programming/perl/rt/User_Local.pm.ldap
#
#   Author's credits:
#   Modification Originally by Marcelo Bartsch <bartschm_cl@hotmail.com>
#   Update by Stewart James <stewart.james@vu.edu.au for rt3.
#   Update by David Wheeler <david@kineticode.com> for TLS and 
#      Group membership support.
#
#
#   CaonicalizeEmailAddress(), CanonicalizeUserInfo(), and LookupExternalInfo()
#   based on work by Phillip Cole (phillip d cole @ uk d coltgroup d com)
#   found at:
#
#   http://wiki.bestpractical.com/view/AutoCreateAndCanonicalizeUserInfo
#
#   His credits:
#     based on CurrentUser_Local.pm and much help from the mailing lists 
#
#   All integrated, refactored, and updated by Jim Meyer (purp@acm.org)
#
# Modified to provide alternate external services authentication and information for rt3
# as part of RT::Authen::ExternalAuth by Mike Peachey (mike.peachey@jennic.com)

no warnings qw(redefine);
use strict;
use DBI;
use Net::LDAP qw(LDAP_SUCCESS LDAP_PARTIAL_RESULTS);
use Net::LDAP::Util qw(ldap_error_name);
use Net::LDAP::Filter;

# We only need Net::SSLeay if one of our external services requires 
# OpenSSL because it plans to use SSL or TLS to encrypt connections
require Net::SSLeay if $RT::ExternalServiceUsesSSLorTLS;

sub IsExternalPassword {
    my $self = shift;

    my $name_to_auth = $self->Name;
    my $pass_to_auth = shift;

    $RT::Logger->debug( (caller(0))[3],
                        "Trying External authentication");
    
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
            my $db_table        = $config->{'table'};
            my $db_u_field      = $config->{'u_field'};
            my $db_p_field 	    = $config->{'p_field'};
            my $db_p_enc_pkg    = $config->{'p_enc_pkg'};
            my $db_p_enc_sub    = $config->{'p_enc_sub'};

            # Set SQL query and bind parameters
            my $query = "SELECT $db_u_field,$db_p_field FROM $db_table WHERE $db_u_field=?";
            my @params = ($name_to_auth);
            
            # Uncomment this to trace basic DBI information and drop it in a log for debugging
            # DBI->trace(1,'/tmp/dbi.log');

            # Get DBI handle object (DBH), do SQL query, kill DBH
            my $dbh = $self->_GetBoundDBIObj($config);
            my $results_hashref = $dbh->selectall_hashref($query,$db_u_field,{},@params);
            $dbh->disconnect();

            my $num_users_returned = scalar keys %$results_hashref;
            if($num_users_returned != 1) { # FAIL
                # FAIL because more than one user returned. Users MUST be unique! 
                if ((scalar keys %$results_hashref) > 1) {
                    $RT::Logger->info(  $service,
                                        "AUTH FAILED",
                                        $name_to_auth,
                                        "More than one user with that username!");
                }

                # FAIL because no users returned. Users MUST exist! 
                if ((scalar keys %$results_hashref) < 1) {
                    $RT::Logger->info(  $service,
                                        "AUTH FAILED",
                                        $name_to_auth,
                                        "User not found in database!");
                }
  
        	    # Drop out to next external authentication service
        	    next;
            }
            
            # Get the user's password from the database query result
            my $pass_from_db = $results_hashref->{$name_to_auth}->{$db_p_field};        

            # This is the encryption package & subroutine passed in by the config file
            $RT::Logger->debug( "Encryption Package:",
                                $db_p_enc_pkg);
            $RT::Logger->debug( "Encryption Subroutine:",
                                $db_p_enc_sub);

            # Use config info to auto-load the perl package needed for password encryption
            # I know it uses a string eval - but I don't think there's a better way to do this
            # Jump to next external authentication service on failure
            eval "require $db_p_enc_pkg" or 
                $RT::Logger->error("AUTH FAILED, Couldn't Load Password Encryption Package. Error: $@") && next;
            
            my $encrypt = $db_p_enc_pkg->can($db_p_enc_sub);
            if (defined($encrypt)) {
                # If the package given can perform the subroutine given, then use it to compare the
                # password given with the password pulled from the database.
                # Jump to the next external authentication service if they don't match
                if(${encrypt}->($pass_to_auth) ne $pass_from_db){
                    $RT::Logger->info(  $service,
                                        "AUTH FAILED", 
                                        $name_to_auth, 
                                        "Password Incorrect");
                    next;
                }
            } else {
                # If the encryption package can't perform the request subroutine,
                # dump an error and jump to the next external authentication service.
                $RT::Logger->error($service,
                                    "AUTH FAILED",
                                    "The encryption package you gave me (",
                                    $db_p_enc_pkg,
                                    ") does not support the encryption method you specified (",
                                    $db_p_enc_sub,
                                    ")");
                    next;
            }
            
            # Any other checks you want to add? Add them here.

            # If we've survived to this point, we're good.
            $RT::Logger->info(  (caller(0))[3], 
                                "External Auth OK (",
                                $service,
                                "):", 
                                $name_to_auth);
            return 1;
            
        } elsif ($config->{'type'} eq 'ldap') {
            my $base            = $config->{'base'};
            my $filter          = $config->{'filter'};
            my $group           = $config->{'group'};
            my $group_attr      = $config->{'group_attr'};
            my $attr_map        = $config->{'attr_map'};
            my @attrs           = ('dn');

            # Empty parentheses as filters cause Net::LDAP to barf.
            # We take care of this by using Net::LDAP::Filter, but
            # there's no harm in fixing this right now.
            if ($filter eq "()") { undef($filter) };

            # Now let's get connected
            my $ldap = $self->_GetBoundLdapObj($config);
            next unless ($ldap);

            $filter = Net::LDAP::Filter->new(   '(&(' . 
                                                $attr_map->{'Name'} . 
                                                '=' . 
                                                $self->Name . 
                                                ')' . 
                                                $filter . 
                                                ')'
                                            );

            $RT::Logger->debug( "LDAP Search === ",
                                "Base:",
                                $base,
                                "== Filter:", 
                                $filter->as_string,
                                "== Attrs:", 
                                join(',',@attrs));

            my $ldap_msg = $ldap->search(   base   => $base,
                                            filter => $filter,
                                            attrs  => \@attrs);

            unless ($ldap_msg->code == LDAP_SUCCESS || $ldap_msg->code == LDAP_PARTIAL_RESULTS) {
                $RT::Logger->debug( "search for", 
                                    $filter->as_string, 
                                    "failed:", 
                                    ldap_error_name($ldap_msg->code), 
                                    $ldap_msg->code);
                # Didn't even get a partial result - jump straight to the next external auth service
                next;
            }

            unless ($ldap_msg->count == 1) {
                $RT::Logger->info(  $service,
                                    "AUTH FAILED:", 
                                    $self->Name,
                                    "User not found or more than one user found");
                # We got no user, or too many users.. jump straight to the next external auth service
                next;
            }

            my $ldap_dn = $ldap_msg->first_entry->dn;
            $RT::Logger->debug( "Found LDAP DN:", 
                                $ldap_dn);

            # THIS bind determines success or failure on the password.
            $ldap_msg = $ldap->bind($ldap_dn, password => $pass_to_auth);

            unless ($ldap_msg->code == LDAP_SUCCESS) {
                $RT::Logger->info(  $service,
                                    "AUTH FAILED", 
                                    $self->Name, 
                                    "(can't bind:", 
                                    ldap_error_name($ldap_msg->code), 
                                    $ldap_msg->code, 
                                    ")");
                # Could not bind to the LDAP server as the user we found with the password
                # we were given, therefore the password must be wrong so we fail and
                # jump straight to the next external auth service
                next;
            }

            # The user is authenticated ok, but is there an LDAP Group to check?
            if ($group) {
                # If we've been asked to check a group...
                $filter = Net::LDAP::Filter->new("(${group_attr}=${ldap_dn})");
                
                $RT::Logger->debug( "LDAP Search === ",
                                    "Base:",
                                    $base,
                                    "== Filter:", 
                                    $filter->as_string,
                                    "== Attrs:", 
                                    join(',',@attrs));
                
                $ldap_msg = $ldap->search(  base   => $group,
                                            filter => $filter,
                                            attrs  => \@attrs,
                                            scope  => 'base');

                # And the user isn't a member:
                unless ($ldap_msg->code == LDAP_SUCCESS || 
                        $ldap_msg->code == LDAP_PARTIAL_RESULTS) {
                    $RT::Logger->critical(  "Search for", 
                                            $filter->as_string, 
                                            "failed:",
                                            ldap_error_name($ldap_msg->code), 
                                            $ldap_msg->code);

                    # Fail auth - jump to next external auth service
                    next;
                }

                unless ($ldap_msg->count == 1) {
                    $RT::Logger->info(  $service,
                                        "AUTH FAILED:", 
                                        $self->Name);
                                        
                    # Fail auth - jump to next external auth service
                    next;
                }
            }
            
            # Any other checks you want to add? Add them here.

            # If we've survived to this point, we're good.
            $RT::Logger->info(  (caller(0))[3], 
                                "External Auth OK (",
                                $service,
                                "):", 
                                $name_to_auth);
            return 1;
        
        } else {
            $RT::Logger->error("Invalid type specification in config",$service);
        }
    } 

    # If we still haven't returned, we must have been unsuccessful
    $RT::Logger->info(  (caller(0))[3], 
                        "External Auth Failed:", 
                        $name_to_auth);
    return 0;
}

sub IsInternalPassword {
    my $self = shift;
    my $value = shift;

    unless ($self->HasPassword) {
        $RT::Logger->info(  (caller(0))[3], 
                            "AUTH FAILED (no passwd):", 
                            $self->Name);
        return(undef);
    }

    # generate an md5 password 
    if ($self->_GeneratePassword($value) eq $self->__Value('Password')) {
        $RT::Logger->info(  (caller(0))[3], 
                            "AUTH OKAY:", 
                            $self->Name);
        return(1);
    }

    #  if it's a historical password we say ok.
    if ($self->__Value('Password') eq crypt($value, $self->__Value('Password'))
        or $self->_GeneratePasswordBase64($value) eq $self->__Value('Password'))
      {
          # ...but upgrade the legacy password inplace.
          $self->SUPER::SetPassword( $self->_GeneratePassword($value) );
          $RT::Logger->info((caller(0))[3], 
                            "AUTH OKAY:", 
                            $self->Name);
          return(1);
      }

    $RT::Logger->info(  (caller(0))[3], 
                        "AUTH FAILED:", 
                        $self->Name);

    return(undef);
}

# {{{ sub IsPassword 

sub IsPassword {
    my $self  = shift;
    my $value = shift;

    # TODO there isn't any apparent way to legitimately ACL this

    # RT does not allow null passwords 
    if ( ( !defined($value) ) or ( $value eq '' ) ) {
        return (undef);
    }

    if ( $self->PrincipalObj->Disabled ) {
        $RT::Logger->info("Disabled user " . $self->Name . 
                          " tried to log in" );
        return (undef);
    }

    my $success = undef;

    $success = $self->IsExternalPassword($value);
    $RT::Logger->debug( (caller(0))[3], 
                        "External auth", 
                        ($success ? 'SUCCEEDED' : 'FAILED'));
    
    unless ($success) {
        $success = $self->IsInternalPassword($value);
        $RT::Logger->debug( (caller(0))[3], 
                            "Internal auth", 
                            ($success ? 'SUCCEEDED' : 'FAILED'));
    }
    # We either got it or we didn't
    return ($success);
}

# }}}


# {{{ sub CanonicalizeUserInfo

=head2 CanonicalizeUserInfo HASHREF

Get all ExternalDB attrs listed in $RT::ExternalDBAttrMap and put them into
the hash referred to by HASHREF.

returns true (1) if ExternalDB lookup was successful, false (undef)
in all other cases.

=cut

sub CanonicalizeUserInfo {
    my $self = shift;
    my $args = shift;

    my $found = 0;
    my %params = ();

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
            # Jump to the next attr if it's not an RT attr passed in $args
            $RT::Logger->debug( "Attempting to use this canonicalization key:",
                                $rt_attr);
            next unless defined($args->{$rt_attr});
                                
            # Else, use it as a key for LookupExternalUserInfo    
            ($found, %params) = 
                $self->LookupExternalUserInfo($config->{'attr_map'}->{$rt_attr},$args->{$rt_attr});
         
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
# }}}

# {{{ sub LookupExternalUserInfo

=head2 LookupExternalUserInfo KEY VALUE [BASE_DN]

LookupExternalUserInfo takes a key/value pair, looks it up externally, 
and returns a params hash containing all attrs listed in the source's 
attr_map, suitable for creating an RT::User object.

Returns a tuple, ($found, %params)

=cut

sub LookupExternalUserInfo {
    my $self = shift;
    my ($key, $value) = @_;
    
    # Set up worst case return info
    my $found = 0;
    my %params = (Name         => undef,
                  EmailAddress => undef,
                  RealName     => undef);
    
    # Get the list of information services in priority order from the SiteConfig
    my @info_services = $RT::ExternalInfoPriority ? @{$RT::ExternalInfoPriority} : undef;
    foreach my $service (@info_services) {
        # Get the full configuration for the service in question
        my $config = $RT::ExternalSettings->{$service};
        
        my $valid = 0;
        my ($attr_key, $attr_value);
        my $attr_map = $config->{'attr_map'};
        while (($attr_key, $attr_value) = each %$attr_map) {
            $valid = 1 if ($key eq $attr_value);
        }
        unless ($valid){
            $RT::Logger->debug( $key,
                                "is not valid attribute key (",
                                $service,
                                ") - Trying Next Service");
            next;
        }
        
        # Use an if/elsif structure to do a lookup with any custom code needed 
        # for any given type of external service, or die if no code exists for
        # the service requested.
        
        if($config->{'type'} eq 'ldap'){
            # Figure out what's what
            my $base            = $config->{'base'};
            my $filter          = $config->{'filter'};

            # Get the list of unique attrs we need
            my @attrs = values(%{$config->{'attr_map'}});

            # This is a bit confusing and probably broken. Something to revisit..
            my $filter_addition = ($key && $value) ? "(". $key . "=$value)" : "";
            if(defined($filter) && ($filter ne "()")) {
                $filter = Net::LDAP::Filter->new(   "(&" . 
                                                    $filter . 
                                                    $filter_addition . 
                                                    ")"
                                                ); 
            } else {
                $RT::Logger->debug( "LDAP Filter invalid or not present.");
            }
            
            unless ($base) {
                $RT::Logger->critical(  (caller(0))[3],
                                        "No base given");
                # Drop out to the next external information service
                next;
            }
            
            # Get a Net::LDAP object based on the config we provide
            my $ldap = $self->_GetBoundLdapObj($config);

            # Jump to the next external information service if we can't get one, 
            # errors should be logged by _GetBoundLdapObj so we don't have to.
            next unless ($ldap);

            # Do a search for them in LDAP
            $RT::Logger->debug( "LDAP Search === ",
                                "Base:",
                                $base,
                                "== Filter:", 
                                $filter->as_string,
                                "== Attrs:", 
                                join(',',@attrs));
 
            my $ldap_msg = $ldap->search(base   => $base,
                                         filter => $filter,
                                         attrs  => \@attrs);

            # If we didn't get at LEAST a partial result, just die now.
            if ($ldap_msg->code != LDAP_SUCCESS and 
                $ldap_msg->code != LDAP_PARTIAL_RESULTS) {
                $RT::Logger->critical(  (caller(0))[3],
                                        ": Search for ",
                                        $filter->as_string,
                                        " failed: ",
                                        ldap_error_name($ldap_msg->code), 
                                        $ldap_msg->code);
                # $found remains as 0
                
                # Drop out to the next external information service
                $ldap_msg = $ldap->unbind();
                if ($ldap_msg->code != LDAP_SUCCESS) {
                    $RT::Logger->critical(  (caller(0))[3],
                                            ": Could not unbind: ", 
                                            ldap_error_name($ldap_msg->code), 
                                            $ldap_msg->code);
                }
                undef $ldap;
                undef $ldap_msg;
                next;
              
            } else {
                # If there's only one match, we're good; more than one and
                # we don't know which is the right one so we skip it.
                if ($ldap_msg->count == 1) {
                    my $entry = $ldap_msg->first_entry();
                    foreach my $key (keys(%{$config->{'attr_map'}})) {
                        if ($RT::LdapAttrMap->{$key} eq 'dn') {
                            $params{$key} = $entry->dn();
                        } else {
                            $params{$key} = 
                              ($entry->get_value($config->{'attr_map'}->{$key}))[0];
                        }
                    }
                    $found = 1;
                } else {
                    # Drop out to the next external information service
                    $ldap_msg = $ldap->unbind();
                    if ($ldap_msg->code != LDAP_SUCCESS) {
                        $RT::Logger->critical(  (caller(0))[3],
                                                ": Could not unbind: ", 
                                                ldap_error_name($ldap_msg->code), 
                                                $ldap_msg->code);
                    }
                    undef $ldap;
                    undef $ldap_msg;
                    next;
                }
            }
            $ldap_msg = $ldap->unbind();
            if ($ldap_msg->code != LDAP_SUCCESS) {
                $RT::Logger->critical(  (caller(0))[3],
                                        ": Could not unbind: ", 
                                        ldap_error_name($ldap_msg->code), 
                                        $ldap_msg->code);
            }

            undef $ldap;
            undef $ldap_msg;
            last if $found;
        
        } elsif ($config->{'type'} eq 'db') {
            # Figure out what's what
            my $table      = $config->{'table'};

            unless ($table) {
                $RT::Logger->critical(  (caller(0))[3],
                                        "No table given");
                # Drop out to the next external information service
                next;
            }

            unless ($key && $value){
                $RT::Logger->critical(  (caller(0))[3],
                                        " Nothing to look-up given");
                # Drop out to the next external information service
                next;
            }
            
            # "where" refers to WHERE section of SQL query
            my ($where_key,$where_value) = ("@{[ $key ]}",$value);

            # Get the list of unique attrs we need
            my %db_attrs = map {$_ => 1} values(%{$config->{'attr_map'}});
            my @attrs = keys(%db_attrs);
            my $fields = join(',',@attrs);
            my $query = "SELECT $fields FROM $table WHERE $where_key=?";
            my @bind_params = ($where_value);

            # Uncomment this to trace basic DBI throughput in a log
            # DBI->trace(1,'/tmp/dbi.log');
            my $dbh = $self->_GetBoundDBIObj($config);
            my $results_hashref = $dbh->selectall_hashref($query,$key,{},@bind_params);
            $dbh->disconnect();

            if ((scalar keys %$results_hashref) != 1) {
                # If returned users <> 1, we have no single unique user, so prepare to die
                my $death_msg;
                
        	    if ((scalar keys %$results_hashref) == 0) {
                    # If no user...
        	        $death_msg = "No User Found in External Database!";
                } else {
                    # If more than one user...
                    $death_msg = "More than one user found in External Database with that unique identifier!";
                }

                # Log the death
                $RT::Logger->info(  (caller(0))[3],
                                    "INFO CHECK FAILED",
                                    "Key: $key",
                                    "Value: $value",
                                    $death_msg);
                
                # $found remains as 0
                
                # Drop out to next external information service
                next;
            }

            # We haven't dropped out, so DB search must have succeeded with 
            # exactly 1 result. Log it, get the result and set $found to 1
            my $result = $results_hashref->{$value};
         
            # Use the result to populate %params for every key we're given in the config
            foreach my $key (keys(%{$config->{'attr_map'}})) {
                $params{$key} = ($result->{$config->{'attr_map'}->{$key}})[0];
            }
            
            $found = 1;
            last;

        } else {
            $RT::Logger->debug( (caller(0))[3],
                                "does not consider",
                                $service,
                                "a valid information service");
        }
        
        # If our external service found a user, then drop out
        # We don't want to check any lower-priority info services.
        last if $found;
    }    

    # Why on earth do we return the same RealName, just quoted?!
    # Seconded by Mike Peachey - I'd like to know that too!!
    # Sod it, until it breaks something, I'm removing this line forever!
    # $params{'RealName'} = "\"$params{'RealName'}\"";
    
    $RT::Logger->info(  (caller(0))[3],
                        ": Returning: ",
                        join(", ", map {sprintf("%s: %s", $_, $params{$_})}
                            sort(keys(%params))));
    
    $RT::Logger->debug( (caller(0))[3],
                        "No user was found this time"
                      ) if ($found == 0);

    return ($found, %params);
}

# }}}


sub UpdateFromExternal {
    my $self = shift;

    # Prepare for the worst...
    my $found = 0;
    my $updated = 0;
    my $msg = "User NOT updated";
    
    my $name_to_update  	= $self->Name;
    my $user_disabled 	    = 0;
    
    # Get the list of information service names requested by user.    
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
        next unless defined($config);
        
        # If it's a DBI config:
        if ($config->{'type'} eq 'db') {
            # Get the necessary config info
            my $table    	        = $config->{'table'};
    	    my $u_field	            = $config->{'u_field'};
            my $disable_field       = $config->{'d_field'};
            my $disable_values_list = $config->{'d_values'};

            # Only lookup disable information from the DB if a disable_field has been set
            if ($disable_field) { 
                my $query = "SELECT $u_field,$disable_field FROM $table WHERE $u_field=?";
        	    my @bind_params = ($name_to_update);

                # Uncomment this to do a basic trace on DBI information and log it
                # DBI->trace(1,'/tmp/dbi.log');
                
                # Get DBI Object, do the query, disconnect
                my $dbh = $self->_GetBoundDBIObj($config);
                my $results_hashref = $dbh->selectall_hashref($query,$u_field,{},@bind_params);
                $dbh->disconnect();

                my $num_of_results = scalar keys %$results_hashref;
                    
                if ($num_of_results > 1) { 
                    # If more than one result returned, die because we the username field should be unique!
                    $RT::Logger->debug( "Disable Check Failed :: (",
                                        $service,
                                        ")",
                                        $name_to_update,
                                        "More than one user with that username!");
                    # Drop out to next service for an info check
                    next;
                } elsif ($num_of_results < 1) { 
                    # If 0 or negative integer, no user found or major failure
                    $RT::Logger->debug( "Disable Check Failed :: (",
                                        $service,
                                        ")",
                                        $name_to_update,
                                        "User not found");   
                    # Drop out to next service for an info check
                    next;             
                } else { 
                    # otherwise all should be well
                    
                    # $user_db_disable_value = The value for "disabled" returned from the DB
                    my $user_db_disable_value = $results_hashref->{$name_to_update}->{$disable_field};
                    
                    # For each of the values in the (list of values that we consider to mean the user is disabled)..
                    foreach my $disable_value (@{$disable_values_list}){
                        $RT::Logger->debug( "DB Disable Check:", 
                                            "User's Val is $user_db_disable_value,",
                                            "Checking against: $disable_value");
                        
                        # If the value from the DB matches a value from the list, the user is disabled.
                        if ($user_db_disable_value eq $disable_value) {
                            $user_disabled = 1;
                        }
                    }
                }
            }
            
            # If we havent been dropped out by a "next;" by now, 
            # then this will be the authoritative service
            
        } elsif ($config->{'type'} eq 'ldap') {
            
            my $base            = $config->{'base'};
            my $filter          = $config->{'filter'};
            my $disable_filter  = $config->{'d_filter'};
            
            my ($u_filter,$d_filter);

            # While LDAP filters must be surrounded by parentheses, an empty set
            # of parentheses is an invalid filter and will cause failure
            # This shouldn't matter since we are now using Net::LDAP::Filter below,
            # but there's no harm in doing this to be sure
            if ($filter eq "()") { undef($filter) };
            if ($disable_filter eq "()") { undef($disable_filter) };


            if (defined($config->{'attr_map'}->{'Name'})) {
                # Construct the complex filter
                $disable_filter = Net::LDAP::Filter->new(   '(&' . 
                                                            $filter . 
                                                            $disable_filter . 
                                                            '(' . 
                                                            $config->{'attr_map'}->{'Name'} . 
                                                            '=' . 
                                                            $self->Name . 
                                                            '))'
                                                        );
                $filter = Net::LDAP::Filter->new(           '(&' . 
                                                            $filter . 
                                                            '(' . 
                                                            $config->{'attr_map'}->{'Name'} . 
                                                            '=' . 
                                                            $self->Name . 
                                                            '))'
                                                );
            }
 
            my $ldap = $self->_GetBoundLdapObj($config);
            next unless $ldap;

            my @attrs = values(%{$config->{'attr_map'}});

            # FIRST, check that the user exists in the LDAP service
            $RT::Logger->debug( "LDAP Search === ",
                                "Base:",
                                $base,
                                "== Filter:", 
                                $filter->as_string,
                                "== Attrs:", 
                                join(',',@attrs));
            
            my $user_found = $ldap->search( base    => $base,
                                            filter  => $filter,
                                            attrs   => \@attrs);

            if($user_found->count < 1) {
                # If 0 or negative integer, no user found or major failure
                $RT::Logger->debug( "Disable Check Failed :: (",
                                    $service,
                                    ")",
                                    $name_to_update,
                                    "User not found");   
                # Drop out to next service for an info check
                next;  
            } elsif ($user_found->count > 1) {
                # If more than one result returned, die because we the username field should be unique!
                $RT::Logger->debug( "Disable Check Failed :: (",
                                    $service,
                                    ")",
                                    $name_to_update,
                                    "More than one user with that username!");
                # Drop out to next service for an info check
                next;
            }
            undef $user_found;
                        
            # SECOND, now we know the user exists in the service, 
            # check if they are returned in a search for disabled users 
            
            # We only need the UID for confirmation now, 
            # the other information would waste time and bandwidth
            @attrs = ('uid'); 
            
            $RT::Logger->debug( "LDAP Search === ",
                                "Base:",
                                $base,
                                "== Filter:", 
                                $disable_filter->as_string,
                                "== Attrs:", 
                                join(',',@attrs));
                  
            my $disabled_users = $ldap->search(base   => $base, 
                                               filter => $disable_filter, 
                                               attrs  => \@attrs);
            # If ANY results are returned, 
            # we are going to assume the user should be disabled
            if ($disabled_users->count) {
               $user_disabled = 1;
            }
            
            # If we havent been dropped out by a "next;" by now, 
            # then this will be the authoritative service
            
        } else {
            # The type of external service doesn't currently have any methods associated with it. Or it's a typo.
            RT::Logger->error("Invalid type specification for config %config->{'name'}");
            # Drop out to next service in list
            next;
        }
        
        # We are now going to update the user's information from the authoritative source
        # Although we are in a foreach, the statements below will only be executed once.
        # The external services have been checked in the priority order specified by the config.
        # If the user wasn't found in an individual service, we will already have jumped to the next one,
        # or we will have dropped out to the return statement at the base of the function if the user wasn't
        # found in ANY external services.
        
        # The user must have been found in a service to get here so we run the update code 
        # and then "last" out of the foreach so that we only update from one source.
        # and then return out of the function 
        
        # So, breathe, and on we go...
        
        # Load the user inside an RT::SystemUser so you can  set their 
        # information no matter who they are or what permissions they have
        my $UserObj = RT::User->new($RT::SystemUser);
        $UserObj->Load($name_to_update);        

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
            $RT::Logger->info("DISABLED user ",
                                $name_to_update,
                                "per External Service", 
                                "($val, $message)\n");
            $msg = "User disabled";
        } else {
            # Make sure principle is not disabled in RT
            my ($val, $message) = $UserObj->SetDisabled(0);
            # Log what has happened
            $RT::Logger->info("ENABLED user ",
                                $name_to_update,
                                "per External Service",
                                "($val, $message)\n");

            # Update their info from external service using the username as the lookup key
            # CanonicalizeUserInfo will work out for itself which service to use
            # Passing it a service instead could break other RT code
            my %args = (Name => $name_to_update);
            $self->CanonicalizeUserInfo(\%args);

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
            $RT::Logger->debug( "UPDATED user ",
                                $name_to_update,
                                "from External Service\n");
            $msg = 'User updated';
            
            # Just in case we're not the last iteration of the foreach,
            # drop out to the return statement now.
            last;

        }
    }

    return ($updated, $msg);
}

# {{{ sub _GetBoundLdapObj

sub _GetBoundLdapObj {
    my $self = shift;

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

    # Can't decide whether to add a little more error checking here..
    # Perhaps, if user && pass, else dont pass a pass etc..
    if ($ldap_user) {
        $msg = $ldap->bind($ldap_user, password => $ldap_pass);
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

# }}}

# {{{ sub _GetBoundDBIObj

sub _GetBoundDBIObj {
    my $self = shift;
    
    # Config as hashref.
    my $config = shift;

    # Extract the relevant information from the config.
    my $db_server     = $config->{'server'};
    my $db_user       = $config->{'user'};
    my $db_pass       = $config->{'pass'};
    my $db_database   = $config->{'database'};
    my $db_port       = $config->{'port'};
    my $dbi_driver    = $config->{'dbi_driver'};

    # Use config to create a DSN line for the DBI connection
    my $dsn = "dbi:$dbi_driver:database=$db_database;host=$db_server;port=$db_port";

    # Now let's get connected
    my $dbh = DBI->connect($dsn, $db_user, $db_pass,{RaiseError => 1, AutoCommit => 0 })
            or die $DBI::errstr;

    # If we didn't die, return the DBI object handle 
    # and hope it's treated sensibly and correctly 
    # destroyed by the calling code
    return $dbh;
}

# }}}

1;
