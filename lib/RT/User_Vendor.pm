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
use RT::Authen::ExternalAuth::LDAP;
use RT::Authen::ExternalAuth::DBI;

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
            my $success = RT::Authen::ExternalAuth::DBI->getAuth($service,$name_to_auth,$pass_to_auth);
            return 1 if $success;
            next;
            
        } elsif ($config->{'type'} eq 'ldap') {
            my $success = RT::Authen::ExternalAuth::LDAP->getAuth($service,$name_to_auth,$pass_to_auth);
            return 1 if $success;
            next;
                    
        } else {
            $RT::Logger->error("Invalid type specification in config for service:",$service);
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

    if ( $self->PrincipalObj && $self->PrincipalObj->Disabled ) {
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
                                
            # Else, use it as a key for GetUserInfoHash    
            ($found, %params) = 
                $self->GetUserInfoHash($service,$config->{'attr_map'}->{$rt_attr},$args->{$rt_attr});
         
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

=head2 GetUserInfoHash SERVICE KEY VALUE

LookupExternalUserInfo takes a key/value pair and an external service
to look it up in; looks it up and returns a params hash containing 
all attrs listed in the source's attr_map, suitable for creating 
an RT::User object.

Returns a tuple, ($found, %params)

=cut

sub GetUserInfoHash {
    my $self = shift;
    my ($service,$key, $value) = @_;
    
    # Haven't got anything yet..
    my $found = 0;
    my %params = (Name         => undef,
                  EmailAddress => undef,
                  RealName     => undef);
    
    # Get the full configuration for the service in question
    my $config = $RT::ExternalSettings->{$service};
    
    # Check to see that the key being asked for is defined in the config's attr_map
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
                            ")");
        return ($found, %params);
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


    # Why on earth do we return the same RealName, just quoted?!
    # Seconded by Mike Peachey - I'd like to know that too!!
    # Sod it, until it breaks something, I'm removing this line forever!
    # $params{'RealName'} = "\"$params{'RealName'}\"";
    
    
    # Log the info found and return it
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

            unless ($disable_filter) {
                $RT::Logger->error("You haven't specified a d_filter in your configuration.  Not specifying a d_filter usually results in all users being marked as disabled and being unable to log in");
            }

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



1;
