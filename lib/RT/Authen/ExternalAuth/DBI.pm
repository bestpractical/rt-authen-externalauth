package RT::Authen::ExternalAuth::DBI;
use DBI;

sub getAuth {

    my ($service, $username, $password) = @_;
    
    my $config = $RT::ExternalSettings->{$service};
    $RT::Logger->debug( "Trying external auth service:",$service);

    my $db_table        = $config->{'table'};
    my $db_u_field      = $config->{'u_field'};
    my $db_p_field 	    = $config->{'p_field'};
    my $db_p_enc_pkg    = $config->{'p_enc_pkg'};
    my $db_p_enc_sub    = $config->{'p_enc_sub'};

    # Set SQL query and bind parameters
    my $query = "SELECT $db_u_field,$db_p_field FROM $db_table WHERE $db_u_field=?";
    my @params = ($username);
    
    # Uncomment this to trace basic DBI information and drop it in a log for debugging
    # DBI->trace(1,'/tmp/dbi.log');

    # Get DBI handle object (DBH), do SQL query, kill DBH
    my $dbh = _GetBoundDBIObj($config);
    return 0 unless $dbh;
    
    my $results_hashref = $dbh->selectall_hashref($query,$db_u_field,{},@params);
    $dbh->disconnect();

    my $num_users_returned = scalar keys %$results_hashref;
    if($num_users_returned != 1) { # FAIL
        # FAIL because more than one user returned. Users MUST be unique! 
        if ((scalar keys %$results_hashref) > 1) {
            $RT::Logger->info(  $service,
                                "AUTH FAILED",
                                $username,
                                "More than one user with that username!");
        }

        # FAIL because no users returned. Users MUST exist! 
        if ((scalar keys %$results_hashref) < 1) {
            $RT::Logger->info(  $service,
                                "AUTH FAILED",
                                $username,
                                "User not found in database!");
        }

	    # Drop out to next external authentication service
	    return 0;
    }
    
    # Get the user's password from the database query result
    my $pass_from_db = $results_hashref->{$username}->{$db_p_field};        

    # This is the encryption package & subroutine passed in by the config file
    $RT::Logger->debug( "Encryption Package:",
                        $db_p_enc_pkg);
    $RT::Logger->debug( "Encryption Subroutine:",
                        $db_p_enc_sub);

    # Use config info to auto-load the perl package needed for password encryption
    # I know it uses a string eval - but I don't think there's a better way to do this
    # Jump to next external authentication service on failure
    eval "require $db_p_enc_pkg" or 
        $RT::Logger->error("AUTH FAILED, Couldn't Load Password Encryption Package. Error: $@") && return 0;
    
    my $encrypt = $db_p_enc_pkg->can($db_p_enc_sub);
    if (defined($encrypt)) {
        # If the package given can perform the subroutine given, then use it to compare the
        # password given with the password pulled from the database.
        # Jump to the next external authentication service if they don't match
        if(${encrypt}->($password) ne $pass_from_db){
            $RT::Logger->info(  $service,
                                "AUTH FAILED", 
                                $username, 
                                "Password Incorrect");
            return 0;
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
            return 0;
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

sub FindUserThenReturnInfo {
    
    my ($service, $key, $value) = @_;

    my $found = 0;
    my %params = (Name         => undef,
                  EmailAddress => undef,
                  RealName     => undef);
    
    # Load the config
    my $config = $RT::ExternalSettings->{$service};
    
    # Figure out what's what
    my $table      = $config->{'table'};

    unless ($table) {
        $RT::Logger->critical(  (caller(0))[3],
                                "No table given");
        # Drop out to the next external information service
        return ($found, %params);
    }

    unless ($key && $value){
        $RT::Logger->critical(  (caller(0))[3],
                                " Nothing to look-up given");
        # Drop out to the next external information service
        return ($found, %params);
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
        return ($found, %params);
    }

    # We haven't dropped out, so DB search must have succeeded with 
    # exactly 1 result. Get the result and set $found to 1
    my $result = $results_hashref->{$value};
 
    # Use the result to populate %params for every key we're given in the config
    foreach my $key (keys(%{$config->{'attr_map'}})) {
        $params{$key} = ($result->{$config->{'attr_map'}->{$key}})[0];
    }
    
    $found = 1;
  
    return ($found, %params);
}

# {{{ sub _GetBoundDBIObj

sub _GetBoundDBIObj {
    
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