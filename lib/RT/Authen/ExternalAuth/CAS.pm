package RT::Authen::ExternalAuth::CAS;

use AuthCAS;

sub GetCasAuth {

			     
    # Get our config
    my $config = shift;
    my $ticket = shift;

    $RT::Logger->debug( (caller(0))[3], "Checking CAS for an Authenticated User. \$ticket is [ $ticket ]");

    my $username = undef;

    $RT::Logger->debug( (caller(0))[3], "CAS \$config->casUrl is [ " . $config->{'casUrl'} . "]");
    my $cas = new AuthCAS( casUrl => $config->{'casUrl'} );

    $username = $cas->validateST(RT->Config->Get('WebURL'), $ticket);


    if ($username) {
        $RT::Logger->debug( "User (",
                            $username,
                            ") was authenticated by CAS");
    } else {
        $RT::Logger->debug( "No CAS user authenticated. Errors:\n\t" . $cas->get_errors );
	my $cas_login_url = $cas->getServerLoginURL(RT->Config->Get('WebURL'));
        $RT::Logger->debug( "Redirecting to:" . $cas_login_url );
	#$RT::Interface::Web->Redirect( $cas_login_url );
	$HTML::Mason::Commands::m->redirect( $cas_login_url );
    }

    return $username;

}

1;
