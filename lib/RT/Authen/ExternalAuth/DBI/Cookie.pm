package RT::Authen::ExternalAuth::DBI::Cookie;

use CGI::Cookie;

use strict;

# {{{ sub GetCookieVal
sub GetCookieVal {

    # The name of the cookie
    my $cookie_name = shift;
    my $cookie_value;

    # Pull in all cookies from browser within our cookie domain
    my %cookies = CGI::Cookie->fetch();

    # If the cookie is set, get the value, if it's not set, get out now!
    if (defined $cookies{$cookie_name}) {
      $cookie_value = $cookies{$cookie_name}->value;
      $RT::Logger->debug(  "Cookie Found",
                           ":: $cookie_name");
    } else {
        $RT::Logger->debug( "Cookie Not Found");
    }

    return $cookie_value;
}

# }}}

1;
