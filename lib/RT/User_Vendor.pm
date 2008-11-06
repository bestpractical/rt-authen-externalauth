no warnings qw(redefine);
use strict;
use RT::Authen::ExternalAuth;

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


    if(RT::Authen::ExternalAuth->GetAuth($self->Name,$value)) {
        $RT::Logger->debug( (caller(0))[3], 
                            "EXTERNAL AUTH OKAY");
        return(1);
    } else {
        $RT::Logger->debug( (caller(0))[3], 
                            "EXTERNAL AUTH FAILED");
    }
    
    unless ($self->HasPassword) {
        $RT::Logger->info(  (caller(0))[3], 
                            "INTERNAL AUTH FAILED (no passwd):", 
                            $self->Name);
        return(undef);
    }

    # generate an md5 password 
    if ($self->_GeneratePassword($value) eq $self->__Value('Password')) {
        $RT::Logger->info(  (caller(0))[3], 
                            "INTERNAL AUTH OKAY:", 
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
                            "INTERNAL AUTH OKAY:", 
                            $self->Name);
          return(1);
      }

    $RT::Logger->info(  (caller(0))[3], 
                        "INTERNAL AUTH FAILED:", 
                        $self->Name);

    # If we haven't succeeded by now, fail.
    return (undef);
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
    return($RT::Authen::ExternalAuth->CanonicalizeUserInfo($self,$args));
}
# }}}




1;
