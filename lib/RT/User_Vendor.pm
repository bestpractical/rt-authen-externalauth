no warnings qw(redefine);
use strict;
use RT::Authen::ExternalAuth;

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
    return(RT::Authen::ExternalAuth::CanonicalizeUserInfo($self,$args));
}
# }}}




1;
