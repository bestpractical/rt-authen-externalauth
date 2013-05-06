=head1 External Authentication Configuration

L<RT::Authen::ExternalAuth> provides a lot of flexibility
with many configuration options. This file describes these
configuration options and is itself a sample configuration
suitable for dropping into your C<etc/RT_SiteConfig.pm>
file and modifying.

=over 4

=item C<$ExternalAuthPriority>

The order in which the services defined in ExternalSettings
should be used to authenticate users. User is authenticated
if successfully confirmed by any service - no more services
are checked.

You should remove services you don't use. For example,
if you're only using My_LDAP, remove My_MySQL and My_SSO_Cookie.

=cut

Set($ExternalAuthPriority,  [ 'My_LDAP',
                              'My_MySQL',
                              'My_SSO_Cookie'
                            ]
);

=item C<$ExternalInfoPriority>

When multiple auth services are available, this value eefines
the order in which the services defined in ExternalSettings
should be used to get information about users. This includes
RealName, Tel numbers etc, but also whether or not the user
should be considered disabled.

Once a user record is found, no more services are checked.

You CANNOT use a SSO cookie to retrieve information.

You should remove services you don't use, but you must define
at least one service.

=cut

Set($ExternalInfoPriority,  [ 'My_LDAP',
                              'My_MySQL',
                            ]
);

=item C<$ExternalServiceUsesSSLorTLS>

If this is set to true, then the relevant packages will
be loaded to use SSL/TLS connections. At the moment,
this just means L<Net::SSLeay>.

=cut

Set($ExternalServiceUsesSSLorTLS,    0);

=item C<$AutoCreateNonExternalUsers>

If this is set to 1, then users should be autocreated by RT
as internal users if they fail to authenticate from an
external service. This is useful if you have users outside
your organization who might interface with RT, perhaps by sending
email to a support email address.

=cut

Set($AutoCreateNonExternalUsers,    0);

=item C<$ExternalSettings>

These are the full settings for each external service as a HashOfHashes.
Note that you may have as many external services as you wish. They will
be checked in the order specified in $ExternalAuthPriority and
$ExternalInfoPriority directives above.

The outer structure is a key with the authentication option (name of external
source). The value is a hash reference with configuration keys and values,
for example:

    Set($ExternalSettings,
        MyLDAP => {
            type => 'ldap',
            ... other options ...
        },
        MyMySQL => {
            type => 'db',
            ... other options ...
        },
        ... other sources ...
    );

As shown above, each description should have 'type' defined.
The following types are supported:

=over 4

=item ldap

Authenticate against and sync information with LDAP servers.
See L<RT::Authen::ExternalAuth::LDAP> for details.

=item db

Authenticate against and sync information with external RDBMS,
supported by Perl's L<DBI> interface. See L<RT::Authen::ExternalAuth::DBI>
for details.

=item cookie

Authenticate by cookie. See L<RT::Authen::ExternalAuth::DBI::Cookie>
for details.

=back

See the modules noted above for configuration options specific to each type.
The following apply to all types.

=over 4

=item attr_match_list

The list of RT attributes that uniquely identify a user. These values
are used, in order, to find users in the selected authentication
source. Each value specified here must have a mapping in the
L</"attr_map"> section below. You can remove values you don't
expect to match, but it's recommended to use 'Name' and 'EmailAddress'
at minimum. For example:

    'attr_match_list' => [
        'Name',
        'EmailAddress',
        'RealName',
    ],

=item attr_map

Mapping of RT attributes on to attributes in the external source.
Valid keys are attributes of an
L<RT::User|http://bestpractical.com/rt/docs/latest/RT/User.html>.
The values are attributes from your authentication source.
For example, an LDAP mapping might look like:

    'attr_map' => {
        'Name'         => 'sAMAccountName',
        'EmailAddress' => 'mail',
        'Organization' => 'physicalDeliveryOfficeName',
        'RealName'     => 'cn',
        ...
    },

Since version 0.10 it's possible to map one RT field to multiple
external attributes, for example:

    attr_map => {
        EmailAddress => ['mail', 'alias'],
        ...
    },

Note that only one value is stored in RT, so this doesn't enable RT
users to have multiple email addresses defined. However, the search
will use all of the attributes to try to match a user if the field is
defined in the C<attr_match_list>.

On create or update, the original value input by the user, from an email
or login attempt, is used as long as it's valid. If user didn't enter a
value for that attribute, then the value retrieved from the first external
attribute is used.

For example, for the following configuration:

    attr_match_list => ['Name', 'EmailAddress'],
    attr_map => {
        Name         => 'account',
        EmailAddress => ['mail', 'alias'],
        ...
    },

If a new user sent an email to RT from an email alias, the search
would match on the alias and that alias would be set as the user's
EmailAddress in RT when the new account is created.

However, if a user with an existing RT account, with EmailAddress set
to the C<mail> address, sent mail from C<alias>, it would
still match. However, the user's EmailAddress in RT would
remain the primary C<mail> address.

This feature is useful for LDAP configurations where users have
a primary institutional email address, but might also use aliases from
subdomains or other email services. This prevents RT from creating
multiple accounts for the same person.

If you want the RT user accounts to always have the primary C<mail>
address for EmailAddress, you likely want to run
L<RT::Extension::LDAPImport> to make sure the user accounts are
created with the desired email address set.

=back

=back

=cut

Set($ExternalSettings, {
    # AN EXAMPLE DB SERVICE
    'My_MySQL'   =>  {
        'type'                      =>  'db',
        'server'                    =>  'server.domain.tld',
        'database'                  =>  'DB_NAME',
        'table'                     =>  'USERS_TABLE',
        'user'                      =>  'DB_USER',
        'pass'                      =>  'DB_PASS',
        'port'                      =>  'DB_PORT',
        'dbi_driver'                =>  'DBI_DRIVER',
        'u_field'                   =>  'username',
        'p_field'                   =>  'password',
        'p_enc_pkg'                 =>  'Crypt::MySQL',
        'p_enc_sub'                 =>  'password',
        'd_field'                   =>  'disabled',
        'd_values'                  =>  ['0'],
        'attr_match_list' =>  [
            'Gecos',
            'Name',
        ],
        'attr_map' => {
            'Name'           => 'username',
            'EmailAddress'   => 'email',
            'ExternalAuthId' => 'username',
            'Gecos'          => 'userID',
        },
    },
    # AN EXAMPLE LDAP SERVICE
    'My_LDAP'       =>  {
        'type'                      =>  'ldap',
        'server'                    =>  'server.domain.tld',
        'user'                      =>  'rt_ldap_username',
        'pass'                    =>  'rt_ldap_password',
        'base'                      =>  'ou=Organisational Unit,dc=domain,dc=TLD',
        'filter'                    =>  '(FILTER_STRING)',
        'd_filter'                  =>  '(FILTER_STRING)',
        'group'                     =>  'GROUP_NAME',
        'group_attr'                =>  'GROUP_ATTR',
        'tls'                       =>  0,
        'ssl_version'               =>  3,
        'net_ldap_args'             => [    version =>  3   ],
        'group_scope'               =>  'base',
        'group_attr_value'          =>  'GROUP_ATTR_VALUE',
        'attr_match_list' => [
            'Name',
            'EmailAddress',
            'RealName',
        ],
        'attr_map' => {
            'Name' => 'sAMAccountName',
            'EmailAddress' => 'mail',
            'Organization' => 'physicalDeliveryOfficeName',
            'RealName' => 'cn',
            'ExternalAuthId' => 'sAMAccountName',
            'Gecos' => 'sAMAccountName',
            'WorkPhone' => 'telephoneNumber',
            'Address1' => 'streetAddress',
            'City' => 'l',
            'State' => 'st',
            'Zip' => 'postalCode',
            'Country' => 'co'
        },
    },
    # An example SSO cookie service
    'My_SSO_Cookie'  => {
        'type'                      =>  'cookie',
        'name'                      =>  'loginCookieValue',
        'u_table'                   =>  'users',
        'u_field'                   =>  'username',
        'u_match_key'               =>  'userID',
        'c_table'                   =>  'login_cookie',
        'c_field'                   =>  'loginCookieValue',
        'c_match_key'               =>  'loginCookieUserID',
        'db_service_name'           =>  'My_MySQL'
    },
} );

1;
