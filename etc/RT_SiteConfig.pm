=head1 External Authentication Configuration

=over 4

=item C<$ExternalAuthPriority>

The order in which the services defined in ExternalSettings
should be used to authenticate users. User is authenticated
if successfully confirmed by any service - no more services
are checked.

=cut

Set($ExternalAuthPriority,  [   'My_LDAP',
                                'My_MySQL',
                                'My_SSO_Cookie'
                            ]
);

=item C<$ExternalInfoPriority>

The order in which the services defined in ExternalSettings
should be used to get information about users. This includes
RealName, Tel numbers etc, but also whether or not the user
should be considered disabled.

Once user record is found, no more services are checked.

You CANNOT use a SSO cookie to retrieve information.

=cut

Set($ExternalInfoPriority,  [   'My_MySQL',
                                'My_LDAP'
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
external service.

=cut

Set($AutoCreateNonExternalUsers,    0);

=item C<$ExternalSettings>

These are the full settings for each external service as a HashOfHashes.
Note that you may have as many external services as you wish. They will
be checked in the order specified in $ExternalAuthPriority and
$ExternalInfoPriority directives above.

Option is a hash with (name of external source, hash reference with
description) pairs, for example:

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

As showed above each description should have 'type' information,
the following types are supported:

=over 4

=item ldap

Auth against and information sync with LDAP servers.
See L<RT::Authen::ExternalAuth::LDAP> for details.

=item db

Auth against and information sync with external RDBMS supported
by perl's L<DBI> interface. See L<RT::Authen::ExternalAuth::DBI>
for details.

=item cookie

Auth by a cookie. See L<RT::Authen::ExternalAuth::DBI::Cookie>
for details.

=back

See documentation of referenced modules for information on config
options.

Generic options for services providing users' information:

=over 4

=item attr_match_list

The list of RT attributes that uniquely identify a user. It's
recommended to use 'Name' and 'EmailAddress' to save
encountering problems later. Example:

    'attr_match_list' => [
        'Name',
        'EmailAddress',
        'RealName',
        'WorkPhone',
    ],

=item attr_map

Mapping of RT attributes on to attributes in the external source.
Example:

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

Note that only one value storred in RT. However, search goes by
all external attributes if such RT field list in 'attr_match_list'.
On create or update entered value is used as long as it's valid.
If user didn't enter value then value stored in the first external
attribute is used. Config example:

    attr_match_list => ['Name', 'EmailAddress'],
    attr_map => {
        Name         => 'account',
        EmailAddress => ['mail', 'alias'],
        ...
    },

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
            'WorkPhone',
            'Address2'
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

=back

=cut

1;
