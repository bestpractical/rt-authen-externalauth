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

Set($ExternalSettings, {   # AN EXAMPLE DB SERVICE
    'My_MySQL'   =>  {
        ## GENERIC SECTION
        # The type of service (db/ldap/cookie)
        'type'                      =>  'db',
        # The server hosting the service
        'server'                    =>  'server.domain.tld',
        ## SERVICE-SPECIFIC SECTION
        # The database name
        'database'                  =>  'DB_NAME',
        # The database table
        'table'                     =>  'USERS_TABLE',
        # The user to connect to the database as
        'user'                      =>  'DB_USER',
        # The password to use to connect with
        'pass'                      =>  'DB_PASS',
        # The port to use to connect with (e.g. 3306)
        'port'                      =>  'DB_PORT',
        # The name of the Perl DBI driver to use (e.g. mysql)
        'dbi_driver'                =>  'DBI_DRIVER',
        # The field in the table that holds usernames
        'u_field'                   =>  'username',
        # The field in the table that holds passwords
        'p_field'                   =>  'password',
        # The Perl package & subroutine used to encrypt passwords
        # e.g. if the passwords are stored using the MySQL v3.23 "PASSWORD"
        # function, then you will need Crypt::MySQL::password, but for the
        # MySQL4+ password function you will need Crypt::MySQL::password41
        # Alternatively, you could use Digest::MD5::md5_hex or any other
        # encryption subroutine you can load in your perl installation
        'p_enc_pkg'                 =>  'Crypt::MySQL',
        'p_enc_sub'                 =>  'password',
        # If your p_enc_sub takes a salt as a second parameter,
        # uncomment this line to add your salt
        #'p_salt'                    =>  'SALT',
        #
        # The field and values in the table that determines if a user should
        # be disabled. For example, if the field is 'user_status' and the values
        # are ['0','1','2','disabled'] then the user will be disabled if their
        # user_status is set to '0','1','2' or the string 'disabled'.
        # Otherwise, they will be considered enabled.
        'd_field'                   =>  'disabled',
        'd_values'                  =>  ['0'],
        ## RT ATTRIBUTE MATCHING SECTION
        # The list of RT attributes that uniquely identify a user
        'attr_match_list' =>  [
            'Gecos',
            'Name',
        ],
        # The mapping of RT attributes on to field names
        'attr_map' => {
            'Name'           => 'username',
            'EmailAddress'   => 'email',
            'ExternalAuthId' => 'username',
            'Gecos'          => 'userID',
        },
    },
    # AN EXAMPLE LDAP SERVICE
    'My_LDAP'       =>  {
        ## GENERIC SECTION
        # The type of service (db/ldap/cookie)
        'type'                      =>  'ldap',
        # The server hosting the service
        'server'                    =>  'server.domain.tld',
        ## SERVICE-SPECIFIC SECTION
        # If you can bind to your LDAP server anonymously you should
        # remove the user and pass config lines, otherwise specify them here:
        #
        # The username RT should use to connect to the LDAP server
        'user'                      =>  'rt_ldap_username',
        # The password RT should use to connect to the LDAP server
        'pass'                    =>  'rt_ldap_password',
        #
        # The LDAP search base
        'base'                      =>  'ou=Organisational Unit,dc=domain,dc=TLD',
        #
        # ALL FILTERS MUST BE VALID LDAP FILTERS ENCASED IN PARENTHESES!
        # YOU **MUST** SPECIFY A filter AND A d_filter!!
        #
        # The filter to use to match RT-Users
        'filter'                    =>  '(FILTER_STRING)',
        # A catch-all example filter: '(objectClass=*)'
        #
        # The filter that will only match disabled users
        'd_filter'                  =>  '(FILTER_STRING)',
        # A catch-none example d_filter: '(objectClass=FooBarBaz)'
        #
        # Should we try to use TLS to encrypt connections?
        'tls'                       =>  0,
        # SSL Version to provide to Net::SSLeay *if* using SSL
        'ssl_version'               =>  3,
        # What other args should I pass to Net::LDAP->new($host,@args)?
        'net_ldap_args'             => [    version =>  3   ],
        # Does authentication depend on group membership? What group name?
        'group'                     =>  'GROUP_NAME',
        # What is the scope of the group search? (base, one, sub)
        # Optional; defaults to 'base', which is good enough for most cases.
        # 'sub' is appropriate when you have nested groups
        'group_scope'               =>  'base',
        # What is the attribute for the group object that determines membership?
        'group_attr'                =>  'GROUP_ATTR',
        # What is the attribute of the user entry that should be matched against
        # group_attr above? (Optional; defaults to 'dn')
        'group_attr_value'          =>  'GROUP_ATTR_VALUE',
        ## RT ATTRIBUTE MATCHING SECTION
        # The list of RT attributes that uniquely identify a user
        # This example shows what you *can* specify.. I recommend reducing this
        # to just the Name and EmailAddress to save encountering problems later.
        'attr_match_list' => [
            'Name',
            'EmailAddress',
            'RealName',
            'WorkPhone',
            'Address2'
        ],
        # The mapping of RT attributes on to LDAP attributes
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
        # # The type of service (db/ldap/cookie)
        'type'                      =>  'cookie',
        # The name of the cookie to be used
        'name'                      =>  'loginCookieValue',
        # The users table
        'u_table'                   =>  'users',
        # The username field in the users table
        'u_field'                   =>  'username',
        # The field in the users table that uniquely identifies a user
        # and also exists in the cookies table
        'u_match_key'               =>  'userID',
        # The cookies table
        'c_table'                   =>  'login_cookie',
        # The field that stores cookie values
        'c_field'                   =>  'loginCookieValue',
        # The field in the cookies table that uniquely identifies a user
        # and also exists in the users table
        'c_match_key'               =>  'loginCookieUserID',
        # The DB service in this configuration to use to lookup the cookie information
        'db_service_name'           =>  'My_MySQL'
    },
} );

=back

=cut

1;
