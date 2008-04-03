# The order in which the services defined in ExternalSettings
# should be used to authenticate users. User is authenticated
# if successfully confirmed by any service - no more services
# are checked.
Set($ExternalAuthPriority,  [   'My_LDAP',
                                'My_MySQL'
                            ]
);

# The order in which the services defined in ExternalSettings
# should be used to get information about users. This includes
# RealName, Tel numbers etc, but also whether or not the user
# should be considered disabled. 
# Once user info is found, no more services are checked.
Set($ExternalInfoPriority,  [   'My_MySQL',
                                'My_LDAP'
                            ]
);

# If this is set to true, then the relevant packages will
# be loaded to use SSL/TLS connections. At the moment,
# this just means "use Net::SSLeay;"
Set($ExternalServiceUsesSSLorTLS,    0);

# If this is set to 1, then users should be autocreated by RT
# as internal users if they fail to authenticate from an
# external service.
Set($AutoCreateNonExternalUsers,    0);

# These are the full settings for each external service as a HashOfHashes
# Note that you may have as many external services as you wish. They will
# be checked in the order specified in the Priority directives above.
# e.g. 
#   Set(ExternalAuthPriority,['My_LDAP','My_MySQL','My_Oracle','SecondaryLDAP','Other-DB']);
#
Set($ExternalSettings,      {   # AN EXAMPLE DB SERVICE
                                'My_MySQL'   =>  {      ## GENERIC SECTION
                                                        # The type of service (db/ldap) 
                                                        'type'                      =>  'db',
                                                        # Should the service be used for authentication?
                                                        'auth'                      =>  1,
                                                        # Should the service be used for information?
                                                        'info'                      =>  1,
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
                                                        # Alternatively, you could use Crypt::MD5::md5_hex or any other
                                                        # encryption subroutine you can load in your perl installation
                                                        'p_enc_pkg'                 =>  'Crypt::MySQL',
                                                        'p_enc_sub'                 =>  'password',
                                                        # The field and values in the table that determines if a user should
                                                        # be disabled. For example, if the field is 'user_status' and the values
                                                        # are ['0','1','2','disabled'] then the user will be disabled if their
                                                        # user_status is set to '0','1','2' or the string 'disabled'.
                                                        # Otherwise, they will be considered enabled.
                                                        'd_field'                   =>  'userSupportAccess',
                                                        'd_values'                  =>  ['0'],
                                                        ## RT ATTRIBUTE MATCHING SECTION
                                                        # The list of RT attributes that uniquely identify a user
                                                        'attr_match_list'           =>  [   'Gecos',
                                                                                            'Name'
                                                                                        ],
                                                        # The mapping of RT attributes on to field names
                                                        'attr_map'                  =>  {   'Name' => 'username',
                                                                                            'EmailAddress' => 'email',
                                                                                            'ExternalAuthId' => 'username',
                                                                                            'Gecos' => 'userID'
                                                                                        }
                                                    },
                                # AN EXAMPLE LDAP SERVICE
                                'My_LDAP'       =>  {   ## GENERIC SECTION
                                                        # The type of service (db/ldap/cookie) 
                                                        'type'                      =>  'ldap',
                                                        # Should the service be used for authentication?
                                                        'auth'                      =>  1,
                                                        # Should the service be used for information?
                                                        'info'                      =>  1,
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
                                                        # The filter to use to match RT-Users
                                                        'filter'                    =>  '(FILTER_STRING)',
                                                        # The filter that will only match disabled users
                                                        'd_filter'                  =>  '(FILTER_STRING)',
                                                        # Should we try to use TLS to encrypt connections?
                                                        'tls'                       =>  0,
                                                        # What other args should I pass to Net::LDAP->new($host,@args)?
                                                        'net_ldap_args'             => [    version =>  3   ],
                                                        # Does authentication depend on group membership? What group name?
                                                        'group'                     =>  'GROUP_NAME',
                                                        # What is the attribute for the group object that determines membership?
                                                        'group_attr'                =>  'GROUP_ATTR',
                                                        ## RT ATTRIBUTE MATCHING SECTION
                                                        # The list of RT attributes that uniquely identify a user
                                                        'attr_match_list'           => [    'Name',
                                                                                            'EmailAddress', 
                                                                                            'RealName',
                                                                                            'WorkPhone', 
                                                                                            'Address2'
                                                                                        ],
                                                        # The mapping of RT attributes on to LDAP attributes
                                                        'attr_map'                  =>  {   'Name' => 'sAMAccountName',
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
                                                                                        }
                                                    }
                                }
);

1;
