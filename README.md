# lp-aws-saml

This repository contains the LastPass AWS SAML login tool.

If you are using LastPass Enterprise SAML with AWS, then this script eases the
process of using the AWS CLI utility.  It retrieves a SAML assertion from
LastPass and then converts it into credentials for use with ```aws```.

## Requirements

You will need python with the Amazon boto3 module and the AWS CLI tool.
The latter may be installed with pip:
```
    # pip install boto3 awscli requests
```
On recent Mac platforms, you may need to pass --ignore-installed:

```
    # pip install boto3 awscli requests --ignore-installed
```

You will also need to have integrated AWS with LastPass SAML through the
AWS and LastPass management consoles.  See the SAML setup instructions on the
LastPass AWS configuration page for more information.

### Optional Requirements

This script can be copied standalone into your development environment
tools path.  The accompanying ```aws_saml_diag.py``` is not needed during 
normal operation.

The list applications feature uses ```BeautifulSoup``` (python package 
```bs4```) to extract the Legacy Application ids from the Enterprise 
Administrator Console page for AWS Legacy SAML Applications.  If this 
package is not available, the applications list will only show web 
applications from ```identity.lastpass.com```.  You can add this with:

```
    # pip install bs4
```

## Usage

First you will need to look up the LastPass SAML configuration ID for the AWS
instance you wish to control.  There are two types of configuration ID's
supported:

* Legacy SAML Configuration ID (numeric)
* Application ID from identity.lastpass.com (GUID)

Then launch the tool to login to lastpass.  You will be prompted for
password and optionally the AWS role to assume.

Once completed, the ```aws``` tool may be used to execute commands as that
user by specifying the appropriate profile.

You can use the following options to change how the tool will work:

* ```--profile-name``` specifies which profile in ```~/.aws/credentials```
   the credentials will be written to.
* ```--role-name``` specifies which Role name to select if the Application
   configuration provides multiple roles.  You can provide the name of the
   role from the end of the role ARN after the first /:

   ```arn:aws:iam::xxxx:role/role-name```
* ```--duration``` specifies the duration of the token (900-3600) in seconds.
* ```--json``` will print provided credentials in JSON format for use with
   AWS CLI external credentials feature, or print the identity.lastpass.com
   web applications list in JSON format instead of a printed list.
* ```--otp OTP``` provide the OTP value directly on the command line instead
    of prompting the user for the OTP (note -- it might timeout).
* ```--prompt-otp``` always ask for the OTP after providing the password.
* ```--silent-on-success``` don't print anything out on success (useful for
   use within a script).
* ```--print-eval``` prints the credentials in a format that can be parsed
   by the shell eval function.
* ```--session``` will save the cookies to ```~/.lp_aws_saml``` in an INI
   formatted file where the section name is derived from the username. This
   option can be used independently of ```--clear-session```.
* ```--clear-session``` will remove saved cookies for the current user.
   this option  can be used independantly of ```--session```.  Note
   however, that specifying both will load the current set of saved
   cookies into the current session, but then ensure that the cookies are
   removed upon completion.
* ```--dump-assertion``` is an option only available if the 
   ```aws_saml_diag.py``` file is in the same directory as the main 
   script.  This will print a formatted JSON structure that you can read
   to help identify possible misconfigurations in your IdP, which 
   SAML attributes are being passed across with their associated values,
   and what their associated IAM Condition strings are typically 
   associated with the value from the Response, or from an Attribute
   within the response.  Recognized attributes for:

    Assertion Values:

    * ```audience``` maps to ```/Response/Assertion/Conditions/AudienceRestriction/Audience```
    * ```saml:aud``` maps to ```/Response/Assertion/Subject/SubjectConfirmationData[@Recipient]```
    * ```saml:iss``` maps to ```/Response/Issuer```
    * ```saml:sub``` maps to ```/Response/Assertion/Subject/NameID```
    * ```saml:sub_type``` maps to ```/Response/Assertion/Subject/NameID[@Format]```

    Attributes:

    * ```https://aws.amazon.com/SAML/Attributes/Role```
    * ```https://aws.amazon.com/SAML/Attributes/RoleSessionName```
    * ```https://aws.amazon.com/SAML/Attributes/SessionDuration```
    * ```https://aws.amazon.com/SAML/Attributes/PrincipalTag:____```
    * ```https://aws.amazon.com/SAML/Attributes/TransitiveTagKeys```
    * ```eduPerson*``` attributes
    * ```eduOrg*``` attributes
    * ```name``` for AD
    * ```commonName``` for AD and X500
    * ```givenName``` for AD and X500
    * ```surname``` for ad and X500
    * ```mail``` for AD and X500
    * ```uid``` for AD and X500
    * ```x500UniqueIdentifier``` for X500
    * ```organizationStatus``` for X500

    Generated Values:

    * ```saml:doc```
    * ```saml:namequalifier```

   Generates a ```status_check``` at the bottom of the report that lists
   out any issues or potential misconfigurations.

### Legacy SAML Configuration ID

The Legacy SAML Configuration ID can be obtained from the generated
Launch URL. if the launch URL is ```https://lastpass.com/saml/launch/cfg/25```
then the configuration ID is ```25```.  You can use the ```list``` feature
to retrieve the list of legacy SAML AWS applications (requires ```bs4```).

Example:

```
$ ./lp-aws-saml.py user@example.com 25
Password:
A new AWS CLI profile 'user@example.com' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile user@example.com [...]

This token expires in 60:00 minutes.
```

### Application ID from identity.lastpass.com

The Application ID is a GUID that uniquely represents the Web Application
configured for the AWS instance you intend to log into.  The ID can be
obtained by running this script and specifying ```list``` as the
Configuration ID.  Once you login to LastPass, it will login to
identity.lastpass.com and then retrieve the list of applications and
provide you with their Id's and their configured names.  *Note that
you will need to be an Account Administrator for the list command to
work.*

You can then provide the GUID for the correct Application as the
Configuration Id.

List Application Ids Example (with legacy SAML configurations shown):

```
$ ./lp-aws-saml.py admin_user@example.com list
Password:
+--------------------------------------+------------------------------------+
| Application ID (GUID)                | Application Name                   |
+--------------------------------------+------------------------------------+
| aaaaaaaa-1111-2222-3333-444444444444 | AWS Account - DEV (123456789111)   |
| bbbbbbbb-1111-2222-3333-444444444444 | AWS Account - PRD (123456789222)   |
| xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx | Cool Service                       |
| 11111                                | Amazon Web Services (123456789111) |
| 22222                                | Amazon Web Services (123456789222) |
+--------------------------------------+------------------------------------+

```

Example Login:

```
$ ./lp-aws-saml.py aws_user@example.com aaaaaaaa-1111-2222-3333-444444444444
Password:
A new AWS CLI profile 'aws_user@example.com' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile aws_user@example.com [...]

This token expires in 60:00 minutes.
```

