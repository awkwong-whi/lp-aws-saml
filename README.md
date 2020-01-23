# lp-aws-saml

This repository contains the LastPass AWS SAML login tool.

If you are using LastPass Enterprise SAML with AWS, then this script eases the
process of using the AWS CLI utility.  It retrieves a SAML assertion from
LastPass and then converts it into credentials for use with ```aws```.

## Requirements

You will need python with the Amazon boto3 module and the AWS CLI tool.
The latter may be installed with pip:
```
    # pip install boto3 awscli
```
On recent Mac platforms, you may need to pass --ignore-installed:

```
    # pip install boto3 awscli --ignore-installed
```

You will also need to have integrated AWS with LastPass SAML through the
AWS and LastPass management consoles.  See the SAML setup instructions on the
LastPass AWS configuration page for more information.

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
* ```json``` will print the identity.lastpass.com web applications list in
   JSON format instead of a printed list.
* ```--otp OTP``` provide the OTP value directly on the command line instead
    of prompting the user for the OTP (note -- it might timeout).
* ```--prompt-otp``` always ask for the OTP after providing the password.
* ```--sient-on-success``` don't print anything out on success (useful for
   use within a script).
* ```--print-eval``` prints the credentials in a format that can be parsed
   by the shell eval function.

### Legacy SAML Configuration ID

The Legacy SAML Configuration ID can be obtained from the generated
Launch URL. if the launch URL is ```https://lastpass.com/saml/launch/cfg/25```
then the configuration ID is ```25```.

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

List Application Ids Example:

```
$ ./lp-aws-saml.py admin_user@example.com list
Password:
Web Application Id ----------------- Application Name ---------------------------
aaaaaaaa-1111-2222-3333-444444444444 AWS Account (123456789111)
bbbbbbbb-1111-2222-3333-444444444444 AWS Account (123456789222)
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

### Assume an Alternate Role

For accounts using AWS Organizations, you may want to assume an alternate role
that is different than the role you SAML into, but the role you SAML into has
rights to assume another role that you need. In this use case, you don't want
to save the initial set of credentials -- just the altenate role credentials.

The authentication flow looks like this:

```
    LastPass --> Role in Account 1 --> Alternate Role in Account 2
```

You can either specify the full AWS ARN by specifying the ```--alt-arn``` 
which looks like: ```arn:aws:iam:123456789012:role/RoleName```

Or you an specify the ```--alt-account``` with the 12 digit account number, and
the ```--alt-role``` with the role name to assume in the specified account. The
code will generate the ARN for you.

When using the alternate role feature, you should also specify the ```--profile```
parameter.  The profile name will also appear in the CloudWatch logs.

Example:

```
$ ./lp-aws-saml.py user@example.com 25 \
        --profile org2 \
        --alt-account 123456789012 \
        --alt-role Org2Admin
Password:
A new AWS CLI profile 'org2' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile org2 [...]

This token expires in 60:00 minutes.
```

# aws-sts-switch-role

If you used ```lp-aws-saml``` to save a set of credentials, and you have one or
more other credential sets that you need to use simultaneously (such as managing 
multiple AWS organization accounts, or using services only accessible by separate
roles), use ```aws-sts-switch-role``` to save a new profile with new credentials
based on the role rights in the original that includes the right to assume-role.

All existing credentials are maintained (unless you specify the target ```profile_name```
as the same name as the reference ```using_session``` name).

Example:

```
$ ./aws-sts-switch-role.py -d 900 saml1 admin2 -a 123456789012 -r Org2Admin
A new AWS CLI profile 'admin2' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile admin2 [...] 

This token expires in 15:00 minutes.
```
