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
instance you wish to control.  This can be obtained from the generated
Launch URL: if the launch URL is ```https://lastpass.com/saml/launch/cfg/25```
then the configuration ID is ```25```.

Then launch the tool to login to lastpass.  You will be prompted for
password and optionally the AWS role to assume:

```
$ ./lp-aws-saml.py user@example.com 25
Password:
A new AWS CLI profile 'user@example.com' has been added.
You may now invoke the aws CLI tool as follows:

    aws --profile user@example.com [...]

This token expires in one hour.
```

Once completed, the ```aws``` tool may be used to execute commands as that
user by specifying the appropriate profile.

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

