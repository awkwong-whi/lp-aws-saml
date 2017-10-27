#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# Amazon Web Services CLI - Save a new assume-role profile
#
# Using an existing, named, assumed, role profile, (if the default
# profile is to be used, you must specify "default") generate and store 
# credentials for another named profile that the original credentials
# will allow you to use STS to assume-role to.
#
# Copyright (c) 2017 West Health Institute
#
# Some functions derived from LastPass (``lp-aws-saml.py``)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import logging
import os
import argparse

import boto3
from six.moves import configparser

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger('aws-sts-switch-role')

def aws_assume_role_alt(profile_name, alt_arn, session_name, duration=3600):
    """
    Returns a new STS assume-role response object using the
    credentials provided from a previous assume_role call.
    
    Credentials from the specified profile_name are used to
    assume a new role and then saved to a new profile named
    by the session_name. 
    
    The newly assumed role will be based on the provided arn
    value, and the session_name value in the assume_role
    call.

    Your final assumed ARN will typically then become:
        ``arn:aws:sts::123456789012:assumed-role/rolename/session_name``

    :param profile_name: AWS profile name with rights to assume-role
    :param alt_arn: Full ARN of the role to assume
    :param session_name: Session name
    :param duration: duration in seconds (900-3600) of the role session
    :type profile_name: str
    :type alt_arn: str
    :type session_name: str
    :type duration: int
    :returns: The assume_role response object
    """
    session = boto3.Session(profile_name=profile_name)
    client = session.client('sts')
    return client.assume_role(
                RoleArn=alt_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration)

def aws_set_profile(profile_name, response):
    """
    Save AWS credentials returned from Assume Role operation in
    ~/.aws/credentials INI file.  The credentials are saved in
    a profile with [profile_name].
    """
    config_fn = os.path.expanduser("~/.aws/credentials")

    config = configparser.ConfigParser()
    config.read(config_fn)

    section = profile_name
    try:
        config.add_section(section)
    except configparser.DuplicateSectionError:
        pass

    try:
        os.makedirs(os.path.dirname(config_fn))
    except OSError:
        pass

    config.set(section, 'aws_access_key_id',
               response['Credentials']['AccessKeyId'])
    config.set(section, 'aws_secret_access_key',
               response['Credentials']['SecretAccessKey'])
    config.set(section, 'aws_session_token',
               response['Credentials']['SessionToken'])
    with open(config_fn, 'w') as out:
        config.write(out)

def main():
   # ----------------------------------------------------------------------
   # Define argparse parameters
   # ----------------------------------------------------------------------
    parser = argparse.ArgumentParser(
                    description='Use AWS STS to create or update a new ' +
                    'AWS credentials profile provided a IAM Role ARN, ' +
                    'or both an account number and a role name. Credentials ' +
                    'from the first profile will be used to obtain the' +
                    'new creentials.')
    parser.add_argument('using_session', type=str,
                    help='the profile name with assume-role rights (from)')
    parser.add_argument('profile_name', type=str,
                    help='the name of AWS profile to save the data in (to)')
    arg_dur = parser.add_argument('-d', '--duration', type=int, default=3600, dest='duration',
                    help='duration in seconds (900-3600) of the role session ' +
                    '(default is 3600 or 1 hour)')
    arg_acc = parser.add_argument('-a', '--account', type=str, dest='account',
                    help='the AWS account number to assume')
    arg_rol = parser.add_argument('-r', '--role-name', type=str, dest='role_name',
                    help='the role name to assume in the specified account')
    arg_arn = parser.add_argument('-n', '--arn', dest='full_arn',
                    help='the full ARN of the role to assume in the format ' +
                    'arn:aws:iam::123456789012:role/NewRoleName')

    args = parser.parse_args()
   
   # ----------------------------------------------------------------------
   # Validate parameters 
   # ----------------------------------------------------------------------
    using_session = args.using_session
    profile_name = args.profile_name
    duration = args.duration

    # Setup the full_arn based on full_arn, account, and role_name
    full_arn = None
    if args.account is not None or args.role_name is not None or args.full_arn is not None:
        if args.account is not None and args.role_name is not None:
            full_arn = "arn:aws:iam::{0}:role/{1}".format(args.account, args.role_name)
        else:
            if args.full_arn is not None:
                full_arn = args.full_arn
            else:
                if args.account is None:
                    w = arg_acc
                else:
                    w = arg_rol
                raise argparse.ArgumentError(w, 
                    'Both the --account and --role-name must both be specified')
    else:
        raise argparse.ArgumentError(arg_arn,
            'Either the --arn or both --account and --role-name must be specified')

    # Check duration
    if duration < 900 or duration > 3600:
        raise argparse.ArgumentError(arg_dur, 
            'Duration must be between 900 and 3600 seconds.')

   # ----------------------------------------------------------------------
   # Assume role and save credentials
   # ----------------------------------------------------------------------
    response = aws_assume_role_alt(using_session, full_arn, profile_name, duration)
    aws_set_profile(profile_name, response)

    print "A new AWS CLI profile '{0}' has been added.".format(profile_name)
    print "You may now invoke the aws CLI tool as follows:"
    print
    print "    aws --profile {0} [...] ".format(profile_name)
    print
    print "This token expires in {0}:{1:02d} minutes.".format(duration//60, duration%60)


if __name__ == "__main__":
    try:
        main()
    except argparse.ArgumentError as e:
        logger.error(e)
