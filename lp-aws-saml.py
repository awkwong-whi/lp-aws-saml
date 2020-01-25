#!/usr/bin/env python3
# -*- coding: utf8 -*-
#
# Amazon Web Services CLI - LastPass SAML integration
#
# This script uses LastPass Enterprise SAML-based login to authenticate
# with AWS and retrieve a session token that can then be used with the
# AWS cli tool.
#
# Copyright (c) 2016 LastPass
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
import os
import sys
import re
import logging
from json import JSONDecodeError, loads as json_loads, dumps as json_dumps
from boto3 import client as aws_client
from lzma import compress, decompress
from requests import Session
from hashlib import pbkdf2_hmac
from xml.etree import ElementTree
from base64 import b64decode, b64encode
from argparse import ArgumentParser, ArgumentError
from html import unescape
from configparser import ConfigParser
from http.cookiejar import Cookie
from getpass import getpass

LASTPASS_SERVER = 'https://lastpass.com'

# for debugging with proxy
PROXY_SERVER = 'https://127.0.0.1:8443'
# LASTPASS_SERVER = PROXY_SERVER

SESSION_FILE = os.path.expanduser('~/.lp_aws_saml')

# A list of ACS URL's found in the form action url to where the
# SAMLResponse's will be posted to.  This is a list of
# recognized intermediate ACS endpoints that should be considered
# as an intermediate ACS (that is, this is not the final AWS
# ACS endpoint).
intermediate_acs_list = [
    'https://identity.lastpass.com/SAML/AssertionConsumerService'
]


logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger('lp-aws-saml')

class MfaRequiredException(Exception):
    pass


class ResponseValueError(ValueError):
    """
    given the html response text, extract the title from the H2 and
    return a ValueError exception object with the extracted title
    after the provided message.
    """
    def __init__(self, message, response):

        def scan_dict(d, prefix=""):
            e = ""
            for k,v in d.items():
                if k.lower() in ["status","code","message","error"]:
                    if type(v) is dict:
                        e += scan_dict(v,f"{k}.")
                    else:
                        e += f"\n!    info: {prefix}{k} {v}"
            return e
                        
        try:
            j = response.json()
            error = scan_dict(j)

        except JSONDecodeError:
            # If not a JSON response, treat response as an html document
            # and find all header and title elements and print the embedded
            # text.  (regex uses non-greedy scanning to find closest 
            # matching closing tag).
            error = ""
            match = re.findall(r'<(h[0-9]|title)[^>]*?>(.*?)</\s*?\1>', response.text, re.DOTALL|re.IGNORECASE)
            if match:
               for m in match:
                   msg = unescape(m[1]).strip()
                   msg = re.sub(r'<br[^>]*?/??>', '\n    info:', msg, re.IGNORECASE)
                   msg = re.sub(r'<(span|i|b|em|strong|a )[^>]*?/??>', '', msg, re.IGNORECASE)
                   error += f"\n!    info: {msg}"

        super(ResponseValueError, self).__init__(message + error)


def load_session(session, filename, username, ignore_session=False):
    """
    Safely loads cookies from a session file ```~/.lp_aws_saml``` where
    the session file is an ini style file with the cookies stored as:

    1. Array( Cookie.__dict__ )
    2. JSON Encoded
    3. LZMA Compressed
    4. Base64 Encoded

    Once the cookies option is retrieved from the ini section based
    on the username, it is Decoded, Decompressed, and JSON loaded.

    Each cookie is then reconstructed such that all cookie attributes
    are retained (expire, path, domain, secure, port, etc.).  Each
    saved key is checked to make sure it is compatible with the
    http.cookiejar.Cookie() constructor.

    Each cookie that is properly construcuted is then directly added
    into the session cookies set as long as the cookie is still
    valid (that is, not expired).

    If a session file is missing, or no cookies are present, or
    one or more cookies exired, this function will return True to
    indicate that the user must perform a full login first.
    """
    # start with not requiring the user to login
    needs_auth = False
    if ignore_session:
        # make sure we indicate login is required if
        # the session file is ignored.
        needs_auth = True
    else:
        if os.path.isfile(filename):
            sescfg = ConfigParser()
            sescfg.read(filename)

            if sescfg.has_option(username, 'cookies'):
                cstr = sescfg.get(username, 'cookies')
                if len(cstr) > 0:
                    cookies = json_loads(decompress(b64decode(cstr.encode())).decode())
                    for cookie in cookies:
                        cookie_params = {}
                        for k, v in cookie.items():
                            if k.strip('_') in [
                                'version', 'name', 'value', 'port', 'port_specified',
                                'domain', 'domain_specified', 'domain_initial_dot',
                                'path', 'path_specified', 'secure', 'expires', 'discard',
                                'comment', 'comment_url', 'rest', 'rfc2109' ]:
                                cookie_params[k.strip('_')] = v
                        new_cookie = Cookie(**cookie_params)
                        if new_cookie.is_expired():
                            # if we find an expired cookie, its very likely
                            # that the user will need to login directly with
                            # lastpass first.
                            logger.info(f'Cookie {new_cookie.name} expired.')
                            needs_auth = True
                        else:
                            # restore this cookie to the current session
                            session.cookies.set_cookie(new_cookie)
                else:
                    # cookies was present but was empty
                    needs_auth = True
            else:
                # cookies was not present
                needs_auth = True
        else:
            # session file is not present
            needs_auth = True
    return needs_auth


def save_session(session, filename, username, clear_cookies=False):
    """
    save the cookies from the current session into a saved
    session file that uses an ini style format.
    save the data into a section based on the username.

    Example:
        [admin_user@example.com]
        cookies = ...

        [user@example.com]
        cookies = ...

    if clear_cookies is True, the cookies option will be deleted
    from the session file.

    Cookies are extracted directly from the cookie __dict__
    so that the cookie can be reconstructed in a safe manner
    when loading the session.

    All cookies are added into an array which is then:
    1. JSON encoded
    2. LZMA compressed
    3. Base64 encoded
    """
    if os.path.isdir(os.path.dirname(filename)):
        sescfg = ConfigParser()
        sescfg.read(filename)

        if not sescfg.has_section(username):
            sescfg.add_section(username)

        if clear_cookies:
            sescfg.remove_option(username, 'cookies')
        else:
            cookies = []
            for cookie in session.cookies:
                cookies.append(cookie.__dict__)
            ccookies = b64encode(compress(json_dumps(cookies).encode())).decode()
            sescfg.set(username, 'cookies', ccookies)

        with open(filename, 'w') as out:
            sescfg.write(out)


def should_verify():
    """ Disable SSL validation only when debugging via proxy """
    return LASTPASS_SERVER != PROXY_SERVER


def get_input(message):
      """
      Returns a string from stdin after printing a message or
      prompt to stderr.
      """
      print(f"{message}: ", end="", file=sys.stderr)
      return input()


def extract_form(html):
    """
    Retrieve the (first) form elements from an html page.
    """
    fields = {}
    matches = re.findall(r'name="([^"]*)" (id="([^"]*)" )?value="([^"]*)"',
                         html)
    for match in matches:
        if len(match) > 2:
            fields[match[0]] = match[3]

    action = ''
    match = re.search(r'action="([^"]*)"', html)
    if match:
        action = match.group(1)

    form = {
        'action': action,
        'fields': fields
    }
    return form


def lastpass_login_hash(username, password, iterations):
    """
    Determine the number of PBKDF2 iterations needed for a user.
    Use pbkdf2_hmac() library function.
    """
    key = pbkdf2_hmac('sha256', password.encode(), username.encode(), iterations, 32)
    result = pbkdf2_hmac('sha256', key, password.encode(), 1, 32).hex()
    return result


def lastpass_iterations(session, username):
    """
    Determine the number of PBKDF2 iterations needed for a user.
    """
    iterations = 5000
    lp_iterations_page = f'{LASTPASS_SERVER}/iterations.php'
    params = {
        'email': username
    }
    r = session.post(lp_iterations_page, data=params, verify=should_verify())
    if r.status_code == 200:
        iterations = int(r.text)

    return iterations


def lastpass_login(session, username, password, otp = None):
    """
    Log into LastPass with a given username and password.
    """
    logger.debug(f"logging into lastpass as {username}")
    iterations = lastpass_iterations(session, username)

    lp_login_page = f'{LASTPASS_SERVER}/login.php'

    params = {
        'method': 'cli',
        'xml': '1',
        'username': username,
        'hash': lastpass_login_hash(username, password, iterations),
        'iterations': iterations
    }
    if otp is not None:
        params['otp'] = otp

    r = session.post(lp_login_page, data=params, verify=should_verify())
    r.raise_for_status()

    doc = ElementTree.fromstring(r.text)
    error = doc.find("error")
    if error is not None:
        cause = error.get('cause')
        if cause in [ 'googleauthrequired',  "otprequired", "microsoftauthrequired" ]:
            raise MfaRequiredException(f'Need MFA ({cause.strip("required")}) for this login')
        else:
            reason = error.get('message')
            if cause == "unknown":
                message = f"Could not login to lastpass: {reason}"
            else:
                message = f"Could not login to lastpass: {cause} - {reason}"
            raise ValueError(message)


def full_lastpass_login(session, username, password, otp=None, prompt_otp=False):
    """
    do a full login to lastpass.com/login.php.
    requires:
    * an existing requests session
    * username/email to login as
    * password for user
    * otp code if known in advance
    * prompt_otp True to force the retrieval of the OTP code
    """
    try:
        # Use the provided OTP value as a default if provided (it might time out though)
        # Otherwise, immediately prompt for the OTP if requested
        if otp is None and prompt_otp:
            otp = get_input("OTP")

        lastpass_login(session, username, password, otp)

    except MfaRequiredException:
        # either need OTP or provided OTP expired -- ask for a new one
        otp = get_input("OTP")
        lastpass_login(session, username, password, otp)


def identity_login(session):
    """
    Log into LastPass Identity from LastPass.
    You must have already logged into LastPass using
    the provided session.
    """

    idp_login = f'{LASTPASS_SERVER}/saml/launch/nopassword?RelayState=/'
    r = session.get(idp_login, verify=should_verify())

    form = extract_form(r.text)
    if not form['action']:
        raise ResponseValueError("Unable to find SAML ACS for identity.lastpass.com", r)
    elif form['action'] in ['action.php?', 'accts.php' ]:
        raise ResponseValueError("Needs login", r)
    else:
        r = session.post(form['action'], data=form['fields'], verify=should_verify())
        if r.status_code > 299:
            raise ResponseValueError("Unable to authenticate with identity.lastpass.com", r)


def get_app_list(session):
    """
    Query identity.lastpass.com API to retrieve the list of
    Web Apps and display their associated GUID Id's.
    You must already have logged into LastPass using the
    provided session.
    You must also already have logged into
    identity.lastpass.com using identity_login() with the
    same session.
    """

    # Use Apps/list API
    list_apps_url = 'https://identity.lastpass.com/api/v2/Apps/list'
    page = 1
    app_list = []

    # API was intended for a Web Interface.  The UI is typically
    # paginated to 10 per page.  Use the same pagination here.
    # We're only interested in SAML based applications.
    # API expects the accept field to indicate a json response.
    while True:
        p = { "size": 10, "page": page, "onlySaml": True, "onlyPassword":False  }
        h = { "accept": "application/json" }
        r = session.get(list_apps_url, params=p, headers=h, verify=should_verify())
        if r.status_code > 299:
            message = f"Unable to retrieve apps list from identity.lastpass.com ({r.status_code})"
            if r.status_code == 401:
                message += f"\n!    SSO administrator rights required."
            raise ResponseValueError(message, r)

        # Response includes two fields:
        #   * total   -- (int)   total number of matching web applications
        #   * results -- (obj[]) a list of web application objects
        #
        # Web Application objects have two fields of interest:
        #   * id      -- (str)   GUID representing the Web Application ID
        #                        and is also the /redirect?id=xxxxxxxx
        #                        target that you can then use as the
        #                        saml_config_id.
        #   * name    -- (str)   The Name of the Web App as configured
        #                        by the LastPass Administrator.
        apps = r.json()
        for app in apps["results"]:
            app_list.append({"id": app["id"], "name": app["name"]})
        if len(app_list) >= apps["total"]:
            break
        else:
            page = page + 1

    return app_list


def get_saml_token(session, saml_cfg_id):
    """
    Log into LastPass and retrieve a SAML token for a given
    SAML configuration.
    """
    logger.debug("Getting SAML token")

    # now logged in, grab the SAML token from the IdP-initiated login
    if saml_cfg_id.isdigit():
        idp_login = f'{LASTPASS_SERVER}/saml/launch/cfg/{saml_cfg_id}'
    else:
        idp_login = f'{LASTPASS_SERVER}/saml/launch/nopassword?RelayState=/redirect%3Fid%3D{saml_cfg_id}'

    # if we are logging in and then using identity.lastpass.com, we are effectively
    # chaining SAML logins.  LastPass first authenticates to identity.lastpass.com,
    # then identity.lastpass.com will provide the SAMLResponse for AWS.
    #
    # To support chaining, first GET from lastpass.com to initiate the
    # IDP initiated login.  then, for each subsequent hop, post the
    # returned SAMLResponse to the form[action] identified ACS url.
    # eventually, it should end up at one of:
    #
    # * https://signin.aws.amazon.com/saml
    # * https://signin.amazonaws-us-gov.com/saml
    #
    r = session.get(idp_login, verify=should_verify())
    while True:
        form = extract_form(r.text)
        if not form['action']:
            raise ResponseValueError("Unable to find SAML ACS",r)

        if form['action'] in intermediate_acs_list:
            # post this intermediate SAMLResponse to the specified intermediate ACS
            r = session.post(form['action'], data=form['fields'], verify=should_verify())
        else:
            break

    return b64decode(form['fields']['SAMLResponse'])


def get_saml_aws_roles(assertion):
    """
    Get the AWS roles contained in the assertion.  This returns a list of
    RoleARN, PrincipalARN (IdP) pairs.
    """
    doc = ElementTree.fromstring(assertion)

    role_attrib = 'https://aws.amazon.com/SAML/Attributes/Role'
    xpath = f".//saml:Attribute[@Name='{role_attrib}']/saml:AttributeValue"
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}

    attribs = doc.findall(xpath, ns)
    return [a.text.split(",", 2) for a in attribs]


def get_saml_nameid(assertion):
    """
    Get the AWS roles contained in the assertion.  This returns a list of
    RoleARN, PrincipalARN (IdP) pairs.
    """
    doc = ElementTree.fromstring(assertion)

    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    return doc.find(".//saml:NameID", ns).text


def prompt_for_role(roles, role_name=None):
    """
    Ask user which role to assume.  If role_name is provided,
    Return the role where the role_name is found at the end
    of the role ARN: arn:aws:iam::xxxx:role/role_name.
    """
    role = roles[0]

    if len(roles) > 1:
        if role_name is None:
            print('Please select a role:', file=sys.stderr)
            count = 1
            for r in roles:
                print(f'  {count}) {r[0]}', file=sys.stderr)
                count += 1

            choice = 0
            while choice < 1 or choice > len(roles):
                try:
                    choice = int(get_input("Choice"))
                except ValueError:
                    choice = 0
            role = roles[choice - 1]
        else:
            role = None
            for r in roles:
                if r[0].endswith(role_name):
                    role = r
                    break
            if role is None:
                raise ValueError(f"Role {role_name} not found in available roles.")

    return role


def aws_assume_role(session, assertion, role_arn, principal_arn, duration=3600):
    client = aws_client('sts')
    return client.assume_role_with_saml(
                RoleArn=role_arn,
                PrincipalArn=principal_arn,
                SAMLAssertion=b64encode(assertion).decode(),
                DurationSeconds=duration)


def aws_assume_role_alt(response, alt_arn, session_name, duration=3600):
    """
    Returns a new STS assume-role response object using the
    credentials provided from a previous assume_role call.

    Credentials from the response parameter (typically created
    in a previous call to ``aws_assume_role`` are used to then
    assume a new role (Such as logging into a root AWS
    Organization account, and then switching roles into an
    account in the Organization that your main account has
    rights to assume.

    The newly assumed role will be based on the provide alt_arn ARN
    value, and the session_name value in the assume_role
    call.

    Your final assumed ARN will typically then become:
        ``arn:aws:sts::123456789012:assumed-role/rolename/session_name``

    :param response: response object from ``aws_assume_role``
    :param alt_arn: ARN of the role to assume
    :param session_name: Session name
    :param duration: duration in seconds (900-3600) of the role session
    :type response: str
    :type alt_arn: str
    :type session_name: str
    :type duration: int
    :returns: The assume_role response object
    """
    credentials = response['Credentials']
    client = aws_client('sts',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'])
    return client.assume_role(
                RoleArn=alt_arn,
                RoleSessionName=session_name,
                DurationSeconds=duration)


def aws_set_profile(profile_name, response, print_eval=False, print_json=False):
    """
    Save AWS credentials returned from Assume Role operation in
    ~/.aws/credentials INI file.  The credentials are saved in
    a profile with [profile_name].
    """
    config_fn = os.path.expanduser("~/.aws/credentials")

    config = ConfigParser()
    config.read(config_fn)

    section = profile_name
    if not config.has_section(section):
        config.add_section(section)

    try:
        os.makedirs(os.path.dirname(config_fn))
    except OSError:
        pass

    message = ""
    if print_eval:
        message = (f"export AWS_ACCESS_KEY_ID={response['Credentials']['AccessKeyId']}"
                f" AWS_SECRET_ACCESS_KEY={response['Credentials']['SecretAccessKey']}"
                f" AWS_SESSION_TOKEN={response['Credentials']['SessionToken']}")
    elif print_json:
        filtered_response = {}
        filtered_keys = [
            'AssumedRoleUser',
            'Audience',
            'Credentials',
            'Issuer',
            'NameQualifier',
            'PackedPolicySize',
            'Subject',
            'SubjectType' ]
        for k in response:
            if k in filtered_keys:
                filtered_response[k] = response[k]
        message = json_dumps(filtered_response, indent=2, sort_keys=True, default=lambda x: x.__str__())
    else:
        config.set(section, 'aws_access_key_id',
                   response['Credentials']['AccessKeyId'])
        config.set(section, 'aws_secret_access_key',
                   response['Credentials']['SecretAccessKey'])
        config.set(section, 'aws_session_token',
                   response['Credentials']['SessionToken'])
        with open(config_fn, 'w') as out:
            config.write(out)

    return message



def main():
    parser = ArgumentParser(
                    description='Get temporary AWS access credentials using LastPass SAML Login',
                    epilog=(
                          'The saml_config_id can be classic or Legacy SSO SAML config '
                          'id found at the end of the lastpass.com/saml/launch/cfg/XXXXX '
                          'URL.  It can also be the LastPass Identity Web App Id which is '
                          'a GUID: (00000000-0000-0000-0000-000000000000). You can obtain '
                          'this ID by specifying "list" instead.  After you login, it will '
                          'Print out a list Web App Ids and their configured Web App names.'
                    ))
    parser.add_argument('username', type=str,
                    help='the lastpass username')
    parser.add_argument('saml_config_id', type=str,
                    help='the LastPass Application ID (number | GUID | "list")')
    parser.add_argument('--profile-name', dest='profile_name',
                    help='the name of AWS profile to save the data in (default username)')
    parser.add_argument('--role-name', type=str, default=None,
                    help='A role name (the end part of the Role ARN) to automatically select')
    duration_arg = parser.add_argument('--duration', type=int, default=3600, dest='duration',
                    help='duration in seconds (900-3600) of the role session (default is 3600 or 1 hour)')
    parser.add_argument('--json', action='store_true',
                    help='display application list in json format.')
    parser.add_argument('--otp', type=str, default=None,
                    help='provide the OTP value directly instead of asking. this overrides --prompt-otp.')
    parser.add_argument('--prompt-otp', action='store_true',
                    help='always ask for OTP after providing password.')
    parser.add_argument('--silent-on-success', action='store_true',
                    help='dont print anything on success')
    parser.add_argument('--print-eval', action='store_true',
                    help='print out credentials as eval-able exports')
    parser.add_argument('--clear-session', action='store_true',
                    help='ignore and remove the saved session information')

    group_alt = parser.add_argument_group(
                    title='optional alternate role arguments',
                    description='Assume an alternate secondary role using the ' +
                    'assumed-role from LastPass.  Note that only the alternate credentials will be saved.')
    group_alt.add_argument('--alt-arn', dest='alt_arn',
                    help='Full ARN in the format: arn:aws:iam::123456789012:role/newrole')
    group_alt.add_argument('--alt-account', dest='alt_account',
                    help='AWS Account number to assume (must also provide --alt-role)'),
    group_alt.add_argument('--alt-role', dest='alt_role',
                    help='IAM Role name in the --alt-account to assume (must also provide --alt-account')

    args = parser.parse_args()

    if args.duration < 900 or args.duration > 3600:
        raise ArgumentError(duration_arg, 'Duration must be between 900 and 3600 seconds.')

    if args.profile_name is not None:
        profile_name = args.profile_name
    else:
        profile_name = args.username

    # Build the alt_arn string based on either args.alt_arn or both of args.alt_role and args.alt_account
    alt_arn = None
    if args.alt_account is not None or args.alt_role is not None or args.alt_arn is not None:
        if args.alt_account is not None and args.alt_role is not None:
            alt_arn = f"arn:aws:iam::{args.alt_account}:role/{args.alt_role}"
        else:
            if args.alt_arn is not None:
                alt_arn = args.alt_arn
            else:
                raise ArgumentError(group_alt, 'alt-role and alt-account must both be specified')

    # Setup a new session and load the cookies if available
    session = Session()
    needs_auth = load_session(session, SESSION_FILE, args.username, args.clear_session)

    # full login requires the password
    if needs_auth:
        password = getpass("Password: ", sys.stderr)

    if args.saml_config_id.lower() in [ "list", "apps", "webapps", "web_apps" ]:
        # Try to login to identity using the current session
        try:
            if needs_auth:
                full_lastpass_login(session, args.username, password, args.otp, args.prompt_otp)

            identity_login(session)
        except (ResponseValueError, KeyError):
            # We might need to login to lastpass again first
            full_lastpass_login(session, args.username, password, args.otp, args.prompt_otp)
            # try logging into identity again with refreshed credentials
            identity_login(session)

        app_list = get_app_list(session)

        if args.json:
            print(json_dumps(app_list,indent=2))
        else:
            print("+--------------------------------------+----------------------------------------------+")
            print("| Web Application Id                   | Application Name                             |")
            print("+--------------------------------------+----------------------------------------------+")
            for app in app_list:
                print(f'| {app["id"]:<36.36} | {app["name"]:<44.44} |')
            print("+--------------------------------------+----------------------------------------------+")

        save_session(session, SESSION_FILE, args.username, args.clear_session)
        return

    # Try to get the token using the current session
    try:
        if needs_auth:
            full_lastpass_login(session, args.username, password, args.otp, args.prompt_otp)

        assertion = get_saml_token(session, args.saml_config_id)
    except KeyError:
        # We might need to login to lastpass again first
        full_lastpass_login(session, args.username, password, args.otp, args.prompt_otp)
        # try initiating the saml process with refreshed credentials
        assertion = get_saml_token(session, args.saml_config_id)

    roles = get_saml_aws_roles(assertion)
    user = get_saml_nameid(assertion)

    role = prompt_for_role(roles, args.role_name)

    # All interaction with LastPass are complete.
    save_session(session, SESSION_FILE, args.username, args.clear_session)

    if alt_arn is None:
        response = aws_assume_role(session, assertion, role[0], role[1], args.duration)
        eval_output = aws_set_profile(profile_name, response, args.print_eval, args.json)
    else:
        # Set duration for the Primary SAML role to the minimum (15 mins) to
        # ensure this temporary token will expire as fast as possible.
        # Alternate token duration will be set to the specified (or default)
        # duration.
        response = aws_assume_role(session, assertion, role[0], role[1], 900)
        alt_response = aws_assume_role_alt(response, alt_arn, profile_name, args.duration)
        eval_output = aws_set_profile(profile_name, alt_response, args.print_eval, args.json)

    if args.print_eval or args.json:
        print(eval_output)
    elif not args.silent_on_success:
        print(f"A new AWS CLI profile '{profile_name}' has been added.")
        print("You may now invoke the aws CLI tool as follows:")
        print("")
        print(f"    aws --profile {profile_name} [...] ")
        print("")
        print(f"This token expires in {args.duration//60}:{args.duration%60:02d} minutes.")


if __name__ == "__main__":
    try:
        main()
    except (ArgumentError, ValueError, KeyboardInterrupt) as e:
        logger.error(e)
