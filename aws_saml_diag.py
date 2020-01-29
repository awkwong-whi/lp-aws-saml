#!/usr/bin/env python3
# -*- coding: utf8 -*-
#
# Amazon Web Services CLI - LastPass SAML integration
#
# Copyright (c) 2020 West Health Institute
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
from json import dumps as json_dumps
from hashlib import sha1
from xml.etree import ElementTree
from base64 import b64encode
from typing import Optional

def diag_enabled() -> bool:
    """Indicates diagnostics module (this one) is available"""
    return True


def dump_assertion_attributes(assertion: str, assume_result: Optional[dict] = None) -> None:
    """
    Provide a simplified summary of the Assertion in JSON format for
    Verifying the correct attributes and matching those attributes
    with IAM Condition Strings.
    If the assume_result is provided, compare and verify that the Assertion
    Values that are used to generate the result match.
    Output JSON object includes:
    * audience
    * saml:*       -- any saml:* attributes found or generated.
    * sts:*        -- any sts:* attributes found or generated.
    * aws:*        -- any aws:* attributes found or generated.
    * RoleSessionName
    * SessionDuration
    * status_check -- present if there are errors discovered.
    * attributes   -- list of attributes extracted from the
                      assertion. certain attributes will have
                      annotations for faster understanding.
    """

    # Namespace required for ElementTree
    ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
    # dict for all Name to friendlyName mappings
    friendly = {
        "0.9.2342.19200300.100.1.45": { "friendlyName": "organizationStatus", "array": True },
        "0.9.2342.19200300100.1.1": { "friendlyName": "uid", "array": True },
        "0.9.2342.19200300100.1.3": { "friendlyName": "mail", "array": True },
        "2.4.5.42": { "friendlyName": "givenName", "array": True },
        "2.5.4.3": { "friendlyName": "commonName", "array": True },
        "2.5.4.4": { "friendlyName": "surname", "array": True },
        "2.5.4.45": { "friendlyName": "x500UniqueIdentifier", "array": True },
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid": { "friendlyName": "uid", "array": True },
        "http://schemas.xmlsoap.org/claims/CommonName": { "friendlyName": "commonName", "array": True },
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": { "friendlyName": "mail", "array": True },
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": { "friendlyName": "givenName", "array": True },
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": { "friendlyName": "name", "array": True },
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": { "friendlyName": "surname", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.1": { "friendlyName": "eduPersonAffiliation", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.10": { "friendlyName": "eduPersonTargetedID", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.11": { "friendlyName": "eduPersonAssurance", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.2": { "friendlyName": "eduPersonNickname", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.3": { "friendlyName": "eduPersonOrgDN", "array": False },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.4": { "friendlyName": "eduPersonOrgUnitDN", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.5": { "friendlyName": "eduPersonPrimaryAffiliation", "array": False },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.6": { "friendlyName": "eduPersonPrincipalName", "array": False },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.7": { "friendlyName": "eduPersonEntitlement", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.8": { "friendlyName": "eduPersonPrimaryOrgUnitDN", "array": False },
        "urn:oid:1.3.6.1.4.1.5923.1.1.1.9": { "friendlyName": "eduPersonScopedAffiliation", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.2.1.2": { "friendlyName": "eduOrgHomePageURI", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.2.1.3": { "friendlyName": "eduOrgIdentityAuthNPolicyURI", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.2.1.4": { "friendlyName": "eduOrgLegalName", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.2.1.5": { "friendlyName": "eduOrgSuperiorURI", "array": True },
        "urn:oid:1.3.6.1.4.1.5923.1.2.1.6": { "friendlyName": "eduOrgWhitePagesURI", "array": True },
        "urn:oid:2.5.4.3": { "friendlyName": "cn", "array": True }
    }
    # List of valid subtypes
    valid_subtypes = [
        "persistent",
        "transient",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
    ]
    # List of typical Audience values
    typical_audience = [
        "https://signin.aws.amazon.com/saml",
        "https://signin.amazonaws-us-gov.com/saml",
        "urn:amazon:webservices",
    ]

    # Placeholder for the extracted RoleSessionName (if found)
    roleSessionName = None
    # Placeholder for the Account number the Assertion is directed towards
    samlAccount = None
    # Placeholder for the Issuer from the Assertion
    samlIssuer = None
    # Placeholder for the Provider from the Role Selector
    samlProvider = None
    # Placeholder for the Constructed string based on samlIssuer, samlAccount, and samlProvider
    nameQualifierString = None
    # Placeholder for the base64 encoded SHA1 has of the nameQualifierString
    nameQualifier = None

    assume = {
        "Status": False,
        "Role": {
            "Id": None,
            "Arn": None,
            "Account": None,
            "Name": None,
            "SessionName": None,
        },
        "Subject": None,
        "SubjectType": None,
        "Issuer": None,
        "Audience": None,
        "NameQualifier": None,
        "PackedPolicySize": None,
        "RequestId": None,
    }

    if assume_result is not None:
        rmd = assume_result.get("ResponseMetadata", None)
        if rmd:
            assume["Status"] = rmd.get("HTTPStatusCode", 0) == 200
            assume["RequestId"] = rmd.get("RequestId", None)
        aru = assume_result.get("AssumedRoleUser", None)
        if aru:
            assume["Role"]["Id"] = aru.get("AssumedRoleId", None)
            assume["Role"]["Arn"] = aru.get("Arn", None)
        aroleparts = assume["Role"]["Arn"].split(":assumed-role/",1)
        if len(aroleparts) >= 2:
            rightparts = aroleparts[1].split("/", 1)
            if len(rightparts) >= 2:
                assume["Role"]["Name"] = rightparts[0]
                assume["Role"]["SessionName"] = rightparts[1]
            leftparts = aroleparts[0].rsplit(":", 1)
            if len(leftparts) >= 2:
                assume["Role"]["Account"] = leftparts[1]
        assume["Subject"] = assume_result.get("Subject", None)
        assume["SubjectType"] = assume_result.get("SubjectType", None)
        assume["Issuer"] = assume_result.get("Issuer", None)
        assume["Audience"] = assume_result.get("Audience", None)
        assume["NameQualifier"] = assume_result.get("NameQualifier", None)
        assume["PackedPolicySize"] = assume_result.get("PackedPolicySize", None)

    # The Assertion descriptor structure that carries everything.
    a = {}

    # the primary parser
    doc = ElementTree.fromstring(assertion)

    # Audience Check
    e = doc.find(".//saml:AudienceRestriction/saml:Audience",ns)
    if e is None:
        a['audience'] = { 
            "status": "Missing", 
            "message": "malformed assertion missing /Response/Assertion/Conditions/AudienceRestriction/Audience.",
            "typical_values": typical_audience,
        }
    else:
        a['audience'] = e.text

    # SubjectConfirmationData Check
    e = doc.find(".//saml:SubjectConfirmationData",ns)
    if e is None:
        a['saml:aud'] = { 
            "status": "Missing",
            "message": "malformed assertion missing /Response/Assertion/Subject/SubjectConfirmationData",
            "typical_values": [
                "https://signin.aws.amazon.com/saml",
                "https://signin.amazonaws-us-gov.com/saml",
            ]
        }
    else:
        a['saml:aud'] = e.attrib.get('Recipient')

    # Issuer Check
    e = doc.find(".//saml:Issuer",ns)
    if e is None:
        a['saml:iss'] = { 
            "status": "Missing", 
            "message":  "malformed assertion missing /Response/Issuer",
            "typical_values": [
                "https://lastpass.com/saml/idp",
                "https://lastpass.com/saml/idp/cfg/xxxxx",
                "https://identity.lastpass.com",
                "Identity SSO Appliation Step 4 - IDP field",
            ]
        }
    else:
        a['saml:iss'] = e.text
        samlIssuer = e.text

    # Subject NameID Check
    e = doc.find(".//saml:NameID",ns)
    if e is None:
        a['saml:sub'] = { 
            "status": "Missing", 
            "message": "malformed assertion. /Response/Assertion/Subject/NameID",
            "typical_values": [
                "Email Address",
                "AD objectGUID: {00000000-0000-0000-0000-000000000000}",
                "AD objectGUID: AAAAAAAAAAAAAAAAAAAAAA==",
                "AD sAMAccountName: user@domain"
            ]
        }
    else:
        a['saml:sub'] = e.text

    # Subject Type Check
    e = doc.find(".//saml:NameID[@Format]",ns)
    if e is None:
       a['saml:sub_type'] = { 
            "status": "Missing", 
            "message": "malformed assertion attribute Format missing from /Response/Assertion/Subject/NameID",
            "typical_values": valid_subtypes,
        }
    else:
        if e.attrib.get('Format', '!!invalid!!') not in valid_subtypes:
            a['saml:sub_type'] = {
                "status": "Value not recognized",
                "message": "value must be one of the typical values",
                "typical_values": valid_subtypes
            }
        else:
            a['saml:sub_type'] = e.attrib.get('Format', '!!invalid!!')

    # A list of found attributes
    attr_list = []
    # A list of special attributes to put in after the regular attributes
    specialAttributes = []
    # Set to count any mismatches in account numbers found in the Role Attribute Values
    role_account_set = set()

    # Attributes Scanner
    for attr in doc.findall(".//saml:Attribute", ns):
        attr_name = attr.attrib.get('Name','! Unnamed')

        # Scan all AttributeValue Elements
        attr_value = []
        for value in attr.findall(".//saml:AttributeValue", ns):
            new_value = { "value": value.text }
            for aname, aval in value.attrib.items():
                if "type" in aname.lower():
                    # only want to know if it isn't a string type
                    if "string" not in aval.lower():
                        new_value["type"] = aval
            if attr_name == "https://aws.amazon.com/SAML/Attributes/Role":
                if ',' in value.text:
                    account_number = None
                    role_name = None
                    principal_name = None
                    info = { "role": {}, "principal": {} }

                    attr_parts = value.text.split(",",2)
                    if len(attr_parts) >= 2:
                        info["role"]["arn"] = role_part = attr_parts[0]
                        info["principal"]["arn"] = principal_part = attr_parts[1]

                    role_parts = role_part.split(":role/",1)
                    if len(role_parts) >= 2:
                        role_name = role_parts[1]
                        info["role"]["name"] = role_name
                        left_parts = role_parts[0].rsplit(":", 1)
                        if len(left_parts) >=2:
                            account_number = left_parts[1]
                            info["role"]["account"] = account_number
                            role_account_set.add(account_number)

                    principal_parts = principal_part.split(":saml-provider/", 1)
                    if len(principal_parts) >= 2:
                        principal_name = principal_parts[1]
                        info["principal"]["name"] = principal_name

                    new_value["info"] = info

                    if samlAccount is None and account_number is not None:
                        samlAccount = account_number
                    if samlProvider is None and principal_name is not None:
                        samlProvider = principal_name

            attr_value.append(new_value)
        new_attr = {}

        # Process attributes for special matches

        # Look for matching friendly names and check whether singular values
        # have the correct ordinality
        if attr_name in friendly:
            new_attr["friendlyName"] = friendly[attr_name]["friendlyName"]
            new_attr["name"] = attr_name
            new_attr["multipleValuesAllowed"] = friendly[attr_name]["array"]
            if not friendly[attr_name]["array"]:
                if len(attr_value) > 1:
                    new_attr["status"] = "Too many values"
                    new_attr["message"] = "Attribute only supports a single value."
        else: 
            new_attr["name"] = attr_name

        # coalesce value elements into attribute node if there is only one
        # value.
        if len(attr_value) == 1:
            for k,v in attr_value[0].items():
                new_attr[k] = v
        else:
            new_attr["value"] = new_attr

        if attr_name in friendly:
            # Attach to the root for a friendly attribute as sub:friendlyName
            a[f"sub:{friendly[attr_name]}"] = new_attr
        elif attr_name == "https://aws.amazon.com/SAML/Attributes/RoleSessionName":
            # RoleSessionName
            if len(attr_value) > 1:
                new_attr["status"] = "Too many values"
                new_attr["message"] = "RoleSessionName must contain only one value."
            else:
                roleSessionName = new_attr["value"]
            specialAttributes.append({
               "name": "RoleSessionName",
               "attr": new_attr if "status" in new_attr else new_attr["value"]
            })
        elif attr_name == "https://aws.amazon.com/SAML/Attributes/SessionDuration":
            # SessionDuration
            if len(attr_value) > 1:
                new_attr["status"] = "Too many values"
                new_attr["message"] = "SessionDuration must contain only one value."
            elif isdigit(new_attr["value"]):
                duration = int(new_attr["value"])
                if duration < 900 or duration > 43200:
                    new_attr["status"] = "Value out of range"
                    new_attr["message"] = "SessionDuration must be between 900 and 43200."
            else:
                new_attr["status"] = "Invalid type"
                new_attr["message"] = "SessionDuration must be a number"
            specialAttributes.append({
                "name": "SessionDuration",
                "attr": new_attr if "status" in new_attr else int(new_attr["value"])
            })
        elif attr_name.startswith("https://aws.amazon.com/SAML/Attributes/PrincipalTag:"):
            # PrincipalTag
            left, tag = attr_name.split('PrincipalTag:')
            new_attr["tag"] = tag
            if len(attr_value) > 1:
                new_attr["status"] = "Too many values"
                new_attr["message"] = "PrincipalTag:* must contain only one value."
            a[f"aws:PrincipalTag/{tag}"] = new_attr if "status" in new_attr else new_attr["value"]
        elif attr_name == "https://aws.amazon.com/SAML/Attributes/TransitiveTagKeys":
            # TransitiveTagKeys
            tags = [ new_attr["value"] ] if len(new_attr["value"]) > 1 else [ a["value"] for a in new_attr["value"] ]
            a["sts:TransitiveTagKeys"] = tags
        attr_list.append(new_attr)

    # Generate the doc attribute
    if samlProvider is not None and samlAccount is not None:
        a["saml:doc"] = f"{samlAccount}/{samlProvider}"

    # Generate the nameQualifier attribute
    if samlIssuer is not None and samlAccount is not None and samlProvider is not None:
        nameQualifierString = samlIssuer + samlAccount + '/' + samlProvider
        nameQualifier = b64encode(sha1(nameQualifierString.encode()).digest()).decode()
        a["saml:namequalifier"] = nameQualifier 

    # Put the special attributes at the end of the current set of attributes
    for special in specialAttributes:
        a[special["name"]] = special["attr"]

    # Add the rest of the attributes
    a['attributes'] = attr_list

    # If we were provided with a response structure from AWS STS AssumeRoleWithSAML()
    # check it all.
    if assume["Status"]:
        a['assume_info'] = {}
        a['assume_info']["AssumedRoleId"] = assume["Role"]["Id"]
        a['assume_info']["AssumedRoleName"]=  assume["Role"]["Name"]
        if assume["PackedPolicySize"]:
            a['assume_info']["PackedPolicySize"] = assume["PackedPolicySize"]
        a['assume_info']["RequestId"] = assume["RequestId"]

        status_check = {}
        if type(a['audience']) is str:
            if a['audience'] not in typical_audience:
                status_check['Audience'] = {
                    "status": "Warning",
                    "message": "Audience value is not one of the typical documented values.",
                    "audience": a['audience'],
                    "typical_values": typical_audience,
                }
        if assume["Role"]["Id"]:
            if not assume["Role"]["Id"].endswith(roleSessionName):
                status_check['AssumedRoleId'] = {
                    "status": "Mismatch",
                    "message": "AssumedRoleId did not include the matching RoleSessionName.",
                    "response": assume["Role"]["Id"],
                    "assertion": roleSessionName,
                }
        if assume["Role"]["Arn"]:
            if not assume["Role"]["Arn"].endswith(roleSessionName):
                if 'AssumedRoleArn' not in status_check:
                    status_check['AssumedRoleArn'] = []
                status_check['AssumedRoleArn'].append({
                    "status": "Mismatch",
                    "message": "AssumedRoleArn did not include the matching RoleSessionName.",
                    "response": assume["Role"]["Arn"],
                    "assertion": roleSessionName,
                })
        if assume["Role"]["Account"]:
            if not assume["Role"]["Account"] == samlAccount:
                if 'AssumedRoleArn' not in status_check:
                    status_check['AssumedRoleArn'] = []
                status_check['AssumedRoleArn'].append({
                    "status": "Mismatch",
                    "message": "AssumedRoleArn Account number and Role Attribute Account number did not match.",
                    "response": assume["Role"]["Account"],
                    "assertion": samlAccount,
                }) 
        if len(role_account_set) > 2:
            status_check['RoleAccountCount'].append({
                "status": "TooManyAccounts",
                "message": "Role list should only reference one account number. {len(role_account_set)} were found.",
                "account": assume["Role"]["Account"],
                "accounts_found": list(role_account_set),
            })
        if assume["Subject"] and type(a['saml:sub']) is str:
            if not assume["Subject"] == a['saml:sub']:
                status_check['Subject'] = {
                    "status": "Mismatch",
                    "message": "Subject in Response did not match saml:sub from Assertion.",
                    "response": assume["Subject"],
                    "assertion": a['saml:sub'],
                }
        if assume["SubjectType"] and type(a['saml:sub_type']) is str:
            if not a['saml:sub_type'].endswith(assume["SubjectType"]):
                status_check['SubjectType'] = {
                    "status": "Mismatch",
                    "message": "SubjectType in Response did not match or match the ending of saml:sub_type",
                    "response": assume["SubjectType"],
                    "assertion": a['saml:sub_type'],
                }
        if assume["Issuer"] and type(a['saml:iss']) is str:
            if not assume["Issuer"] == a['saml:iss']:
                status_check['Issuer'] = {
                    "status": "Mismatch",
                    "message": "Issuer in Response did not match sub:iss from Assertion.",
                    "response": assume["Issuer"],
                    "assertion": a['saml:iss'],
                }
        if assume["Audience"] and type(a['saml:aud']) is str and type(a['audience']) is str:
            if not (assume["Audience"] == a['saml:aud']) and (assume['Audience'] == a['audience']):
                status_check['Issuer'] = {
                    "status": "Mismatch",
                    "message": "Audience in Response did not match Audience and/or saml:aud from Assertion.",
                    "response": assume["Audience"],
                    "assertion": [ a['saml:aud'], a['audience'] ],
                }
        if assume["NameQualifier"] and nameQualifier:
            if not assume["NameQualifier"] == nameQualifier:
                status_check['NameQualifier'] = {
                    "status": "Mismatch",
                    "message": "NameQualifier in Response did not match the Calculated saml:namequalifier from Assertion.",
                    "nameQualifierString": nameQualifierString if nameQualifierString else "",
                    "response": assume["NameQualifier"],
                    "assertion": a['saml:namequalifier'],
                }
        # don't include the status_check if everything was good.
        if len(status_check) > 0:
            a['status_check'] = status_check

    print(json_dumps(a, indent=2))

