#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from collections import OrderedDict
from datetime import datetime, timedelta
from hashlib import sha256
import hmac
from re import compile as re_compile
from six.moves import cStringIO
from string import ascii_letters, digits
from urllib import unquote as url_unquote

# Algorithm for AWS SigV4
AWS4_HMAC_SHA256 = "AWS4-HMAC-SHA256"

# Unreserved characters from RFC 3986.
_rfc3986_unreserved = set(ascii_letters + digits + "-._~")

# HTTP date format
_http_date_format = "%a, %d %b %Y %H:%M:%S %Z"

# Header and query string keys
_authorization = "authorization"
_aws4_request = "aws4_request"
_credential = "Credential"
_date = "date"
_signature = "Signature"
_signedheaders = "SignedHeaders"
_x_amz_algorithm = "X-Amz-Algorithm"
_x_amz_credential = "X-Amz-Credential"
_x_amz_date = "X-Amz-Date"
_x_amz_signature = "X-Amz-Signature"
_x_amz_signedheaders = "X-Amz-SignedHeaders"

# ISO8601 timestamp format regex
_iso8601_timestamp_regex = re_compile(
    r"^(?P<year>[0-9]{4})"
    r"(?P<month>0[1-9]|1[0-2])"
    r"(?P<day>0[1-9]|[12][0-9]|3[01])"
    r"T"
    r"(?P<hour>[01][0-9]|2[0-3])"
    r"(?P<minute>[0-5][0-9])"
    r"(?P<second>[0-5][0-9]|6[01])"
    r"Z$")

# Match for multiple slashes
_multislash = re_compile(r"//+")

class InvalidSignatureError(StandardError):
    """
    An exception indicating that the signature on the request was invalid.
    """
    pass

class AWSSigV4Verifier(object):
    def __init__(self, request_method, uri_path, query_string, headers,
                 body, region, service, key_mapping, timestamp_mismatch=60):
        """
        AWSSigV4Verifier(request_method, uri_path, query_string, headers, body, region, service, key_mapping, timestamp_mismatch=60)

        Create a new AWSSigV4Verifier instance.
        """
        super(AWSSigV4Verifier, self).__init__()

        l = locals()
        # Verify string parameters
        for param in ["request_method", "uri_path", "query_string", "body",
                      "region", "service"]:
            if not isinstance(l[param], basestring):
                raise TypeError("Expected %s to be a string" % param)

        for key, value in headers.iteritems():
            if not isinstance(key, basestring):
                raise TypeError("Invalid key in headers: %r" % key)

            if not isinstance(value, basestring):
                raise TypeError("Invalid value in headers: %r" % value)

        self.request_method = request_method
        self.uri_path = uri_path
        self.query_string = query_string
        self.headers = headers
        self.body = body
        self.region = region
        self.service = service
        self.key_mapping = key_mapping
        self.timestamp_mismatch = timestamp_mismatch
        return

    @property
    def canonical_uri_path(self):
        """
        The canonicalized URI path from the request.
        """
        result = getattr(self, "_canonical_uri_path", None)
        if result is None:
            result = self._canonical_uri_path = get_canonical_uri_path(
                self.uri_path)
        return result

    @property
    def query_parameters(self):
        """
        A key to list of values mapping of the query parameters seen in the
        request.
        """
        result = getattr(self, "_query_parameters", None)
        if result is None:
            result = self._query_parameters = normalize_query_parameters(
                self.query_string)
        return result

    @property
    def canonical_query_string(self):
        """
        The canonical query string from the query parameters.

        This takes the query string from the request and orders the parameters
        in 
        """
        results = []
        for key, values in self.query_parameters.iteritems():
            # Don't include the signature itself.
            if key == _x_amz_signature:
                continue
            
            for value in values:
                results.append("%s=%s" % (key, value))
            
        return "&".join(sorted(results))

    @property
    def authorization_header_parameters(self):
        """
        The parameters from the Authorization header (only).  If the
        Authorization header is not present or is not an AWS SigV4 header, an
        AttributeError exception is raised.
        """
        result = getattr(self, "_authorization_header_parameters", None)
        if result is None:
            auth = self.headers.get(_authorization)
            if auth is None:
                raise AttributeError("Authorization header is not present")
            
            if not auth.startswith(AWS4_HMAC_SHA256 + " "):
                raise AttributeError("Authorization header is not AWS SigV4")

            result = {}
            for parameter in auth[len(AWS4_HMAC_SHA256)+1:].split(","):
                parameter = parameter.strip()
                try:
                    key, value = parameter.split("=", 1)
                except ValueError:
                    raise AttributeError(
                        "Invalid Authorization header: missing '='")

                if key in result:
                    raise AttributeError(
                        "Invalid Authorization header: duplicate key %r" % key)
                
                result[key] = value
            
            self._authorization_header_parameters = result
        return result

    @property
    def signed_headers(self):
        """
        An ordered dictionary containing the signed header names and values.
        """
        # See if the signed headers are listed in the query string
        signed_headers = self.query_parameters.get(_x_amz_signedheaders)
        if signed_headers is not None:
            signed_headers = url_unquote(signed_headers[0])
        else:
            # Get this from the authentication header
            signed_headers = self.authorization_header_parameters[
                _signedheaders]

        # Header names are separated by semicolons.
        parts = signed_headers.split(";")

        # Make sure the signed headers list is canonicalized.  For security
        # reasons, we consider it an error if it isn't.
        canonicalized = sorted([sh.lower() for sh in parts])
        if parts != canonicalized:
            raise AttributeError("SignedHeaders is not canonicalized: %r" %
                                 (signed_headers,))

        # Allow iteration in-order.
        return OrderedDict([(header, self.headers[header])
                            for header in signed_headers.split(";")])

    @property
    def request_date(self):
        """
        The date of the request in ISO8601 YYYYMMDD format.

        If this is not available in the query parameters or headers, or the
        value is not a valid format for AWS SigV4, an AttributeError exception
        is raised.
        """
        return self.request_timestamp[:8]

    @property
    def request_timestamp(self):
        """
        The timestamp of the request in ISO8601 YYYYMMDD'T'HHMMSS'Z' format.

        If this is not available in the query parameters or headers, or the
        value is not a valid format for AWS SigV4, an AttributeError exception
        is raised.
        """
        amz_date = self.query_parameters.get(_x_amz_date)
        if amz_date is not None:
            amz_date = amz_date[0]
        else:
            amz_date = self.headers.get(_x_amz_date)
            if amz_date is None:
                date = self.headers.get(_date)
                if date is None:
                    raise AttributeError("Date was not passed in the request")

                # This isn't really valid -- seems to be a bug in the AWS
                # documentation.
                if _iso8601_timestamp_regex.match(date):
                    amz_date = date # pragma: nocover
                else:
                    # Parse this as an HTTP date and reformulate it.
                    amz_date = (datetime.strptime(date, _http_date_format)
                                .strftime("%Y%m%dT%H%M%SZ"))
        if not _iso8601_timestamp_regex.match(amz_date):
            raise AttributeError("X-Amz-Date parameter is not a valid ISO8601 "
                                 "string: %r" % amz_date)

        return amz_date

    @property
    def credential_scope(self):
        """
        The scope of the credentials to use.
        """
        return (self.request_date + "/" + self.region + "/" + self.service +
                "/" + _aws4_request)

    @property
    def access_key(self):
        """
        The access key id used to sign the request.

        If the access key is not in the same credential scope as this request,
        an AttributeError exception is raised.
        """
        credential = self.query_parameters.get(_x_amz_credential)
        if credential is not None:
            credential = url_unquote(credential[0])
        else:
            credential = self.authorization_header_parameters.get(_credential)

            if credential is None:
                raise AttributeError("Credential was not passed in the request")
        try:
            key, scope = credential.split("/", 1)
        except ValueError:
            raise AttributeError("Invalid request credential: %r" % credential)

        if scope != self.credential_scope:
            raise AttributeError("Incorrect credential scope: %r (wanted %r)" %
                                 (scope, self.credential_scope))

        return key

    @property
    def request_signature(self):
        """
        The signature passed in the request.
        """
        signature = self.query_parameters.get(_x_amz_signature)
        if signature is not None:
            signature = signature[0]
        else:
            signature = self.authorization_header_parameters.get(_signature)
            if signature is None:
                raise AttributeError("Signature was not passed in the request")
            
        return signature

    @property
    def canonical_request(self):
        """
        The AWS SigV4 canonical request given parameters from an HTTP request.
        This process is outlined here:
        http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        The canonical request is:
            request_method + '\n' +
            canonical_uri_path + '\n' +
            canonical_query_string + '\n' +
            signed_headers + '\n' +
            sha256(body).hexdigest()
        """
        signed_headers = self.signed_headers
        header_lines = "".join(
            ["%s:%s\n" % item for item in signed_headers.iteritems()])
        header_keys = ";".join([key for key in self.signed_headers.iterkeys()])
        
        return (self.request_method + "\n" +
                self.canonical_uri_path + "\n" +
                self.canonical_query_string + "\n" +
                header_lines + "\n" +
                header_keys + "\n" +
                sha256(self.body).hexdigest())

    @property
    def string_to_sign(self):
        """
        The AWS SigV4 string being signed.
        """
        return (AWS4_HMAC_SHA256 + "\n" +
                self.request_timestamp + "\n" +
                self.credential_scope + "\n" +
                sha256(self.canonical_request).hexdigest())

    @property
    def expected_signature(self):
        """
        The AWS SigV4 signature expected from the request.
        """
        k_secret = "AWS4" + self.key_mapping[self.access_key]
        k_date = hmac.new(k_secret, self.request_date, sha256).digest()
        k_region = hmac.new(k_date, self.region, sha256).digest()
        k_service = hmac.new(k_region, self.service, sha256).digest()
        k_signing = hmac.new(k_service, _aws4_request, sha256).digest()

        return hmac.new(k_signing, self.string_to_sign, sha256).hexdigest()

    def verify(self):
        """
        Verifies that the request timestamp is not beyond our allowable
        timestamp mismatch and that the request signature matches our
        expectations.
        """
        try:
            if self.timestamp_mismatch is not None:
                m = _iso8601_timestamp_regex.match(self.request_timestamp)
                year = int(m.group("year"))
                month = int(m.group("month"))
                day = int(m.group("day"))
                hour = int(m.group("hour"))
                minute = int(m.group("minute"))
                second = int(m.group("second"))

                req_ts = datetime(year, month, day, hour, minute, second)
                now = datetime.utcnow()

                if abs(req_ts - now) > timedelta(0, self.timestamp_mismatch):
                    raise InvalidSignatureError("Timestamp mismatch")

            if self.expected_signature != self.request_signature:
                from sys import stderr
                print("Signature mismatch: expected %r, got %r" % (
                    self.expected_signature, self.request_signature),
                      file=stderr)
                raise InvalidSignatureError(
                    "Signature mismatch: expected %r, got %r" % (
                        self.expected_signature, self.request_signature))
        except (AttributeError, KeyError, ValueError) as e:
            raise InvalidSignatureError(str(e))

        return True

def normalize_uri_path_component(path_component):
    """
    normalize_uri_path_component(path_component) -> str

    Normalize the path component according to RFC 3986.  This performs the
    following operations:
    * Alpha, digit, and the symbols '-', '.', '_', and '~' (unreserved
      characters) are left alone.
    * Characters outside this range are percent-encoded.
    * Percent-encoded values are upper-cased ('%2a' becomes '%2A')
    * Percent-encoded values in the unreserved space (%41-%5A, %61-%7A,
      %30-%39, %2D, %2E, %5F, %7E) are converted to normal characters.

    If a percent encoding is incomplete, the percent is encoded as %25.

    A ValueError exception is thrown if a percent encoding includes non-hex
    characters (e.g. %3z).
    """
    result = cStringIO()

    i = 0
    while i < len(path_component):
        c = path_component[i]
        if c in _rfc3986_unreserved:
            result.write(c)
            i += 1
        elif c == "%":
            if i + 2 >= len(path_component):
                result.write("%25")
                i += 1
                continue
            try:
                value = int(path_component[i+1:i+3], 16)
            except ValueError:
                raise ValueError("Invalid %% encoding at position %d" % i)
            
            c = chr(value)
            if c in _rfc3986_unreserved:
                result.write(c)
            else:
                result.write("%%%02X" % value)
            
            i += 3
        elif c == "+":
            # Plus-encoded space.  Convert this to %20.
            result.write("%20")
            i += 1
        else:
            result.write("%%%02X" % ord(c))
            i += 1
    
    return result.getvalue()

def get_canonical_uri_path(uri_path):
    """
    get_canonical_uri_path(uri_path) -> str

    Normalizes the specified URI path component, removing redundant slashes
    and relative path components.

    A ValueError exception is raised if:
    * The URI path is not empty and not absolute (does not start with '/').
    * A parent relative path element ('..') attempts to go beyond the top.
    * An invalid percent-encoding is encountered.
    """
    # Special case: empty path is converted to '/'
    if uri_path == "" or uri_path == "/":
        return "/"

    # All other paths must be absolute.
    if not uri_path.startswith("/"):
        raise ValueError("URI path is not absolute.")

    # Replace double slashes; this makes it easier to handle slashes at the
    # end.
    uri_path = _multislash.sub("/", uri_path)
    
    # Examine each path component for relative directories.
    components = uri_path.split("/")[1:]
    i = 0
    while i < len(components):
        # Fix % encodings.
        component = normalize_uri_path_component(components[i])
        components[i] = component
        
        if components[i] == ".":
            # Relative current directory.  Remove this.
            del components[i]

            # Don't increment i; with the deletion, we're now pointing to
            # the next element in the path.
        elif components[i] == "..":
            # Relative path: parent directory.  Remove this and the previous
            # component.
            if i == 0:
                # Not allowed at the beginning!
                raise ValueError("URI path attempts to go beyond root")
            del components[i-1:i+1]

            # Since we've deleted two components, we need to back up one to
            # examine what's now the next component.
            i -= 1
        else:
            # Leave it alone; proceed to the next component.
            i += 1
    
    return "/" + "/".join(components)

def normalize_query_parameters(query_string):
    """
    normalize_query_parameters(query_string) -> dict

    Converts a query string into a list of parameters.  This ensurses that the
    query string follows % encoding rules according to RFC 3986 and checks
    for duplicate keys.

    A ValueError exception is raised if a percent encoding is invalid.
    """
    if query_string == "":
        return {}

    components = query_string.split("&")
    result = {}

    for component in components:
        try:
            key, value = component.split("=", 1)
        except ValueError:
            key = component
            value = ""

        if component == "":
            # Empty component; skip it.
            continue
        
        key = normalize_uri_path_component(key)
        value = normalize_uri_path_component(value)

        if key in result:
            result[key].append(value)
        else:
            result[key] = [value]

    return dict([(key, sorted(values))
                 for key, values in result.iteritems()])



# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
