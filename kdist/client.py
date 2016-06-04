#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from boto.connection import AWSQueryConnection
from boto.exception import BotoServerError
from boto.regioninfo import RegionInfo
from json import dumps as json_dumps, loads as json_loads

class KDistConnection(AWSQueryConnection):
    APIVersion = "2015-10-25"
    DefaultRegionName = "us-west-2"
    DefaultRegionEndpoint = "localhost"
    ServiceName = "kdistservice"

    def __init__(self, **kwargs):
        region = kwargs.pop('region', None)
        if not region:
            region = RegionInfo(self, self.DefaultRegionName,
                                self.DefaultRegionEndpoint)
        if 'host' not in kwargs or kwargs['host'] is None:
            kwargs['host'] = region.endpoint

        super(KDistConnection, self).__init__(**kwargs)
        self.region = region

    def _required_auth_capability(self):
        return ['hmac-v4']

    def execute(self, command, environment=None, user=None, directory=None,
                stdin=None):
        """
        Executes a command on the remote host.
        """
        params = {'command': command}
        if environment is not None:
            params['environment'] = environment
        if user is not None:
            params['user'] = user
        if directory is not None:
            params['directory'] = directory
        if stdin is not None:
            params['stdin'] = stdin

        return self.make_request("exec", params)

    def invoke(self, entrypoint, params):
        path = "/" + entrypoint
        body = json_dumps(params)
        headers = {
            'Host': self.region.endpoint,
            'Content-Type': 'application/json',
            'Content-Length': str(len(body)),
        }
        http_request = self.build_base_http_request(
            method='POST', path=path, auth_path=path, params={},
            headers=headers, data=body)
        response = self._mexe(http_request, sender=None, override_num_retries=1)
        response_body = response.read().decode('utf-8')

        if response.status == 200:
            if response_body:
                return json_loads(response_body)
            else:
                return
        else:
            raise KDistServerError(response.status, response.reason,
                                   response_body)

class KDistServerError(BotoServerError):
    pass

# Local variables:
# mode: Python
# tab-width: 8
# indent-tabs-mode: nil
# End:
# vi: set expandtab tabstop=8
