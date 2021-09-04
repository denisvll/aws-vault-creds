import collections

import os
import tempfile

from urllib.parse import urljoin
import requests
from requests.exceptions import HTTPError

CredentialPlugin = collections.namedtuple('CredentialPlugin', ['name', 'inputs', 'backend'])


def raise_for_status(resp):
    resp.raise_for_status()
    if resp.status_code >= 300:
        exc = HTTPError()
        setattr(exc, 'response', resp)
        raise exc


class CertFiles:
    """
    A context manager used for writing a certificate and (optional) key
    to $TMPDIR, and cleaning up afterwards.

    This is particularly useful as a shared resource for credential plugins
    that want to pull cert/key data out of the database and persist it
    temporarily to the file system so that it can loaded into the openssl
    certificate chain (generally, for HTTPS requests plugins make via the
    Python requests library)

    with CertFiles(cert_data, key_data) as cert:
        # cert is string representing a path to the cert or pemfile
        # temporarily written to disk
        requests.post(..., cert=cert)
    """

    certfile = None

    def __init__(self, cert, key=None):
        self.cert = cert
        self.key = key

    def __enter__(self):
        if not self.cert:
            return None
        self.certfile = tempfile.NamedTemporaryFile('wb', delete=False)
        self.certfile.write(self.cert.encode())
        if self.key:
            self.certfile.write(b'\n')
            self.certfile.write(self.key.encode())
        self.certfile.flush()
        return str(self.certfile.name)

    def __exit__(self, *args):
        if self.certfile and os.path.exists(self.certfile.name):
            os.remove(self.certfile.name)


def k8s_auth(**kwargs):
    sa_token_path = kwargs.get('sa_token_path', '/var/run/secrets/kubernetes.io/serviceaccount/token')
    role = kwargs['role']
    # we first try to use the 'auth_path' from the metadata
    # if not found we try to fetch the 'default_auth_path' from inputs
    auth_path = kwargs.get('auth_path') or kwargs['default_auth_path']

    url = urljoin(kwargs['url'], 'v1')
    cacert = kwargs.get('cacert', None)

    with open(sa_token_path, 'r') as fd:
        sa_token = fd.read()

    request_kwargs = {'timeout': 30}
    # AppRole Login
    request_kwargs['json'] = {'jwt': sa_token, 'role': role}
    sess = requests.Session()
    # Namespace support
    if kwargs.get('namespace'):
        sess.headers['X-Vault-Namespace'] = kwargs['namespace']
    request_url = '/'.join([url, 'auth', auth_path, 'login']).rstrip('/')

    with CertFiles(cacert) as cert:
        request_kwargs['verify'] = cert
        resp = sess.post(request_url, **request_kwargs)
    resp.raise_for_status()
    token = resp.json()['auth']['client_token']
    return token


def aws_cred(**kwargs):
    token = k8s_auth(**kwargs)
    url = kwargs['url']
    creds_path = kwargs['creds_path']
    creds_backend = kwargs.get('creds_backend', None)
    cacert = kwargs.get('cacert', None)

    request_kwargs = {
        'timeout': 30,
        'allow_redirects': False,
    }

    sess = requests.Session()
    sess.headers['Authorization'] = 'Bearer {}'.format(token)
    # Compatibility header for older installs of Hashicorp Vault
    sess.headers['X-Vault-Token'] = token
    if kwargs.get('namespace'):
        sess.headers['X-Vault-Namespace'] = kwargs['namespace']

    request_url = '/'.join([url, 'v1', creds_backend, 'creds', creds_path]).rstrip('/')
    print(request_url)
    with CertFiles(cacert) as cert:
        request_kwargs['verify'] = cert
        resp = sess.get(request_url, **request_kwargs)

    raise_for_status(resp)
    auth_data = "aws_access_key_id = {}\naws_secret_access_key = {}\naws_security_token = {}\n".format(
        resp.json()['data']['access_key'], resp.json()['data']['secret_key'], resp.json()['data']['security_token'])
    return auth_data


plugin = CredentialPlugin(
    'Example AWX Credential Plugin',
    # see: https://docs.ansible.com/ansible-tower/latest/html/userguide/credential_types.html
    # inputs will be used to create a new CredentialType() instance
    #
    # inputs.fields represents fields the user will specify *when they create*
    # a credential of this type; they generally represent fields
    # used for authentication (URL to the credential management system, any
    # fields necessary for authentication, such as an OAuth2.0 token, or
    # a username and password). They're the types of values you set up _once_
    # in AWX
    #
    # inputs.metadata represents values the user will specify *every time
    # they link two credentials together*
    # this is generally _pathing_ information about _where_ in the external
    # management system you can find the value you care about i.e.,
    #
    # "I would like Machine Credential A to retrieve its username using
    # Credential-O-Matic B at identifier=some_key"
    inputs={
        'fields': [{
            'id': 'url',
            'label': 'Server URL',
            'type': 'string',
        }, {
            'id': 'token',
            'label': 'Authentication Token',
            'type': 'string',
            'secret': True,
        }],
        'metadata': [{
            'id': 'identifier',
            'label': 'Identifier',
            'type': 'string',
            'help_text': 'The name of the key in My Credential System to fetch.'
        }],
        'required': ['url', 'token', 'secret_key'],
    },
    # backend is a callable function which will be passed all of the values
    # defined in `inputs`; this function is responsible for taking the arguments,
    # interacting with the third party credential management system in question
    # using Python code, and returning the value from the third party
    # credential management system
    backend=aws_cred
)
