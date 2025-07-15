"""
An RFC-4217 asynchronous FTPS server supporting both SSL and TLS.
Requires the PyOpenSSL module (https://pypi.org/project/pyOpenSSL).
"""

from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
authorizer = DummyAuthorizer()
# Add user 1, username='user1', password='12345', home directory is current directory, full permissions
authorizer.add_user('user1', '12345', '.', perm='elradfmwMT')
# Add user 2, username='user2', password='abcde', home directory='/home/user2', permissions to download and list directories
authorizer.add_user('user2', 'abcde', '/home/user2', perm='elr')
# Add user 3, username='user3', password='password', home directory='/var/ftp', permissions to upload and download
authorizer.add_user('user3', 'password', '/var/ftp', perm='adfm')
# Add anonymous user, home directory is current directory
authorizer.add_anonymous('.')
handler = TLS_FTPHandler
handler.certfile = '/path/to/ftpd.crt'  # Path to the SSL/TLS certificate file
handler.keyfile = '/path/to/ftpd.key'   # Path to the private key file
handler.authorizer = authorizer
handler.tls_control_required = True  # Optional: require the control channel to use TLS
handler.tls_data_required = True     # Optional: require the data channel to use TLS
server = FTPServer(('0.0.0.0', 21), handler)  # Start the server on port 21
server.serve_forever()  # Begin serving, run indefinitely
