""" Build a Mitmproxy (mitmdump) command line string """
from __future__ import print_function
import socket
import sys
import os
import getopt


class InvalidPathException(Exception):
    """ Exception representing invalid path """


class MitmProxy():
    """ Build a mitmproxy server command line string """

    def __init__(self, config):
        self.config = config
        self.mitm_logs = os.getenv('mitm_verbose', 'false').lower() == 'true'
        if not self.config.get('har_path').endswith('.har'):
            raise InvalidPathException(
                "Config value 'har_path' is not a valid path to a HAR file")

    def log_output(self, output):
        '''
        Prints MITM logs from this library to output if mitm_verbose is set
        '''
        if self.mitm_logs:
            print(output)

    # pylint: disable=useless-else-on-loop
    def build_ignore_hosts(self, hostname=None):
        """ Build a mitmproxy ignore_hosts command string.
        Take a hostname and convert it to a list of IP addresses. Use this to
        build the mitmproxy ignore command line argument string """

        ignore_str = r""
        if not hostname:
            return ignore_str
        # Resolve hostname to a list of IP addresses
        self.log_output(
            'proxy_launcher: Resolving hostname: {}'.format(hostname))
        ip_addresses = socket.gethostbyname_ex(hostname)[-1]

        # Construct the ignore hosts string
        if ip_addresses:
            ignore_str += r"--ignore-hosts '"
            if len(ip_addresses) == 1:
                ignore_str += ip_addresses[0].replace(r'.', r'\.') + r":80"
            else:
                ip_addresses = list(set(ip_addresses))
                for ip_addr in ip_addresses[:-1]:
                    # All but the last IP address entry
                    ignore_str += ip_addr.replace(r'.', r'\.') + r":80|"
                else:
                    # Last IP address entry
                    ignore_str += (
                        ip_addresses[-1].replace(r'.', r'\.') + r":80")
            ignore_str += r"'"
        self.log_output('ignore-hosts value: {}'.format(ignore_str))
        return ignore_str

    def build_command(self):
        """ Build the mitmproxy (mitmdump) command line string """
        ignore_str = MitmProxy.build_ignore_hosts(
            self.config.get('ignore_hostname', ''))

        # Set mitmproxy mode
        mode_str = ''
        mode = self.config.get('mode', None)
        if mode:
            mode_str = "--mode {0} ".format(mode)
        # Enable or disable HTTP/2
        no_http2 = ''
        if 'url_rewrite' in self.config.get('script_path'):
            no_http2 = '--no-http2'
        cmd = ("ulimit -s {ulimit} & "
               "{python3_path} {mitm_dump_path} {no_http2} "
               "{mode_str}"
               "--listen-port={proxy_port} --showhost "
               "--set hardump='{har_path}' "
               "--set status_code='{status_code}' "
               "--set partial_url='{partial_url}' "
               "--set new_url='{new_url}' "
               "--set fixture_path='{fixture_path}' "
               "--set latency={latency} "
               "--set run_identifier='{run_identifier}' "
               "{ignore_str}").format(
                   ulimit=self.config.get('ulimit', ''),
                   python3_path=self.config.get('python3_path', ''),
                   mitm_dump_path=self.config.get(
                       'mitm_dump_path', '/usr/local/bin/mitmdump'),
                   no_http2=no_http2,
                   mode_str=mode_str,
                   proxy_port=self.config.get('proxy_port', ''),
                   har_path=self.config.get('har_path', ''),
                   status_code=self.config.get('status_code', ''),
                   partial_url=self.config.get('partial_url', ''),
                   new_url=self.config.get('new_url', ''),
                   fixture_path=self.config.get('fixture_path', ''),
                   latency=self.config.get('latency', ''),
                   run_identifier=self.config.get('run_identifier', ''),
                   ignore_str=ignore_str)
        if self.config.get('script_path'):
            cmd += " -s {}".format(self.config.get('script_path'))
        if self.config.get('tls_passthrough'):
            cmd += " -s {}".format(self.config.get('tls_passthrough'))
        cmd += " > /dev/null 2>&1 &"
        return cmd

    def run_command(self):
        """ Run the mitmproxy command """
        cmd = self.build_command()
        self.log_output('proxy_launcher: Running command: {}'.format(cmd))
        os.system(cmd)


if __name__ == '__main__':
    try:
        OPTIONS, _ = getopt.getopt(
            sys.argv[1:],
            '',
            ['ulimit=', 'python3_path=', 'har_dump_path=', 'har_path=',
             'proxy_port=', 'script_path=', 'mode=',
             'ignore_hostname=', 'mitm_dump_path=',
             'status_code=',
             'partial_url=', 'new_url=', 'fixture_path=', 'latency=',
             'run_identifier=', 'tls_passthrough='])
    except getopt.GetoptError as err:
        print('proxy_launcher: {}'.format(err))
        sys.exit(1)
    CONF = {}
    for opt, arg in OPTIONS:
        CONF[opt.strip('--')] = arg
    MitmProxy(CONF).run_command()
