''' MITM Proxy client module '''
from __future__ import print_function
import json
import os
import time
import select
from distutils import dir_util

import paramiko
from selenium import webdriver

from mitm_proxy_helpers.proxy_logger import ProxyLogger


class InvalidPathException(Exception):
    ''' Continues if an invalid path is encountered in '''


class InvalidPlatformException(Exception):
    ''' Continues if an invalid platform is encountered '''


class Proxy(ProxyLogger):
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """
    The Proxy Handler can start and stop mitmproxy server locally or on a
     server and run the proxy server with different scripts (har logging,
    blacklisting)
    """
    ulimit_s = '1024'  # OS 'ulmit -s' value

    def __init__(self):
        self.mode = os.getenv('mitm_proxy_mode', 'transparent')
        self.har_log = None
        self.host = os.getenv('mitm_server_host', os.getenv('proxy_host'))
        self.ssh_port = os.getenv('mitm_server_ssh_port', None)
        self.ssh_user = os.getenv('mitm_server_ssh_user', None)
        self.remote = None not in [self.ssh_port, self.ssh_user]
        self.ssh_password = os.getenv('mitm_server_ssh_password', None)
        self.interface = os.getenv('mitm_server_interface', 'eth0')
        self.proxy_port = int(os.getenv('mitm_proxy_listen_port', '8081'))
        url = "http://" + self.host
        url_parts = url.split(":")
        self.proxy = url_parts[1][2:] + ":" + str(self.proxy_port)
        self.har_path = os.getenv(
            'mitm_har_path', '{0}/logs/har/dump.har').format(
            os.path.dirname(os.path.abspath(__file__)))
        self.python3_path = os.getenv(
            'mitm_python3_path', '/usr/local/bin/python3')
        self.path_to_scripts = "{0}/server_scripts".format(
            os.path.dirname(os.path.abspath(__file__)))
        if self.remote is True:
            self.path_to_scripts = "/home/{0}/mitm".format(self.ssh_user)
        self.fixtures_dir = os.getenv(
            'fixtures_dir',
            "{0}/fixtures".format(self.path_to_scripts))
        # Custom scripts
        self.har_dump_path = os.getenv('har_dump_script_path',
                                       "{0}/har_dump.py".format(
                                           self.path_to_scripts))
        self.blacklister_path = os.getenv('blacklister_script_path',
                                          "{0}/blacklister.py".format(
                                              self.path_to_scripts))
        self.empty_response_path = os.getenv('empty_response_script_path',
                                             "{0}/empty_response.py".format(
                                                 self.path_to_scripts))
        self.har_blacklist_path = os.getenv(
            'har_blacklist_script_path',
            "{0}/har_dump_and_blacklister.py".format(self.path_to_scripts))
        self.response_replace_path = os.getenv(
            'response_replace_script_path',
            "{0}/response_replace.py".format(self.path_to_scripts))
        self.request_latency_path = os.getenv('request_latency_script_path',
                                              "{0}/request_latency.py".format(
                                                  self.path_to_scripts))
        self.har_dump_no_replace_path = os.getenv(
            'har_dump_no_replace_path',
            "{0}/har_dump_no_replace.py".format(self.path_to_scripts))
        self.url_rewrite_path = os.getenv(
            'url_rewrite_path',
            "{0}/url_rewrite.py".format(self.path_to_scripts))
        self.tls_passthrough = os.getenv('tls_passthrough',
                                         "{0}/tls_passthrough.py".format(
                                             self.path_to_scripts))
        if not all([self.host, self.ssh_port, self.ssh_user,
                    self.ssh_password, self.har_path, self.python3_path,
                    self.har_dump_path, self.blacklister_path,
                    self.empty_response_path,
                    self.response_replace_path,
                    self.request_latency_path,
                    self.har_dump_no_replace_path,
                    self.url_rewrite_path]) and self.remote:
            raise Exception(
                'Not all remote MITM proxy env variables were provided.')
        if not all([self.host, self.har_path, self.python3_path,
                    self.har_dump_path, self.blacklister_path,
                    self.empty_response_path,
                    self.response_replace_path,
                    self.request_latency_path,
                    self.har_dump_no_replace_path,
                    self.url_rewrite_path]):
            raise Exception(
                'Not all local MITM proxy env variables were provided.')
        if not self.har_path.endswith('.har'):
            raise InvalidPathException(
                'har_path is not a valid path to a HAR file')
        if not self.remote:
            har_dir = os.path.dirname(self.har_path)
            dir_util.mkpath(har_dir)
        super(Proxy, self).__init__()

    def har(self):
        '''
        To retrieve the har file, we need to stop the proxy dump
        which writes out the har, fetch the har file, load it
        into the har_log attribute, then delete the har file
        once it is read and restart the proxy
        '''
        self.stop_proxy()
        self.har_log = self.fetch_har()
        self.delete_har()
        self.start_proxy()
        return self.har_log

    def port(self):
        ''' Returns the current proxy port '''
        return self.proxy_port

    def ssh_command(self, command, max_attempts=1):
        '''
        Execute arbitrary SSH commmand on a remote host, use with caution
        '''
        retry_wait = 2
        error_str = "SSHException. Could not SSH to {0} error: {1}"
        for i in range(max_attempts):
            self.log_output(
                "Trying to connect to {0} (Attempt {1}/{2})".format(
                    self.host, i + 1, max_attempts))
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    self.host, port=int(self.ssh_port), username=self.ssh_user,
                    password=self.ssh_password)
                self.log_output("Connected to {}".format(self.host))
                break
            except paramiko.ssh_exception.SSHException as err:
                self.log_output(error_str.format(self.host, err))
                time.sleep(retry_wait)
            except paramiko.ssh_exception.NoValidConnectionsError as err:
                self.log_output(error_str.format(self.host, err))
                time.sleep(retry_wait)
        else:
            self.log_output("Could not connect to {0} after {1} attempts. "
                            "Giving up".format(self.host, i + 1))
            return

        # Send the command (non-blocking)
        self.log_output("Running command: {}".format(command))
        _, stdout, _ = ssh.exec_command(command)

        # Wait for the command to terminate
        while not stdout.channel.exit_status_ready():
            # Only print data if there is data to read in the channel
            if stdout.channel.recv_ready():
                rldc, _, _ = select.select([stdout.channel], [], [], 0.0)
                if len(rldc) > 0:
                    # Print data from stdout
                    self.log_output(stdout.channel.recv(1024))

    def run_command(self, command, max_attempts=1):
        """ Executes a command locally or remotely """
        if self.remote is True:
            self.ssh_command(command, max_attempts)
        else:
            os.system(command)

    def wait_after_launch(self):
        """ Wait after proxy launch """
        wait = 20 if self.remote else 5
        self.log_output("Waiting for {0}s after proxy start".format(wait))
        time.sleep(wait)

    def start_proxy(self, script=None, config=None):
        # pylint: disable=too-many-branches,too-many-statements
        """ Start a proxy with optional script and script config """
        if not script:
            script = 'har_logging'

        # Validate script name
        valid_scripts = ['no_script', 'har_logging', 'blacklist',
                         'empty_response', 'har_and_blacklist',
                         'response_replace', 'request_latency',
                         'har_logging_no_replace', 'url_rewrite']
        if script not in valid_scripts:
            raise Exception("Script '{}' is not a valid mitmproxy "
                            "script.".format(script))

        script_path = None
        mandatory_fields = ['partial_url']
        if script == 'no_script':
            script_path = ''
        elif script == 'har_logging':
            script_path = self.har_dump_path
        elif script == 'blacklist':
            script_path = self.blacklister_path
            mandatory_fields.append('status_code')
        elif script == 'empty_response':
            script_path = self.empty_response_path
        elif script == 'har_and_blacklist':
            script_path = self.har_blacklist_path
            mandatory_fields.append('status_code')
        elif script == 'response_replace':
            script_path = self.response_replace_path
            mandatory_fields.append('fixture_file')
        elif script == 'request_latency':
            script_path = self.request_latency_path
            mandatory_fields.append('latency')
        elif script == 'har_logging_no_replace':
            script_path = self.har_dump_no_replace_path
            mandatory_fields.append('run_identifier')
        elif script == 'url_rewrite':
            script_path = self.url_rewrite_path
            mandatory_fields.append('new_url')
        else:
            raise Exception("Unknown proxy script provided: '{}'."
                            .format(script))

        self.log_output("Starting mitmdump proxy server with script: {}"
                        .format(script))

        # Validate config file
        config = config or {}
        if config:
            for field in mandatory_fields:
                try:
                    field = config[field]
                except KeyError:
                    error_msg = ("Field '{}' was not found in the mitmproxy "
                                 "config object for script '{}'".format(
                                     field, script))
                    raise KeyError(error_msg)

        # Build the proxy_launcher command line string
        ignore_hostname = os.getenv('proxy_hostname_ignore', '')
        fixture_file = config.get('fixture_file') or ''
        fixture_path = self.fixtures_dir + fixture_file
        command = ("python3 {0}/proxy_launcher.py "
                   "--ulimit={1} --python3_path={2} --har_dump_path={3} "
                   "--har_path={4} --proxy_port={5} --script_path={6}"
                   " --tls_passthrough={7} "
                   .format(
                       self.path_to_scripts, self.ulimit_s, self.python3_path,
                       self.har_dump_path, self.har_path, self.proxy_port,
                       script_path, self.tls_passthrough))
        if self.remote is True:
            command = "{command} --mode={mode}".format(
                command=command, mode=self.mode)
        command = ("{command} "
                   "--status_code={status_code} "
                   "--partial_url='{partial_url}' "
                   "--fixture_path='{fixture_path}' "
                   "--latency={latency} "
                   "--run_identifier='{run_identifier}' "
                   "--ignore_hostname={ignore_hostname} "
                   "--new_url={new_url} &"
                   .format(
                       command=command,
                       status_code=config.get('status_code', ''),
                       partial_url=config.get('partial_url', ''),
                       fixture_path=fixture_path,
                       latency=config.get('latency', ''),
                       run_identifier=config.get('run_identifier', ''),
                       ignore_hostname=ignore_hostname,
                       new_url=config.get('new_url', '')))

        self.bandwidth_throttle(clear=True)
        self.run_command(command)
        self.wait_after_launch()
        return self

    @staticmethod
    def pids():
        """ Returns pids of all mitm proxy instances running """
        stream = os.popen("ps aux | grep '[m]itm' | awk '{print $2}'")
        return stream.read()

    def stop_proxy(self):
        """ Stop the proxy server """
        self.log_output('Stopping MITM proxy server')
        command = ''
        if self.remote is True:
            command = "echo '{0}' | sudo killall {1}".format(
                self.ssh_password, os.path.basename(self.python3_path))
        else:
            mitm_pids = self.pids()
            if mitm_pids:
                command = "kill {0}".format(' '.join(mitm_pids.split("\n")))
        self.run_command(command)

    def set_ip_routing(self):
        """ Set IP routing on the host machine so that incoming http
        requests on port 80 get redirected to the proxy port
        Supports: Linux
        """
        os_type = os.getenv('server_os_type', None)
        if self.remote is not True and os_type not in ['Linux']:
            self.log_output('Cannot set iptables on non Linux hosts.')
            return

        self.log_output(
            'Setting IP forwarding and iptables rules on {} host'.format(
                os_type))

        command = (
            "echo '{0}' | sudo -S sysctl -w net.ipv4.ip_forward=1 && "
            "echo '{0}' | sudo -S sysctl -w net.ipv6.conf.all.forwarding=1 && "
            "echo '{0}' | sudo -S sysctl -w net.ipv4.conf.all.send_redirects=0"
            " && echo '{0}' | sudo -S iptables -t nat -A PREROUTING -i {1} -p "
            "tcp --match multiport --dports 80,443 -j REDIRECT --to-port {2} "
            "&& echo '{0}' | sudo -S ip6tables -t nat -A PREROUTING -i {1} "
            "-p tcp --match multiport --dports 80,443 -j REDIRECT "
            "--to-port {2}"
        )
        self.run_command(command.format(
            self.ssh_password, self.interface, self.proxy_port))

    def unset_ip_routing(self):
        """ Unset IP routing on the host machine so that incoming http
        requests on port 80 are NOT redirected to the proxy port
        Supports: Linux
        """
        os_type = os.getenv('server_os_type', None)
        if self.remote is not True and os_type not in ['Linux']:
            self.log_output('Cannot unset iptables on non Linux hosts.')
            return

        self.log_output(
            'Unsetting IP forwarding and iptables rules on {} host'.format(
                os_type))

        command = (
            "echo '{0}' | sudo -S iptables -F && "
            "echo '{0}' | sudo -S iptables -X && "
            "echo '{0}' | sudo -S iptables -t nat -F && "
            "echo '{0}' | sudo -S iptables -t nat -X && "
            "echo '{0}' | sudo -S iptables -t mangle -F && "
            "echo '{0}' | sudo -S iptables -t mangle -X && "
            "echo '{0}' | sudo -S iptables -P INPUT ACCEPT && "
            "echo '{0}' | sudo -S iptables -P FORWARD ACCEPT && "
            "echo '{0}' | sudo -S iptables -P OUTPUT ACCEPT && "
            "echo '{0}' | sudo -S sysctl -w net.ipv4.ip_forward=0 && "
            "echo '{0}' | sudo -S sysctl -w net.ipv6.conf.all.forwarding=0 && "
            "echo '{0}' | sudo -S sysctl -w net.ipv4.conf.all.send_redirects=1"
        )
        self.run_command(command.format(self.ssh_password))

    @staticmethod
    def initialise_har(_page_ref):
        """
        Initialises the proxy har.
        """

    def _fetch_remote_har(self):
        """ SFTP Get a HAR file from a remote server """
        # pylint: disable=no-member
        try:
            self.log_output('Retrieving remote HAR file')
            transport = paramiko.Transport((self.host, int(self.ssh_port)))
            transport.connect(
                hostkey=None,
                username=self.ssh_user,
                password=self.ssh_password
            )
            sftp = paramiko.SFTPClient.from_transport(transport)
            with sftp.open(self.har_path, "r") as har_file:
                self.har_log = har_file.read()

            # Disconnect from the host
            self.log_output('Retrieved HAR file, closing SFTP connection')
            sftp.close()
            return self.har_log
        except paramiko.ssh_exception.SSHException as err:
            self.log_output(
                "Could not SFTP to {0} error: {1}".format(self.host, err))
            return None
        except IOError as err:
            self.log_output("IOError: {}".format(err))
            return None

    def fetch_har(self):
        """ Tries to get the HAR file """
        har = ''
        retries = 30
        time.sleep(5)
        if self.remote is True:
            har = self._fetch_remote_har()
        else:
            self.log_output('Retrieving Local HAR file')
            for _ in range(retries):
                if os.path.exists(self.har_path):
                    break
                time.sleep(1)
            har = open(self.har_path, 'r').read()
        return json.loads(har)

    def delete_har(self):
        """ SSH Delete a HAR file """
        msg = 'Deleting HAR file'
        if self.remote is True:
            msg = 'Deleting remote HAR file'
        self.log_output(msg)
        command = "rm -rf {0}".format(self.har_path)
        self.run_command(command, 10)

    def selenium_proxy(self):
        """
        Returns a Selenium WebDriver Proxy class with details of the HTTP Proxy
        """
        return webdriver.Proxy({
            "httpProxy": self.proxy(),
            "sslProxy": self.proxy(),
        })

    def bandwidth_throttle(self, up_kb=80000, down_kb=80000, clear=False):
        """ Starts the bandwidth throttle with provided up and down limits in
        KB/s.
        Supports: Linux
        :param clear (Boolean) - if True clear any existing bandwidth limits
        :param up_kb (Integer) - upload speed bandwidth limit in KB/s
        :param down_kb (Integer) - download speed bandwidth limit in KB/s
        returns: True on success
        """
        if not self.remote:
            error_msg = 'Cannot throttle in non remote mode'
            self.log_output(error_msg)
            return False, error_msg
        if os.getenv('server_os_type', 'Linux') not in ['Linux']:
            error_msg = 'Cannot throttle bandwidth on non Linux hosts.'
            self.log_output(error_msg)
            return False, error_msg

        clear_cmd = "echo '{0}' | sudo -S /usr/bin/wondershaper -a {1} -c"
        clear_cmd = clear_cmd.format(self.ssh_password, self.interface)
        if clear:
            self.ssh_command(clear_cmd, max_attempts=1)
            self.log_output('Wondershaper: limits cleared.\n')
        else:
            start_cmd = (
                "echo '{0}' | sudo -S /usr/bin/wondershaper -a {1} "
                "-u {2} -d {3}"
            )
            start_cmd = start_cmd.format(
                self.ssh_password, self.interface, up_kb, down_kb)
            # Always clear any pre-existing throttle state first
            self.ssh_command(clear_cmd, max_attempts=1)
            self.ssh_command(start_cmd, max_attempts=1)
            self.log_output('Wondershaper: limits cleared then set.\n')
        return True, ''
