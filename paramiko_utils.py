import paramiko
import time
import re

# IOS / IOS-XE error markers that may appear after sending a config command.
# When any of these are found in the captured output we treat the operation as
# failed instead of silently reporting success.
_IOS_ERROR_PATTERNS = (
    re.compile(r'%\s*Invalid input', re.IGNORECASE),
    re.compile(r'%\s*Incomplete command', re.IGNORECASE),
    re.compile(r'%\s*Ambiguous command', re.IGNORECASE),
    re.compile(r'%\s*Unknown command', re.IGNORECASE),
    re.compile(r'%\s*Bad mask', re.IGNORECASE),
    re.compile(r'%\s*Overlaps with', re.IGNORECASE),
    re.compile(r'%\s*Inconsistent address', re.IGNORECASE),
    re.compile(r'%\s*Cannot apply', re.IGNORECASE),
    re.compile(r'%\s*Not enough', re.IGNORECASE),
    re.compile(r'%\s*Configuration command rejected', re.IGNORECASE),
    re.compile(r'^Command rejected:', re.IGNORECASE | re.MULTILINE),
    re.compile(r'^ERROR:', re.IGNORECASE | re.MULTILINE),
)


def _detect_ios_error(output: str):
    """Return the matched error line when output contains an IOS error marker."""
    if not output:
        return None
    for pattern in _IOS_ERROR_PATTERNS:
        m = pattern.search(output)
        if not m:
            continue
        # Capture the full line containing the marker for a better message.
        start = output.rfind('\n', 0, m.start()) + 1
        end = output.find('\n', m.end())
        if end == -1:
            end = len(output)
        return output[start:end].strip()
    return None


def _run_config_commands(shell, commands, per_cmd_timeout=2.5):
    """Send a list of config commands sequentially, collecting CLI output.

    Each command is given up to ``per_cmd_timeout`` seconds to drain its
    response (we read until the channel goes idle for ~0.4s). The aggregated
    output is returned so callers can detect IOS error markers.
    """
    aggregated = ''
    for cmd in commands:
        if not cmd.endswith('\n'):
            cmd = cmd + '\n'
        shell.send(cmd)
        deadline = time.time() + per_cmd_timeout
        last_data_at = time.time()
        while time.time() < deadline:
            if shell.recv_ready():
                aggregated += shell.recv(4096).decode('utf-8', errors='ignore')
                last_data_at = time.time()
            elif time.time() - last_data_at > 0.4:
                break
            else:
                time.sleep(0.1)
    # Final drain for any trailing async output (e.g. "[OK]" after write mem).
    drain_deadline = time.time() + 1.5
    while time.time() < drain_deadline:
        if shell.recv_ready():
            aggregated += shell.recv(4096).decode('utf-8', errors='ignore')
        else:
            time.sleep(0.1)
    return aggregated


class ParamikoUtils:
    def __init__(self, ip, username, password, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.client = None

    def connect(self):
        """Establish SSH connection to the router.

        The original implementation used the default Paramiko behaviour which
        attempts to load SSH keys from the local environment. In many lab
        setups the router only accepts password authentication, causing the
        connection to fail quickly with an ``AuthenticationException`` that is
        not informative for the user. We now explicitly disable key lookup and
        increase the timeout to 20 seconds to accommodate slower devices.
        The method returns a tuple ``(success, message)`` where ``message``
        contains a human‑readable description of the failure.
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Disable automatic key loading; rely solely on password auth.
            self.client.connect(
                self.ip,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=8,
                banner_timeout=8,
                auth_timeout=8,
                look_for_keys=False,
                allow_agent=False,
            )
            return True, "Connected successfully"
        except paramiko.AuthenticationException:
            return False, "Authentication failed – check username/password"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        """Close the SSH connection."""
        if self.client:
            self.client.close()
            self.client = None

    def check_router_status(self):
        """Check if router is online by attempting SSH connection."""
        success, msg = self.connect()
        if success:
            self.disconnect()
        return success, msg

    def get_interfaces(self):
        """Retrieve list of interfaces from the router."""
        success, msg = self.connect()
        if not success:
            return []

        try:
            # Use invoke_shell for interactive commands
            shell = self.client.invoke_shell()
            shell.send('terminal length 0\n')
            time.sleep(0.2)
            shell.send('show ip interface brief\n')
            output = ''
            last_data_at = time.time()
            timeout_at = time.time() + 6
            while time.time() < timeout_at:
                if shell.recv_ready():
                    output += shell.recv(4096).decode('utf-8', errors='ignore')
                    last_data_at = time.time()
                elif time.time() - last_data_at > 0.6:
                    break
                else:
                    time.sleep(0.1)
            shell.close()

            # Parse interfaces from output
            interfaces = []
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('Interface') and not line.startswith('show') and not line.startswith('Router#'):
                    parts = line.split()
                    if len(parts) >= 6:
                        interface_name = parts[0]
                        ip_address = parts[1] if parts[1] != 'unassigned' else ''
                        status = parts[4] + '/' + parts[5]
                        interfaces.append({
                            'name': interface_name,
                            'ip': ip_address,
                            'status': status
                        })
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []
        finally:
            self.disconnect()

    def add_ip_address(self, interface, ip_raw):
        """Add IP address to an interface, handling CIDR notation."""
        success, msg = self.connect()
        if not success:
            return False, msg

        ip_addr = ip_raw
        mask = "255.255.255.0" # Default mask
        if '/' in ip_raw:
            try:
                ip_addr, prefix = ip_raw.split('/')
                prefix = int(prefix)
                # Common subnet masks for quick lookup
                masks = {
                    8: "255.0.0.0",
                    16: "255.255.0.0",
                    24: "255.255.255.0",
                    25: "255.255.255.128",
                    26: "255.255.255.192",
                    27: "255.255.255.224",
                    28: "255.255.255.240",
                    29: "255.255.255.248",
                    30: "255.255.255.252",
                    31: "255.255.255.254",
                    32: "255.255.255.255",
                }
                mask = masks.get(prefix, mask) # Use default if prefix not in map
            except ValueError: # Handle cases where prefix is not an integer
                pass # Use default mask
        try:
            shell = self.client.invoke_shell()
            time.sleep(0.3)
            if shell.recv_ready():
                shell.recv(65535)
            commands = [
                'terminal length 0',
                'configure terminal',
                f'interface {interface}',
                f'ip address {ip_addr} {mask}',
                'no shutdown',
                'end',
                'write memory',
            ]
            output = _run_config_commands(shell, commands)
            shell.close()
            err = _detect_ios_error(output)
            if err:
                return False, f"Device rejected command: {err}"
            return True, "IP address added successfully"
        except Exception as e:
            return False, str(e)
        finally:
            self.disconnect()

    def remove_ip_address(self, interface, ip_addr=None):
        """Remove IP address from an interface."""
        success, msg = self.connect()
        if not success:
            return False, msg

        try:
            shell = self.client.invoke_shell()
            time.sleep(0.3)
            if shell.recv_ready():
                shell.recv(65535)
            ip_cmd = f'no ip address {ip_addr}' if ip_addr else 'no ip address'
            commands = [
                'terminal length 0',
                'configure terminal',
                f'interface {interface}',
                ip_cmd,
                'end',
                'write memory',
            ]
            output = _run_config_commands(shell, commands)
            shell.close()
            err = _detect_ios_error(output)
            if err:
                return False, f"Device rejected command: {err}"
            return True, "IP address removed successfully"
        except Exception as e:
            return False, str(e)
        finally:
            self.disconnect()

    def no_shutdown_interface(self, interface):
        """Enable an interface (no shutdown)."""
        success, msg = self.connect()
        if not success:
            return False, msg

        try:
            shell = self.client.invoke_shell()
            time.sleep(0.3)
            if shell.recv_ready():
                shell.recv(65535)
            commands = [
                'terminal length 0',
                'configure terminal',
                f'interface {interface}',
                'no shutdown',
                'end',
                'write memory',
            ]
            output = _run_config_commands(shell, commands)
            shell.close()
            err = _detect_ios_error(output)
            if err:
                return False, f"Device rejected command: {err}"
            return True, "Interface enabled successfully"
        except Exception as e:
            return False, str(e)
        finally:
            self.disconnect()

    def shutdown_interface(self, interface):
        """Disable an interface (shutdown)."""
        success, msg = self.connect()
        if not success:
            return False, msg

        try:
            shell = self.client.invoke_shell()
            time.sleep(0.3)
            if shell.recv_ready():
                shell.recv(65535)
            commands = [
                'terminal length 0',
                'configure terminal',
                f'interface {interface}',
                'shutdown',
                'end',
                'write memory',
            ]
            output = _run_config_commands(shell, commands)
            shell.close()
            err = _detect_ios_error(output)
            if err:
                return False, f"Device rejected command: {err}"
            return True, "Interface disabled successfully"
        except Exception as e:
            return False, str(e)
        finally:
            self.disconnect()

    def get_hostname(self):
        """Retrieve the hostname from the router by parsing CLI prompt or running show running-config."""
        success, msg = self.connect()
        if not success:
            return None, msg

        try:
            # Method 1: Try reading the prompt from an interactive shell
            shell = self.client.invoke_shell()
            time.sleep(0.5)  # Wait for connection banner/motd
            # Clear buffer
            if shell.recv_ready():
                shell.recv(65535)

            # Send newline to trigger prompt
            shell.send('\n')
            time.sleep(0.4)
            output = ''
            while shell.recv_ready():
                output += shell.recv(1024).decode('utf-8', errors='ignore')

            import re
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if lines:
                last_line = lines[-1]
                # Match hostname before '#' or '>' (e.g. R1# or R1>)
                match = re.search(r'([A-Za-z0-9\-_]+)(?:\([^)]+\))?[#>]', last_line)
                if match:
                    shell.close()
                    return match.group(1), None

            # Fallback Method 2: Try running 'show running-config | include hostname'
            shell.send('show running-config | include hostname\n')
            output = ''
            last_data_at = time.time()
            timeout_at = time.time() + 5
            while time.time() < timeout_at:
                if shell.recv_ready():
                    output += shell.recv(1024).decode('utf-8', errors='ignore')
                    last_data_at = time.time()
                elif time.time() - last_data_at > 0.6:
                    break
                else:
                    time.sleep(0.1)
            shell.close()

            for line in output.splitlines():
                line = line.strip()
                if line.startswith('hostname '):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1], None

            return None, "Gagal mencocokkan prompt CLI maupun hostname konfigurasi."
        except Exception as e:
            return None, str(e)
        finally:
            self.disconnect()

# Standalone functions for easy calling
def check_router_status(ip, username, password, port=22):
    """Check if router is online."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.check_router_status()

def get_interfaces(ip, username, password, port=22):
    """Get list of interfaces."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.get_interfaces()

def add_ip_address(ip, username, password, port=22, interface='', ip_raw=''):
    """Add IP address to interface."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.add_ip_address(interface, ip_raw)

def remove_ip_address(ip, username, password, port=22, interface='', ip_addr=None):
    """Remove IP address from interface."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.remove_ip_address(interface, ip_addr)

def no_shutdown_interface(ip, username, password, port=22, interface=''):
    """Enable interface."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.no_shutdown_interface(interface)

def shutdown_interface(ip, username, password, port=22, interface=''):
    """Disable interface."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.shutdown_interface(interface)

def get_device_hostname(ip, username, password, port=22):
    """Retrieve the hostname from a router."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.get_hostname()

# New helper to run arbitrary CLI commands and specific show commands
import time

def run_cli_command(ip, username, password, port=22, command=''):
    """Execute arbitrary CLI command on router and return output."""
    utils = ParamikoUtils(ip, username, password, port)
    success, msg = utils.connect()
    if not success:
        return False, msg
    try:
        shell = utils.client.invoke_shell()
        shell.send('terminal length 0\n')
        time.sleep(0.5)
        shell.send('terminal width 512\n')
        time.sleep(0.2)
        shell.send(command + '\n')
        output = ''
        last_data_at = time.time()
        timeout_at = time.time() + 8
        while time.time() < timeout_at:
            if shell.recv_ready():
                output += shell.recv(4096).decode('utf-8', errors='ignore')
                last_data_at = time.time()
            elif time.time() - last_data_at > 1.0:
                break
            else:
                time.sleep(0.2)
        shell.close()
        return True, output
    except Exception as e:
        return False, str(e)
    finally:
        utils.disconnect()

def show_version(ip, username, password, port=22):
    """Run 'show version' on device."""
    return run_cli_command(ip, username, password, port, 'show version')

def show_running_config(ip, username, password, port=22):
    """Run 'show running-config' on device."""
    return run_cli_command(ip, username, password, port, 'show running-config')
