import paramiko
import time

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
                timeout=15,
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
            shell.send('show ip interface brief\n')
            time.sleep(2)  # Wait for output
            output = ''
            while shell.recv_ready():
                output += shell.recv(1024).decode('utf-8', errors='ignore')
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
            commands = [
                f'configure terminal\n',
                f'interface {interface}\n',
                f'ip address {ip_addr} {mask}\n',
                'no shutdown\n',
                'end\n',
                'write memory\n'
            ]
            for cmd in commands:
                shell.send(cmd)
                time.sleep(2)
            shell.close()
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
            ip_cmd = f'no ip address {ip_addr}\n' if ip_addr else 'no ip address\n'
            commands = [
                f'configure terminal\n',
                f'interface {interface}\n',
                ip_cmd,
                'end\n',
                'write memory\n'
            ]
            for cmd in commands:
                shell.send(cmd)
                time.sleep(1)
            shell.close()
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
            commands = [
                f'configure terminal\n',
                f'interface {interface}\n',
                'no shutdown\n',
                'end\n',
                'write memory\n'
            ]
            for cmd in commands:
                shell.send(cmd)
                time.sleep(1)
            shell.close()
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
            commands = [
                f'configure terminal\n',
                f'interface {interface}\n',
                'shutdown\n',
                'end\n',
                'write memory\n'
            ]
            for cmd in commands:
                shell.send(cmd)
                time.sleep(1)
            shell.close()
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
            time.sleep(1)  # Wait for connection banner/motd
            # Clear buffer
            if shell.recv_ready():
                shell.recv(65535)

            # Send newline to trigger prompt
            shell.send('\n')
            time.sleep(1)
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
            time.sleep(1.5)
            output = ''
            while shell.recv_ready():
                output += shell.recv(1024).decode('utf-8', errors='ignore')
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
