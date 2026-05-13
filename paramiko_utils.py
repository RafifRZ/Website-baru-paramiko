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
        """Establish SSH connection to the router."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, port=self.port, username=self.username, password=self.password, timeout=10)
            return True, "Connected successfully"
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

    def add_ip_address(self, interface, ip_addr, mask):
        """Add IP address to an interface."""
        success, msg = self.connect()
        if not success:
            return False, msg

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
                time.sleep(1)
            shell.close()
            return True, "IP address added successfully"
        except Exception as e:
            return False, str(e)
        finally:
            self.disconnect()

    def remove_ip_address(self, interface, ip_addr):
        """Remove IP address from an interface."""
        success, msg = self.connect()
        if not success:
            return False, msg

        try:
            shell = self.client.invoke_shell()
            commands = [
                f'configure terminal\n',
                f'interface {interface}\n',
                f'no ip address {ip_addr}\n',
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

# Standalone functions for easy calling
def check_router_status(ip, username, password, port=22):
    """Check if router is online."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.check_router_status()

def get_interfaces(ip, username, password, port=22):
    """Get list of interfaces."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.get_interfaces()

def add_ip_address(ip, username, password, port=22, interface='', ip_addr='', mask=''):
    """Add IP address to interface."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.add_ip_address(interface, ip_addr, mask)

def remove_ip_address(ip, username, password, port=22, interface='', ip_addr=''):
    """Remove IP address from interface."""
    utils = ParamikoUtils(ip, username, password, port)
    return utils.remove_ip_address(interface, ip_addr)