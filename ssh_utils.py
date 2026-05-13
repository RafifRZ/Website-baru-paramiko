import paramiko
import time
import re

class SSHManager:
    def __init__(self, ip, username, password, port=22):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.client = None

    def connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self.ip,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            return True, "Connected"
        except Exception as e:
            return False, str(e)

    def execute_command(self, command):
        if not self.client:
            return None, "Not connected"
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            return stdout.read().decode('utf-8'), None
        except Exception as e:
            return None, str(e)

    def check_interfaces_shell(self):
        if not self.client:
            return None, "Not connected"
        try:
            conn = self.client.invoke_shell()
            conn.send("conf t\n")
            conn.send("do sh ip int brief\n")
            time.sleep(1)
            output = conn.recv(65535).decode('utf-8')
            return output, None
        except Exception as e:
            return None, str(e)

    def get_router_info(self):
        commands = {
            'version': 'show version | include uptime|Software',
            'interfaces': 'show ip interface brief'
        }
        info = {}
        for key, cmd in commands.items():
            output, err = self.execute_command(cmd)
            if err:
                info[key] = f"Error: {err}"
            else:
                info[key] = output
        return info

    def parse_interfaces(self, output):
        interfaces = []
        lines = output.strip().split('\n')
        for line in lines[2:]:  # Skip headers
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 4:
                interfaces.append({
                    'name': parts[0],
                    'ip': parts[1],
                    'status': parts[4],
                    'protocol': parts[5]
                })
        return interfaces

    def configure_interface(self, interface, action, ip=None, mask=None):
        commands = [
            'configure terminal',
            f'interface {interface}'
        ]
        
        if action == 'Add IP' and ip and mask:
            commands.append(f'ip address {ip} {mask}')
            commands.append('no shutdown')
        elif action == 'Remove IP':
            commands.append('no ip address')
        elif action == 'No Shutdown':
            commands.append('no shutdown')
        
        commands.extend(['end', 'write memory'])
        
        try:
            shell = self.client.invoke_shell()
            time.sleep(1)
            for cmd in commands:
                shell.send(cmd + '\n')
                time.sleep(0.5)
            
            output = shell.recv(65535).decode('utf-8')
            return True, output
        except Exception as e:
            return False, str(e)

    def close(self):
        if self.client:
            self.client.close()

def run_batch_config(device_info, config_lines):
    manager = SSHManager(device_info['ip'], device_info['username'], device_info['password'], device_info.get('port', 22))
    success, msg = manager.connect()
    if not success:
        return False, msg
    
    results = []
    try:
        shell = manager.client.invoke_shell()
        shell.send('terminal length 0\n') # Prevent pagination
        shell.send('configure terminal\n')
        time.sleep(1)
        
        for line in config_lines:
            if line.strip():
                shell.send(line.strip() + '\n')
                time.sleep(0.5)
                # Read output to ensure command was accepted
                if shell.recv_ready():
                    out = shell.recv(65535).decode('utf-8', errors='ignore')
                    results.append(f"CMD: {line.strip()} -> {out.strip()}")
        
        shell.send('end\n')
        shell.send('write memory\n')
        time.sleep(1)
        final_output = "\n".join(results)
        manager.close()
        return True, final_output
    except Exception as e:
        manager.close()
        return False, str(e)
