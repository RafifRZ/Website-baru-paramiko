import paramiko
import time


def connect_terminal_shell(ip, username, password, port=22, timeout=10):
    """Open an SSH shell session for terminal communication."""
    client = None
    shell = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=ip,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell()
        time.sleep(0.5)
        shell.send('terminal length 0\n')
        time.sleep(0.5)
        return True, 'Connected', client, shell
    except Exception as e:
        if shell:
            try:
                shell.close()
            except Exception:
                pass
        if client:
            try:
                client.close()
            except Exception:
                pass
        return False, str(e), None, None


def read_shell_output(shell, wait=0.1):
    """Read available output from the SSH shell."""
    if not shell:
        return ''
    output = ''
    time.sleep(wait)
    while shell.recv_ready():
        try:
            output += shell.recv(4096).decode('utf-8', errors='ignore')
        except Exception:
            break
    return output


def send_shell_command(shell, command):
    """Send a command to the SSH shell."""
    if not shell:
        return False, 'Shell is not initialized'
    try:
        shell.send(command)
        return True, None
    except Exception as e:
        return False, str(e)


def close_terminal_shell(client, shell):
    """Close SSH shell and client connections."""
    if shell:
        try:
            shell.close()
        except Exception:
            pass
    if client:
        try:
            client.close()
        except Exception:
            pass
