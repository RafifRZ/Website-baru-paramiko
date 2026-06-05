import os
import threading
import re
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Device, Log
from paramiko_utils import check_router_status, get_interfaces, add_ip_address, remove_ip_address, no_shutdown_interface, shutdown_interface, get_device_hostname, show_version, show_running_config, run_cli_command
from ssh_utils import run_batch_config
from terminal_utils import connect_terminal_shell, read_shell_output, send_shell_command, close_terminal_shell
import pandas as pd
import io
from datetime import datetime
import pytz
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

def get_user_devices():
    if current_user.username == 'admin':
        return Device.query.all()
    allowed_ids = current_user.get_allowed_device_ids()
    if not allowed_ids:
        return []
    return Device.query.filter(Device.id.in_(allowed_ids)).all()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
active_shells = {}
active_shells_lock = threading.Lock()


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(action, level='INFO', device_id=None):
    user_id = current_user.id if current_user.is_authenticated else None
    jakarta_tz = pytz.timezone('Asia/Jakarta')
    timestamp = datetime.now(jakarta_tz)
    new_log = Log(action=action, level=level, device_id=device_id, user_id=user_id, timestamp=timestamp)
    db.session.add(new_log)
    db.session.commit()


def parse_version_summary(version_output):
    """Extract a small, readable summary from `show version` output."""
    summary = {
        'ios_version': None,
        'uptime': None,
        'system_image': None,
        'serial_number': None,
    }

    if not version_output:
        return summary

    for line in version_output.splitlines():
        clean = line.strip()
        if not clean:
            continue
        if summary['uptime'] is None:
            uptime_match = re.search(r'(.+?) uptime is (.+)', clean, re.IGNORECASE)
            if uptime_match:
                summary['uptime'] = uptime_match.group(2).strip()
        if summary['ios_version'] is None and 'Cisco IOS Software' in clean:
            version_match = re.search(r'Version ([^,\s]+)', clean, re.IGNORECASE)
            if version_match:
                summary['ios_version'] = version_match.group(1)
        if summary['system_image'] is None and 'System image file is' in clean:
            image_match = re.search(r'"([^"]+)"', clean)
            if image_match:
                summary['system_image'] = image_match.group(1)
        if summary['serial_number'] is None and 'Processor board ID' in clean:
            serial_match = re.search(r'Processor board ID\s+(.+)', clean, re.IGNORECASE)
            if serial_match:
                summary['serial_number'] = serial_match.group(1).strip()

    return summary


def ensure_device_port_column():
    if db.engine.dialect.name == 'sqlite':
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(device)"))
            columns = [row[1] for row in result]
            if 'port' not in columns:
                conn.execute(text("ALTER TABLE device ADD COLUMN port INTEGER DEFAULT 22"))


def ensure_user_allowed_devices_column():
    if db.engine.dialect.name == 'sqlite':
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(user)"))
            columns = [row[1] for row in result]
            if 'allowed_devices' not in columns:
                conn.execute(text("ALTER TABLE user ADD COLUMN allowed_devices TEXT DEFAULT ''"))


# Ensure database schema is prepared before handling requests.
# We keep a simple flag to run the preparation only once.
schema_prepared = False

@app.before_request
def prepare_db_schema():
    """Check and update the DB schema on the first request.

    The original implementation used a global flag with ``before_request``.
    The refactor mistakenly switched to ``before_first_request`` which is not
    available in the Flask version used. Restoring the ``before_request``
    approach maintains compatibility while still avoiding repeated work.
    """
    global schema_prepared
    if schema_prepared:
        return
    try:
        ensure_device_port_column()
        ensure_user_allowed_devices_column()
    except OperationalError:
        db.create_all()
        ensure_device_port_column()
        ensure_user_allowed_devices_column()
    schema_prepared = True

# --- Routes ---

@app.route('/')
@login_required
def dashboard():
    devices = get_user_devices()
    stats = {
        'total': len(devices),
        'online': sum(1 for d in devices if d.status == 'Online'),
    }
    return render_template('dashboard.html', devices=devices, stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to main dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route('/devices/verify', methods=['POST'])
@login_required
def verify_device():
    ip = request.form.get('ip')
    username = request.form.get('username')
    password = request.form.get('password')
    port = request.form.get('port') or 22
    try:
        port = int(port)
    except ValueError:
        port = 22

    success, msg = check_router_status(ip, username, password, port)
    return jsonify({'success': success, 'message': msg})

@app.route('/devices/add', methods=['POST'])
@login_required
def add_device():
    hostname = request.form.get('hostname', '').strip()
    ip = request.form.get('ip', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password')
    port = request.form.get('port') or 22
    try:
        port = int(port)
    except ValueError:
        port = 22

    # Check duplicate IP/Hostname in the database first
    if hostname:
        existing = Device.query.filter((Device.ip_address == ip) | (Device.hostname == hostname)).first()
        if existing:
            flash('Router dengan IP atau hostname ini sudah terdaftar.', 'error')
            return redirect(url_for('dashboard'))
    else:
        existing = Device.query.filter(Device.ip_address == ip).first()
        if existing:
            flash('Router dengan IP ini sudah terdaftar.', 'error')
            return redirect(url_for('dashboard'))

    # If hostname is not provided, fetch it from device
    if not hostname:
        resolved_hostname, msg = get_device_hostname(ip, username, password, port)
        if not resolved_hostname:
            flash(f'Router tidak dapat terhubung atau gagal mengambil hostname otomatis: {msg}', 'error')
            return redirect(url_for('dashboard'))
        
        # Verify the resolved hostname is not a duplicate in DB
        existing_hostname = Device.query.filter_by(hostname=resolved_hostname).first()
        if existing_hostname:
            flash(f'Router dengan hostname "{resolved_hostname}" sudah terdaftar.', 'error')
            return redirect(url_for('dashboard'))
            
        hostname = resolved_hostname
    else:
        # Otherwise, just verify the status using the provided credentials
        success, msg = check_router_status(ip, username, password, port)
        if not success:
            flash(f'Router tidak dapat terhubung. Pastikan IP, port, dan kredensial benar: {msg}', 'error')
            return redirect(url_for('dashboard'))

    new_device = Device(hostname=hostname, ip_address=ip, username=username, password=password, port=port, status='Online')
    db.session.add(new_device)
    db.session.commit()
    log_action(f"Added device {hostname} ({ip}:{port})")
    flash('Device registered successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/refresh-status')
@login_required
def refresh_status():
    import concurrent.futures
    devices = get_user_devices()
    
    def check_device(device):
        success, _ = check_router_status(device.ip_address, device.username, device.password, device.port or 22)
        return device.id, 'Online' if success else 'Offline'

    # Check device statuses in parallel to speed up background process
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_device, devices))

    # Update states in the database
    status_map = dict(results)
    for device in devices:
        device.status = status_map.get(device.id, 'Offline')
    db.session.commit()
    
    # Check if AJAX is requested
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('ajax') == '1':
        updated_devices = [{
            'id': d.id,
            'status': d.status
        } for d in devices]
        return jsonify({
            'success': True,
            'devices': updated_devices,
            'stats': {
                'total': len(devices),
                'online': sum(1 for d in devices if d.status == 'Online'),
                'offline': sum(1 for d in devices if d.status != 'Online')
            }
        })

    flash('Status perangkat berhasil diperbarui.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/device/delete/<int:device_id>', methods=['POST'])
@login_required
def delete_device(device_id):
    if current_user.username != 'admin' and device_id not in current_user.get_allowed_device_ids():
        flash('Unauthorized to delete this device', 'error')
        return redirect(url_for('dashboard'))
    device = Device.query.get_or_404(device_id)
    hostname = device.hostname
    db.session.delete(device)
    db.session.commit()
    log_action(f"Deleted device {hostname}")
    flash(f'Device {hostname} removed', 'success')
    return redirect(url_for('dashboard'))

@app.route('/device/update/<int:device_id>', methods=['POST'])
@login_required
def update_device(device_id):
    if current_user.username != 'admin' and device_id not in current_user.get_allowed_device_ids():
        flash('Unauthorized to update this device', 'error')
        return redirect(url_for('dashboard'))
    device = Device.query.get_or_404(device_id)
    old_hostname = device.hostname
    new_hostname = request.form.get('hostname')
    new_ip = request.form.get('ip')
    new_username = request.form.get('username')
    new_port = int(request.form.get('port') or 22)
    new_password = request.form.get('password')
    password_to_verify = new_password if new_password else device.password

    duplicate = Device.query.filter(
        ((Device.ip_address == new_ip) | (Device.hostname == new_hostname)) & (Device.id != device_id)
    ).first()
    if duplicate:
        flash('Router dengan IP atau hostname ini sudah terdaftar pada perangkat lain.', 'error')
        return redirect(url_for('device_detail', device_id=device_id))

    success, msg = check_router_status(new_ip, new_username, password_to_verify, new_port)
    if not success:
        flash('Verifikasi gagal: pastikan IP, port, dan kredensial benar sebelum menyimpan perubahan.', 'error')
        return redirect(url_for('device_detail', device_id=device_id))

    device.hostname = new_hostname
    device.ip_address = new_ip
    device.username = new_username
    device.port = new_port
    if new_password:
        device.password = new_password
    device.status = 'Online'
    db.session.commit()
    log_action(f"Updated device info for {old_hostname} -> {device.hostname}")
    flash(f'Device {device.hostname} updated', 'success')
    return redirect(url_for('device_detail', device_id=device.id))

@app.route('/device/<int:device_id>')
@login_required
def device_detail(device_id):
    if current_user.username != 'admin' and device_id not in current_user.get_allowed_device_ids():
        flash('Unauthorized to view this device', 'error')
        return redirect(url_for('dashboard'))
    device = Device.query.get_or_404(device_id)
    success, msg = check_router_status(device.ip_address, device.username, device.password, device.port or 22)

    if not success:
        if device.status != 'Offline':
            device.status = 'Offline'
            db.session.commit()
        device_info = {
            'hostname': device.hostname,
            'ip_address': device.ip_address,
            'port': device.port or 22,
            'username': device.username,
            'device_type': device.device_type or 'cisco_ios',
            'status': device.status,
            'created_at': device.created_at,
        }
        return render_template('device_detail.html', device=device, error=msg, interfaces=[], interface_count=0, device_info=device_info, version_info={})

    if device.status != 'Online':
        device.status = 'Online'
        db.session.commit()

    interfaces = get_interfaces(device.ip_address, device.username, device.password, device.port or 22)
    interface_count = len(interfaces)
    version_success, version_output = show_version(device.ip_address, device.username, device.password, device.port or 22)
    version_info = parse_version_summary(version_output if version_success else '')

    device_info = {
        'hostname': device.hostname,
        'ip_address': device.ip_address,
        'port': device.port or 22,
        'username': device.username,
        'device_type': device.device_type or 'cisco_ios',
        'status': device.status,
        'created_at': device.created_at,
    }

    return render_template(
        'device_detail.html',
        device=device,
        interfaces=interfaces,
        interface_count=interface_count,
        device_info=device_info,
        version_info=version_info,
    )

@app.route('/device/<int:device_id>/command', methods=['POST'])
@login_required
def device_command(device_id):
    if current_user.username != 'admin' and device_id not in current_user.get_allowed_device_ids():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    device = Device.query.get_or_404(device_id)
    payload = request.get_json(silent=True) or {}
    command = (payload.get('command') or '').strip()

    if command == 'show ip interface brief':
        success, output = run_cli_command(device.ip_address, device.username, device.password, device.port or 22, 'show ip interface brief')
    elif command == 'show version':
        success, output = show_version(device.ip_address, device.username, device.password, device.port or 22)
    elif command == 'show running-config':
        success, output = show_running_config(device.ip_address, device.username, device.password, device.port or 22)
    else:
        return jsonify({'success': False, 'message': 'Command not allowed'}), 400

    if not success:
        return jsonify({'success': False, 'message': output}), 200

    return jsonify({'success': True, 'output': output})

@app.route('/device/<int:device_id>/configure_ip', methods=['POST'])
@login_required
def configure_ip(device_id):
    if current_user.username != 'admin' and device_id not in current_user.get_allowed_device_ids():
        flash('Unauthorized to configure this device', 'error')
        return redirect(url_for('dashboard'))
    device = Device.query.get_or_404(device_id)
    interface = request.form.get('interface')
    action = request.form.get('action')
    ip_raw = request.form.get('ip')

    if action == 'Add IP':
        if not ip_raw:
            flash('Masukkan IP address sebelum menambahkan IP.', 'error')
            return redirect(url_for('device_detail', device_id=device_id))

        success, msg = add_ip_address(device.ip_address, device.username, device.password, device.port or 22, interface, ip_raw)
    elif action == 'Remove IP':
        success, msg = remove_ip_address(device.ip_address, device.username, device.password, device.port or 22, interface, ip_raw)
    elif action == 'No Shutdown':
        success, msg = no_shutdown_interface(device.ip_address, device.username, device.password, device.port or 22, interface)
    elif action == 'Shutdown':
        success, msg = shutdown_interface(device.ip_address, device.username, device.password, device.port or 22, interface)
    else:
        flash('Action tidak valid.', 'error')
        return redirect(url_for('device_detail', device_id=device_id))
    
    if success:
        log_action(f"Performed {action} on {interface} ({ip_raw or ''}) for {device.hostname}", device_id=device.id)
        flash(f'Successfully performed {action} on {interface}', 'success')
    else:
        log_action(f"Failed to configure {interface} on {device.hostname}: {msg}", level='ERROR', device_id=device.id)
        flash(f'Failed to configure {interface}: {msg}', 'error')
    
    return redirect(url_for('device_detail', device_id=device_id))

@app.route('/batch', methods=['GET', 'POST'])
@login_required
def batch_config():
    """Execute a batch of commands on selected devices.

    The endpoint now queries the selected devices in a single database call and
    builds the command list more concisely, reducing overhead.
    """
    if request.method == 'POST':
        # Collect selected device IDs and command sources
        device_ids = request.form.getlist('devices')
        raw_commands = request.form.get('raw_commands')
        csv_file = request.files.get('csv_file')

        # Build command list
        commands: list[str] = []
        if csv_file:
            try:
                df = pd.read_csv(io.StringIO(csv_file.read().decode('utf-8')))
                # Prefer a column named 'command', otherwise take the first column
                commands = df['command'].tolist() if 'command' in df.columns else df.iloc[:, 0].tolist()
            except Exception as e:
                flash(f"Error reading CSV: {e}", 'error')
                return redirect(url_for('batch_config'))

        if raw_commands:
            commands.extend([c.strip() for c in raw_commands.split('\n') if c.strip()])

        # Default to all user devices when none are selected
        if not device_ids:
            device_ids = [str(d.id) for d in get_user_devices()]

        # Convert IDs to integers for a bulk query
        device_ids_int = [int(i) for i in device_ids]
        devices = Device.query.filter(Device.id.in_(device_ids_int)).all()

        results = []
        for device in devices:
            success, output = run_batch_config(
                {
                    'ip': device.ip_address,
                    'username': device.username,
                    'password': device.password,
                    'port': device.port or 22,
                },
                commands,
            )
            results.append({'hostname': device.hostname, 'success': success, 'output': output})
            log_action(
                f"Batch config on {device.hostname}: {'Success' if success else 'Failed'}",
                level='INFO' if success else 'ERROR',
                device_id=device.id,
            )

        return render_template('batch_results.html', results=results)

    # GET request – render the configuration page with all devices
    devices = get_user_devices()
    return render_template('batch_config.html', devices=devices)

# --- User Management ---

@app.route('/users')
@login_required
def users():
    if current_user.username == 'admin':
        users_list = User.query.all()
    else:
        users_list = User.query.filter_by(id=current_user.id).all()
    devices = Device.query.all()
    return render_template('users.html', users=users_list, devices=devices)

@app.route('/users/add', methods=['POST'])
@login_required
def add_user():
    if current_user.username != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('users'))
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Get selected device IDs (checkboxes named 'devices')
    selected_devices = request.form.getlist('devices')
    allowed_devices_str = ','.join([d for d in selected_devices if d])
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
    else:
        new_user = User(username=username, password=generate_password_hash(password), allowed_devices=allowed_devices_str)
        db.session.add(new_user)
        db.session.commit()
        log_action(f"Created new system user: {username}")
        flash('User created successfully', 'success')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.username != 'admin' and current_user.id != user_id:
        flash('Access denied', 'error')
        return redirect(url_for('users'))
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Cannot delete default admin', 'error')
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_action(f"Deleted system user: {username}")
        flash('User removed', 'success')
    return redirect(url_for('users'))


@app.route('/users/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if current_user.username != 'admin' and current_user.id != user_id:
        flash('Access denied', 'error')
        return redirect(url_for('users'))
    user = User.query.get_or_404(user_id)
    # Only allow changing password and allowed devices (not username)
    new_password = request.form.get('password')
    selected_devices = request.form.getlist('devices')
    user.allowed_devices = ','.join([d for d in selected_devices if d])
    if new_password:
        user.password = generate_password_hash(new_password)
    db.session.commit()
    log_action(f"Updated system user: {user.username}")
    flash('User updated successfully', 'success')
    return redirect(url_for('users'))

@app.route('/interfaces')
@login_required
def all_interfaces():
    import concurrent.futures
    devices = get_user_devices()
    
    def fetch_device_data(device):
        device_id = device.id
        hostname = device.hostname
        ip_address = device.ip_address
        username = device.username
        password = device.password
        port = device.port or 22
        status = device.status
        
        interfaces = []
        if status == 'Online':
            interfaces = get_interfaces(ip_address, username, password, port)
        return {
            'device_id': device_id,
            'hostname': hostname,
            'ip_address': ip_address,
            'status': status,
            'interfaces': interfaces,
            'online': status == 'Online'
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_device_data, d): d for d in devices}
        results_map = {}
        for future in concurrent.futures.as_completed(futures):
            d = futures[future]
            try:
                data = future.result()
                results_map[d.id] = data
            except Exception as e:
                results_map[d.id] = {
                    'device_id': d.id,
                    'hostname': d.hostname,
                    'ip_address': d.ip_address,
                    'status': d.status,
                    'interfaces': [],
                    'online': False,
                    'error': str(e)
                }

    devices_interfaces = [results_map[d.id] for d in devices if d.id in results_map]
    return render_template('interfaces.html', devices_interfaces=devices_interfaces)

@app.route('/logs')
@login_required
def system_logs():
    logs = Log.query.order_by(Log.timestamp.desc()).limit(100).all()
    return render_template('logs.html', logs=logs)   

@app.route('/terminal')
@login_required
def terminal():
    devices = get_user_devices()
    selected_device_id = request.args.get('device_id', '')
    return render_template('terminal.html', devices=devices, selected_device_id=selected_device_id)

# --- Terminal (SocketIO) ---

@app.route('/terminal/active-session-status')
@login_required
def active_session_status():
    user_id = current_user.id
    with active_shells_lock:
        session = active_shells.get(user_id)
        if session and session['shell'] and not session['shell'].closed:
            return jsonify({
                'active': True,
                'device_id': session['device_id']
            })
    return jsonify({'active': False})

@socketio.on('connect_terminal')
def handle_terminal_connect(data):
    device_id = data.get('device_id')
    if device_id is not None:
        device_id = str(device_id)
    sid = request.sid

    if not current_user.is_authenticated:
        emit('terminal_output', {'data': 'Authentication required\n'})
        return

    user_id = current_user.id
    device = Device.query.get(device_id)

    if not device:
        emit('terminal_output', {'data': 'Device not found\n'})
        return

    with active_shells_lock:
        # Check if there is an existing session for this user
        session = active_shells.get(user_id)
        if session:
            # If it's the same device and shell is active
            if str(session['device_id']) == device_id and session['shell'] and not session['shell'].closed:
                # Add new sid to the set of tracking sids
                session['sids'].add(sid)
                
                # Emit connection confirmation and the accumulated output buffer
                emit('terminal_output', {'data': '\n[Reconnected to existing session]\n\n'}, room=sid)
                emit('terminal_output', {'data': session['output_buffer']}, room=sid)
                return
            else:
                # Close the old session
                close_terminal_shell(session['client'], session['shell'])
                if user_id in active_shells:
                    del active_shells[user_id]

    success, msg, client, shell = connect_terminal_shell(
        device.ip_address,
        device.username,
        device.password,
        device.port or 22
    )

    if not success:
        emit('terminal_output', {'data': f'Connection failed: {msg}\n'})
        return

    with active_shells_lock:
        active_shells[user_id] = {
            'shell': shell,
            'client': client,
            'device_id': device_id,
            'output_buffer': '',
            'sids': {sid}
        }

    initial_output = read_shell_output(shell, 0.5)
    if initial_output:
        with active_shells_lock:
            if user_id in active_shells:
                active_shells[user_id]['output_buffer'] += initial_output
        emit('terminal_output', {'data': initial_output}, room=sid)

    def background_thread(u_id):
        while True:
            with active_shells_lock:
                if u_id not in active_shells:
                    break
                session_info = active_shells[u_id]
                sh = session_info['shell']
                sids = list(session_info['sids'])
            
            try:
                if sh.recv_ready():
                    output = sh.recv(4096).decode('utf-8', errors='ignore')
                    if output:
                        with active_shells_lock:
                            if u_id in active_shells:
                                active_shells[u_id]['output_buffer'] += output
                        # Emit output to all connected SIDs of this user
                        for s in sids:
                            socketio.emit('terminal_output', {'data': output}, room=s)
            except Exception:
                break
            socketio.sleep(0.1)

    socketio.start_background_task(background_thread, user_id)

@socketio.on('terminal_input')
def handle_terminal_input(data):
    sid = request.sid
    input_text = data.get('data')
    if not current_user.is_authenticated:
        return
    user_id = current_user.id
    
    with active_shells_lock:
        session = active_shells.get(user_id)
        if session and sid in session['sids'] and input_text:
            shell = session['shell']
            if not input_text.endswith('\n'):
                input_text += '\n'
            success, err = send_shell_command(shell, input_text)
            if not success:
                emit('terminal_output', {'data': f'Error sending command: {err}\n'}, room=sid)

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if not current_user.is_authenticated:
        return
    user_id = current_user.id
    
    with active_shells_lock:
        session = active_shells.get(user_id)
        if session and sid in session['sids']:
            session['sids'].remove(sid)
            # Sesi dipertahankan tanpa batas waktu (indefinitely) sampai pengguna
            # secara eksplisit mengklik tombol Disconnect pada antarmuka terminal.

# Handle explicit disconnect request from client UI
@socketio.on('disconnect_terminal')
def handle_disconnect_terminal():
    if not current_user.is_authenticated:
        return
    user_id = current_user.id
    with active_shells_lock:
        session = active_shells.get(user_id)
        if session:
            close_terminal_shell(session['client'], session['shell'])
            if user_id in active_shells:
                del active_shells[user_id]

# --- Init Database ---

@app.cli.command("init-db")
def init_db():
    db.create_all()
    if db.engine.dialect.name == 'sqlite':
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(device)"))
            columns = [row[1] for row in result]
            if 'port' not in columns:
                conn.execute(text("ALTER TABLE device ADD COLUMN port INTEGER DEFAULT 22"))

    # Create default admin
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password=generate_password_hash('admin123'))
        db.session.add(admin)
        db.session.commit()
    print("Database initialized.")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
