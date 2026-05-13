import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Device, Log
from ssh_utils import SSHManager, run_batch_config
import pandas as pd
import io
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

schema_prepared = False

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_action(action, level='INFO', device_id=None):
    user_id = current_user.id if current_user.is_authenticated else None
    new_log = Log(action=action, level=level, device_id=device_id, user_id=user_id)
    db.session.add(new_log)
    db.session.commit()


def ensure_device_port_column():
    if db.engine.dialect.name == 'sqlite':
        with db.engine.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(device)"))
            columns = [row[1] for row in result]
            if 'port' not in columns:
                conn.execute(text("ALTER TABLE device ADD COLUMN port INTEGER DEFAULT 22"))


@app.before_request
def prepare_db_schema():
    global schema_prepared
    if schema_prepared:
        return

    try:
        ensure_device_port_column()
    except OperationalError:
        # If the device table is missing or schema is invalid, create all tables and retry.
        db.create_all()
        ensure_device_port_column()
    schema_prepared = True

# --- Routes ---

@app.route('/')
@login_required
def dashboard():
    devices = Device.query.all()
    stats = {
        'total': len(devices),
        'online': Device.query.filter_by(status='Online').count(),
        'cpu': '12.4%', # Example
        'uptime': '4d 12h'
    }
    return render_template('dashboard.html', devices=devices, stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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

    ssh = SSHManager(ip, username, password, port)
    success, msg = ssh.connect()
    ssh.close()
    return jsonify({'success': success, 'message': msg})

@app.route('/devices/add', methods=['POST'])
@login_required
def add_device():
    hostname = request.form.get('hostname')
    ip = request.form.get('ip')
    username = request.form.get('username')
    password = request.form.get('password')
    port = request.form.get('port') or 22
    try:
        port = int(port)
    except ValueError:
        port = 22

    existing = Device.query.filter((Device.ip_address == ip) | (Device.hostname == hostname)).first()
    if existing:
        flash('Router dengan IP atau hostname ini sudah terdaftar.')
        return redirect(url_for('dashboard'))

    ssh = SSHManager(ip, username, password, port)
    success, msg = ssh.connect()
    if not success:
        flash('Router tidak dapat terhubung. Pastikan IP, port, dan kredensial benar.')
        return redirect(url_for('dashboard'))

    new_device = Device(hostname=hostname, ip_address=ip, username=username, password=password, port=port, status='Online')
    db.session.add(new_device)
    db.session.commit()
    log_action(f"Added device {hostname} ({ip}:{port})")
    flash('Device registered successfully')
    ssh.close()
    return redirect(url_for('dashboard'))

@app.route('/refresh-status')
@login_required
def refresh_status():
    devices = Device.query.all()
    for device in devices:
        ssh = SSHManager(device.ip_address, device.username, device.password, device.port or 22)
        success, _ = ssh.connect()
        ssh.close()
        device.status = 'Online' if success else 'Offline'
    db.session.commit()
    flash('Status perangkat berhasil diperbarui.')
    return redirect(url_for('dashboard'))

@app.route('/device/delete/<int:device_id>')
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    hostname = device.hostname
    db.session.delete(device)
    db.session.commit()
    log_action(f"Deleted device {hostname}")
    flash(f'Device {hostname} removed')
    return redirect(url_for('dashboard'))

@app.route('/device/update/<int:device_id>', methods=['POST'])
@login_required
def update_device(device_id):
    device = Device.query.get_or_404(device_id)
    old_hostname = device.hostname
    device.hostname = request.form.get('hostname')
    device.ip_address = request.form.get('ip')
    device.username = request.form.get('username')
    device.port = int(request.form.get('port') or 22)
    new_password = request.form.get('password')
    if new_password:
        device.password = new_password
    db.session.commit()
    log_action(f"Updated device info for {old_hostname} -> {device.hostname}")
    flash(f'Device {device.hostname} updated')
    return redirect(url_for('dashboard'))

@app.route('/device/<int:device_id>')
@login_required
def device_detail(device_id):
    device = Device.query.get_or_404(device_id)
    ssh = SSHManager(device.ip_address, device.username, device.password, device.port or 22)
    success, msg = ssh.connect()

    if not success:
        if device.status != 'Offline':
            device.status = 'Offline'
            db.session.commit()
        return render_template('device_detail.html', device=device, error=msg, interfaces=[], interface_count=0)

    if device.status != 'Online':
        device.status = 'Online'
        db.session.commit()

    info = ssh.get_router_info()
    shell_output, shell_err = ssh.check_interfaces_shell()

    interface_data = None
    if shell_output:
        interface_data = shell_output
    elif info.get('interfaces'):
        interface_data = info.get('interfaces')

    interfaces = ssh.parse_interfaces(interface_data)
    interface_count = len(interfaces)

    ssh.close()

    return render_template('device_detail.html', device=device, info=info, interfaces=interfaces, interface_count=interface_count)

@app.route('/device/<int:device_id>/configure_ip', methods=['POST'])
@login_required
def configure_ip(device_id):
    device = Device.query.get_or_404(device_id)
    interface = request.form.get('interface')
    action = request.form.get('action')
    ip_raw = request.form.get('ip')
    
    # Parse IP and mask (e.g. 10.1.1.1/24)
    ip = ip_raw
    mask = "255.255.255.0"
    if ip_raw and '/' in ip_raw:
        parts = ip_raw.split('/')
        ip = parts[0]
        prefix = int(parts[1])
        masks = {24: "255.255.255.0", 30: "255.255.255.252", 32: "255.255.255.255", 16: "255.255.0.0", 8: "255.0.0.0"}
        mask = masks.get(prefix, "255.255.255.0")
    
    ssh = SSHManager(device.ip_address, device.username, device.password, device.port or 22)
    success, msg = ssh.connect()
    if not success:
        flash(f"Connection failed: {msg}")
        return redirect(url_for('device_detail', device_id=device_id))
        
    success, output = ssh.configure_interface(interface, action, ip, mask)
    ssh.close()
    
    if success:
        log_action(f"Performed {action} on {interface} ({ip or ''}) for {device.hostname}", device_id=device.id)
        flash(f'Successfully performed {action} on {interface}')
    else:
        log_action(f"Failed to configure {interface} on {device.hostname}: {output}", level='ERROR', device_id=device.id)
        flash(f'Failed to configure {interface}: {output}')
    
    return redirect(url_for('device_detail', device_id=device_id))

@app.route('/batch', methods=['GET', 'POST'])
@login_required
def batch_config():
    if request.method == 'POST':
        device_ids = request.form.getlist('devices')
        config_text = request.form.get('config_text')
        raw_commands = request.form.get('raw_commands')
        csv_file = request.files.get('csv_file')
        commands = []
        if csv_file:
            try:
                df = pd.read_csv(io.StringIO(csv_file.read().decode('utf-8')))
                # Assuming CSV has 'command' column or just raw lines
                if 'command' in df.columns:
                    commands = df['command'].tolist()
                else:
                    commands = df.iloc[:, 0].tolist() # Use first column
            except Exception as e:
                flash(f"Error reading CSV: {e}")
                return redirect(url_for('batch_config'))

        if raw_commands:
            commands = [c.strip() for c in raw_commands.split('\n') if c.strip()]
        
        # If no specific devices selected, use all
        if not device_ids:
            devices = Device.query.all()
            device_ids = [str(d.id) for d in devices]

        for d_id in device_ids:
            device = Device.query.get(d_id)
            if device:
                success, output = run_batch_config({
                    'ip': device.ip_address,
                    'username': device.username,
                    'password': device.password,
                    'port': device.port or 22
                }, commands)
                results.append({'hostname': device.hostname, 'success': success, 'output': output})
                log_action(f"Batch config on {device.hostname}: {'Success' if success else 'Failed'}", 
                           level='INFO' if success else 'ERROR', device_id=device.id)
            
        return render_template('batch_results.html', results=results)
    
    devices = Device.query.all()
    return render_template('batch_config.html', devices=devices)

# --- User Management ---

@app.route('/users')
@login_required
def users():
    users_list = User.query.all()
    return render_template('users.html', users=users_list)

@app.route('/users/add', methods=['POST'])
@login_required
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
    else:
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        log_action(f"Created new system user: {username}")
        flash('User created successfully')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        flash('Cannot delete default admin')
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_action(f"Deleted system user: {username}")
        flash('User removed')
    return redirect(url_for('users'))

@app.route('/interfaces')
@login_required
def all_interfaces():
    devices = Device.query.all()
    return render_template('interfaces.html', devices=devices)

@app.route('/logs')
@login_required
def system_logs():
    logs = Log.query.order_by(Log.timestamp.desc()).limit(100).all()
    return render_template('logs.html', logs=logs)

@app.route('/api/stats')
@login_required
def get_global_stats():
    devices = Device.query.all()
    total = len(devices)
    online = Device.query.filter_by(status='Online').count()
    
    # In a real app, you might aggregate CPU/Uptime here
    return jsonify({
        'total_devices': total,
        'online_devices': online,
        'avg_cpu': "12.4%", # Placeholder or aggregate
        'uptime': "4d 12h"
    })

@app.route('/terminal')
@login_required
def terminal():
    devices = Device.query.all()
    return render_template('terminal.html', devices=devices)

# --- Terminal (SocketIO) ---

active_shells = {}

@socketio.on('connect_terminal')
def handle_terminal_connect(data):
    device_id = data.get('device_id')
    sid = request.sid
    device = Device.query.get(device_id)
    
    if not device:
        emit('terminal_output', {'data': 'Device not found\n'})
        return

    ssh = SSHManager(device.ip_address, device.username, device.password, device.port or 22)
    success, msg = ssh.connect()
    
    if not success:
        emit('terminal_output', {'data': f'Connection failed: {msg}\n'})
        return

    shell = ssh.client.invoke_shell()
    active_shells[sid] = {'shell': shell, 'client': ssh.client}
    
    def background_thread(session_id):
        while session_id in active_shells:
            sh = active_shells[session_id]['shell']
            if sh.recv_ready():
                try:
                    output = sh.recv(1024).decode('utf-8', errors='ignore')
                    socketio.emit('terminal_output', {'data': output}, room=session_id)
                except:
                    break
            socketio.sleep(0.1)

    socketio.start_background_task(background_thread, sid)

@socketio.on('terminal_input')
def handle_terminal_input(data):
    sid = request.sid
    input_text = data.get('data')
    if sid in active_shells:
        try:
            active_shells[sid]['shell'].send(input_text)
        except:
            pass

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in active_shells:
        try:
            active_shells[sid]['shell'].close()
            active_shells[sid]['client'].close()
        except:
            pass
        del active_shells[sid]

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
