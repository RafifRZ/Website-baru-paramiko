# NetMaster - Network Management Dashboard

A modern web-based automation tool for Cisco GNS3 devices.

## Features

- **Dashboard Overview**: Device status and router info.
- **Interface Management**: Automatic interface detection and IP configuration.
- **Batch Actions**: Execute CLI commands across multiple devices.
- **Terminal Integration**: Real-time CLI streaming via SocketIO.
- **Secure Auth**: Login/Logout system with SQLite storage.

## How to Run

### 1. Prerequisites

Ensure Python 3 is installed in your Ubuntu environment:

```bash
sudo apt update
sudo apt install python3-pip python3-venv
```

### 2. Setup Project

Navigate to the project directory and create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Initialize Database

Initialize the SQLite database and create the default admin user:

```bash
export FLASK_APP=app.py
flask init-db
```

> Default Credentials: `admin` / `admin123`

### 4. Run Application

Start the Flask-SocketIO server:

```bash
python3 app.py
```

Open the app in your browser at `http://localhost:5000`.

## GNS3 Requirements

To connect to your routers, ensure:

1. The Ubuntu VM can ping the GNS3 routers.
2. Routers have SSH enabled.

Example Cisco configuration:

```cisco
hostname R1
ip domain-name local.lab
crypto key generate rsa
ip ssh version 2
username admin privilege 15 password admin
line vty 0 4
login local
transport input ssh
```

## Development

- **Backend**: Flask + Paramiko
- **Frontend**: Tailwind CSS + Jinja2
- **Database**: SQLite (SQLAlchemy)
