import base64
from collections import deque
import gzip
import json
import os
import re
import secrets
import shutil
import signal
import socket

try:
    import miniupnpc
except ImportError:
    miniupnpc = None
import subprocess
import sys
import threading
import time
from datetime import datetime

import psutil
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template_string,
    request,
    Response,
    jsonify,
    stream_with_context,
    redirect,
    url_for,
    flash,
    abort,
    send_from_directory,
)
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
load_dotenv()  # Load from .env file if present

SERVERS_BASE_DIR = "C:\\path\\to\\servers"  # !!! SET THIS PATH !!!
BATCH_FILE_NAME = "starter.bat"  # Name of the batch file in each server folder
BACKUPS_DIR = "Backups"  # Name of the backup directory (relative to SERVERS_BASE_DIR)
HOST = "0.0.0.0"  # Listen on all network interfaces (Change to "127.0.0.1" for local access only)
PORT = 25564  # Port for the web server
USERNAME = "admin"  # Global username for login
PASSWORD = os.getenv("PASSWORD", "password")  # !!! CHANGE THIS PASSWORD !!!
COMMAND_PASSWORD = os.getenv("CMD_PASSWORD", "cmdpass")  # !!! CHANGE THIS COMMAND PASSWORD !!!
# Generate a strong secret key. Keep this key secret and consistent across restarts.
# For production, set this via environment variable or config file.
_generated_secret_key_default = secrets.token_hex(24)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", _generated_secret_key_default)
# SSL Certificate
SSL_CERT_PATH = "C:\\Users\\Me\\cert.pem"  # "C:\\Users\\Me\\server.crt"
SSL_KEY_PATH = "C:\\Users\\Me\\key.pem"  # "C:\\Users\\Me\\server.key"
USE_SSL = False
FAVICON_PATH = "favicon.ico"  # Path to favicon, relative to the script's location.
MAX_LOG_LINES = 1000  # Max console lines to keep in memory
MAX_RESOURCE_HISTORY = 120  # Keep 120 data points (e.g., 2 minutes of data at 1s intervals)
RESOURCE_MONITOR_INTERVAL = 1  # seconds
UPNP_ENABLED = False  # Set to True to enable automatic port forwarding. Requires a UPnP/IGD enabled router.
PORT_RANGE = range(25565, 25574 + 1)  # 25565-25574
# ---------------------

# --- Global variables ---
shutting_down = False
upnp_mappings = {}  # { 'server_name': port }
reserved_ports = set()  # To avoid race conditions
upnp_lock = threading.Lock()

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

RESOURCE_MONITOR_ENABLED = MAX_RESOURCE_HISTORY > 0 and RESOURCE_MONITOR_INTERVAL > 0

# --- Rate Limiting Setup ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # General limits
    storage_uri="memory://",  # Memory storage for simplicity
)

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Route name for the login page
login_manager.login_message_category = "info"  # Flash message category


# --- User Model ---
# Simple User class for Flask-Login. For multiple users, you'd typically use a database.
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    @staticmethod
    def get(user_id):
        # In this simple case, we only have one user (id=1)
        if user_id == "1":
            # IMPORTANT: Store the HASH of the password, not the plain password
            hashed_password = users_storage.get(USERNAME)
            if hashed_password:
                return User(id="1", username=USERNAME, password_hash=hashed_password)
        return None


users_storage = {USERNAME: generate_password_hash(PASSWORD)}
COMMAND_PASSWORD_HASH = generate_password_hash(COMMAND_PASSWORD)


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login callback to load a user from the 'database'."""
    return User.get(user_id)


# --- Process Management ---
# In-memory storage for running processes and their output
running_processes = (
    {}
)  # { 'server_name': {'process': Popen_object, 'output': ['line1', 'line2'], 'lock': threading.Lock(), 'stop_requested': False, 'graceful_stop_timer': None, 'resources': {'cpu': deque(), 'ram': deque()}} }


def get_server_properties(server_path):
    """Parses server.properties file and returns a dictionary of key-value pairs."""
    properties = {}
    properties_file = os.path.join(server_path, "server.properties")
    if os.path.isfile(properties_file):
        try:
            with open(properties_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if "=" in line:
                            key, value = line.split("=", 1)
                            # Unescape characters like \:, \=, etc.
                            value = re.sub(r"\\(.)", r"\1", value.strip())
                            properties[key.strip()] = value
        except Exception as e:
            print(f"Error reading server.properties for {os.path.basename(server_path)}: {e}")
    return properties


def get_server_icon(server_path):
    """Reads server-icon.png and returns it as a base64 encoded string."""
    icon_path = os.path.join(server_path, "server-icon.png")
    if os.path.isfile(icon_path):
        try:
            with open(icon_path, "rb") as f:
                encoded_string = base64.b64encode(f.read()).decode("utf-8")
                return f"data:image/png;base64,{encoded_string}"
        except Exception as e:
            print(f"Error reading server icon for {os.path.basename(server_path)}: {e}")
    return None


def is_port_in_use(port):
    """Checks if a local port is already in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def setup_upnp_port_forwarding(server_name, port_range):
    """Discovers router, enumerates all mappings, finds an available port, and forwards it."""
    logs = []
    if not miniupnpc:
        return None, logs + ["STY:error:miniupnpc library is not installed. Cannot use UPnP."]

    with upnp_lock:
        try:
            u = miniupnpc.UPnP()
            u.discoverdelay = 200
            if u.discover() == 0:
                return None, logs + ["STY:error:UPnP discovery failed: No IGD found on network."]

            u.selectigd()
            internal_ip = u.lanaddr
            logs.append(f"STY:log:UPnP device found.")

            # --- Build a complete list of currently mapped ports ---
            mapped_ports = set()
            i = 0
            while True:
                mapping = u.getgenericportmapping(i)
                if mapping is None:
                    break
                ext_port, proto, _, _, _, _, _ = mapping
                if proto == "TCP":
                    mapped_ports.add(ext_port)
                i += 1

            if mapped_ports:
                logs.append(f"STY:log:Router reports these TCP ports are mapped: {sorted(list(mapped_ports))}")
            # ----------------------------------------------------

            for port in port_range:
                if is_port_in_use(port):
                    logs.append(f"STY:log:Port {port} is in use locally. Skipping.")
                    continue

                if port in mapped_ports:
                    logs.append(f"STY:log:Port {port} is already mapped on router. Skipping.")
                    continue

                if port in reserved_ports:
                    logs.append(f"STY:log:Port {port} is reserved by another starting SCM server. Skipping.")
                    continue

                logs.append(f"STY:log:Port {port} appears free. Attempting to forward...")
                try:
                    reserved_ports.add(port)
                    description = f"SCM - {server_name}"
                    u.addportmapping(port, "TCP", internal_ip, port, description, "")
                    logs.append(f"STY:log:Successfully forwarded port {port} -> {internal_ip}:{port}")
                    upnp_mappings[server_name] = port
                    return port, logs
                except Exception as e:
                    # Should only happen in a true race condition
                    logs.append(f"STY:error:Failed to map port {port}: {e}")
                    reserved_ports.discard(port)

            return None, logs + [f"STY:error:No available ports found in the range {port_range.start}-{port_range.stop-1}."]

        except Exception as e:
            return None, logs + [f"STY:error:An unexpected UPnP error occurred: {e}"]


def remove_upnp_port_forwarding(port):
    """Removes a specific port forwarding rule."""
    logs = []
    if not miniupnpc:
        return logs + ["STY:log:miniupnpc library not installed, skipping UPnP cleanup."]

    with upnp_lock:
        # Also remove from our internal reservation list
        reserved_ports.discard(port)
        try:
            u = miniupnpc.UPnP()
            u.discoverdelay = 200
            if u.discover() > 0:
                u.selectigd()
                if u.deleteportmapping(port, "TCP"):
                    logs.append(f"STY:log:Successfully removed UPnP port mapping for port {port}.")
                else:
                    logs.append(f"STY:error:Failed to remove UPnP port mapping for port {port}. It may not exist.")
            else:
                logs.append("STY:error:Could not find UPnP device to remove port mapping.")
        except Exception as e:
            logs.append(f"STY:error:An error occurred while removing UPnP mapping for port {port}: {e}")
    return logs


def cleanup_server_port_mapping(server_name):
    """Finds and removes the port mapping for a specific server."""
    port_to_remove = upnp_mappings.pop(server_name, None)
    if port_to_remove:
        print(f"Cleaning up UPnP port mapping for {server_name} on port {port_to_remove}...")
        logs = remove_upnp_port_forwarding(port_to_remove)
        for log in logs:
            with running_processes.get(server_name, {}).get("lock", threading.Lock()):
                _log_to_server_output(server_name, log)


def update_server_properties_port(server_path, new_port):
    """Updates the server-port, query.port, and rcon.port in server.properties."""
    properties_file = os.path.join(server_path, "server.properties")
    if not os.path.isfile(properties_file):
        return False, "server.properties not found"

    lines = []
    try:
        with open(properties_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        return False, f"Error reading properties file: {e}"

    new_lines = []
    keys_to_update = {
        "server-port": str(new_port),
        "query.port": str(new_port),
        "rcon.port": str(new_port + 10),
    }
    updated_keys = set()

    for line in lines:
        stripped_line = line.strip()
        is_match = False
        if stripped_line and not stripped_line.startswith("#") and "=" in stripped_line:
            key = stripped_line.split("=", 1)[0].strip()
            if key in keys_to_update:
                new_lines.append(f"{key}={keys_to_update[key]}\n")
                updated_keys.add(key)
                is_match = True
        if not is_match:
            new_lines.append(line)

    for key, value in keys_to_update.items():
        if key not in updated_keys:
            new_lines.append(f"\n{key}={value}\n")

    try:
        with open(properties_file, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        return True, f"Ports set to {new_port} (RCON: {new_port + 10})"
    except Exception as e:
        # If writing fails, try to restore the original content
        try:
            with open(properties_file, "w", encoding="utf-8") as f:
                f.writelines(lines)
        except Exception as restore_e:
            return False, f"Failed to update properties and then failed to restore original file: {restore_e}"
        return False, f"Error writing updated properties: {e}"


# --- Helper Functions (get_server_folders, read_process_output - unchanged from previous version) ---
def get_server_folders():
    """Finds valid server folders in the base directory."""
    servers = []
    if not os.path.isdir(SERVERS_BASE_DIR):
        print(f"Error: Base directory not found: {SERVERS_BASE_DIR}")
        return []
    try:
        for item in os.listdir(SERVERS_BASE_DIR):
            full_path = os.path.join(SERVERS_BASE_DIR, item)
            batch_path = os.path.join(full_path, BATCH_FILE_NAME)
            if os.path.isdir(full_path) and os.path.isfile(batch_path):
                servers.append(item)
    except OSError as e:
        print(f"Error reading directory {SERVERS_BASE_DIR}: {e}")
    return sorted(servers)


def read_process_output(server_name, process):
    """Reads stdout/stderr from a process and stores it."""
    global running_processes
    if server_name not in running_processes:
        return  # Safety check

    process_info = running_processes[server_name]

    try:
        # Read stdout line by line
        for line in iter(process.stdout.readline, b""):
            decoded_line = line.decode(errors="replace").strip()
            with process_info["lock"]:
                process_info["output"].append(decoded_line)
                # Trim the output list to save memory
                if len(process_info["output"]) > MAX_LOG_LINES:
                    process_info["output"].pop(0)
            # time.sleep(0.01) # Optional sleep

        for line in iter(process.stderr.readline, b""):
            decoded_line = f"ERROR: {line.decode(errors='replace').strip()}"
            with process_info["lock"]:
                process_info["output"].append(decoded_line)
                if len(process_info["output"]) > MAX_LOG_LINES:
                    process_info["output"].pop(0)
            # time.sleep(0.01)

    except Exception as e:
        print(f"Error reading output for {server_name}: {e}")
        with process_info["lock"]:
            # Check if still exists before appending
            if server_name in running_processes:
                running_processes[server_name]["output"].append(f"STY:error:--- Error reading output: {e} ---")
    finally:
        if process:
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()
            process.wait()

        print(f"Output reading thread finished for {server_name}")
        # Safely update status if the process entry still exists
        if server_name in running_processes:
            with running_processes[server_name]["lock"]:
                if running_processes[server_name].get("process") is None:
                    return

                if not running_processes[server_name]["stop_requested"]:
                    running_processes[server_name]["output"].append("STY:marker:--- SCRIPT FINISHED UNEXPECTEDLY ---")
                else:
                    running_processes[server_name]["output"].append("STY:marker:--- SCRIPT STOPPED ---")

                print(f"Process for {server_name} has exited. Running cleanup from output thread...")

                # 1. Cleanup Port Mapping
                cleanup_server_port_mapping(server_name)

                # 2. Backup Copy
                server_path = os.path.join(SERVERS_BASE_DIR, server_name)
                try:
                    copy_latest_backup(server_name, server_path)
                except Exception as backup_e:
                    print(f"Critical error calling backup function for {server_name}: {backup_e}")

                print(f"Cleanup for {server_name} complete.")
                running_processes[server_name]["process"] = None


# --- Backup Helper ---
def _log_to_server_output(server_name, message):
    """Helper to log messages to a specific server's output stream, displayed in the UI."""
    global running_processes
    if server_name in running_processes:
        process_info = running_processes[server_name]
        with process_info.get("lock", threading.Lock()):  # Use existing lock or a temp one if somehow missing
            if "output" in process_info:
                process_info["output"].append(message)
            else:
                print(f"Warning: 'output' list not found for server {server_name} during backup logging.")
    else:
        print(f"Warning: Process info for server {server_name} not found during backup logging.")


def find_latest_backup_folder(backup_dir):
    """Finds the latest file or folder in the backup directory based on name sorting."""
    if not os.path.isdir(backup_dir):
        return None
    try:
        items = [item for item in os.listdir(backup_dir) if not item.endswith(".json")]
        if not items:
            return None
        # Sort items alphabetically/numerically - assumes naming convention allows this
        # For timestamp-based sorting, you might use:
        # items.sort(key=lambda item: os.path.getmtime(os.path.join(backup_dir, item)))
        items.sort()
        return items[-1]
    except OSError as e:
        print(f"Error listing backup items in {backup_dir}: {e}")
        return None


def copy_latest_backup(server_name, server_path):
    """Copies the latest backup file or folder to the shared Backups directory."""
    _log_to_server_output(server_name, "STY:marker:--- BACKUP START ---")
    source_backups_dir = os.path.join(server_path, "backups")
    # SERVERS_BASE_DIR/BACKUPS_DIR
    target_parent_dir = os.path.abspath(os.path.join(SERVERS_BASE_DIR, BACKUPS_DIR))

    log_msg_checking = f"Checking for backups in: {source_backups_dir}"
    print(log_msg_checking)
    _log_to_server_output(server_name, f"STY:log:{log_msg_checking}")
    latest_item_name = find_latest_backup_folder(source_backups_dir)

    if latest_item_name:
        log_msg_found = f"Found latest backup item: {latest_item_name}"
        print(log_msg_found)
        _log_to_server_output(server_name, f"STY:log:{log_msg_found}")
        source_path = os.path.join(source_backups_dir, latest_item_name)
        is_source_dir = os.path.isdir(source_path)
        dest_item_name = f"{server_name}_{latest_item_name}"
        dest_path = os.path.join(target_parent_dir, dest_item_name)
        log_msg_attempting = f"Attempting to copy backup from '{source_path}' to '{dest_path}'"
        print(log_msg_attempting)
        _log_to_server_output(server_name, f"STY:log:{log_msg_attempting}")

        try:
            os.makedirs(target_parent_dir, exist_ok=True)

            if os.path.exists(dest_path):
                skip_message = f"Destination backup item '{dest_item_name}' already exists. Skipping copy."
                print(f"Warning: {skip_message}")
                _log_to_server_output(server_name, f"STY:log:{skip_message}")
                _log_to_server_output(server_name, "STY:marker:--- BACKUP COMPLETE ---")
                return f"Backup skipped (destination exists: {dest_item_name})"

            if is_source_dir:
                shutil.copytree(source_path, dest_path)
            else:
                shutil.copy2(source_path, dest_path)  # copy2 preserves metadata

            success_message = f"Successfully copied backup '{dest_item_name}' to shared Backups."
            print(success_message)
            _log_to_server_output(server_name, f"STY:log:{success_message}")
            _log_to_server_output(server_name, "STY:marker:--- BACKUP COMPLETE ---")
            return f"Backup copied ({dest_item_name})"
        except OSError as e:
            error_message = f"Error copying backup for {server_name}: {e}"
            print(error_message)
            _log_to_server_output(server_name, f"STY:error:{error_message}")
            _log_to_server_output(server_name, "STY:marker:--- BACKUP COMPLETE ---")
            return f"Backup failed (Error: {e})"
        except Exception as e:
            error_message = f"Unexpected error during backup copy for {server_name}: {e}"
            print(error_message)
            _log_to_server_output(server_name, f"STY:error:{error_message}")
            _log_to_server_output(server_name, "STY:marker:--- BACKUP COMPLETE ---")
            return f"Backup failed (Unexpected Error: {e})"
    else:
        not_found_message = f"No backup items found or accessible in {source_backups_dir}"
        print(not_found_message)
        _log_to_server_output(server_name, f"STY:log:{not_found_message}")
        _log_to_server_output(server_name, "STY:marker:--- BACKUP COMPLETE ---")
        return "No backups found to copy"


# --- Routes ---
@app.route("/favicon.ico")
def favicon():
    if not FAVICON_PATH or not os.path.isfile(os.path.join(app.root_path, FAVICON_PATH)):
        return ("", 204)
    return send_from_directory(app.root_path, FAVICON_PATH)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # Apply rate limit specifically to login attempts
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = True if request.form.get("remember") else False

        stored_password_hash = users_storage.get(username)
        user_obj = None
        if stored_password_hash:
            # Only create User object if username exists to check password
            temp_user = User(id="1", username=username, password_hash=stored_password_hash)  # ID '1' is placeholder
            if check_password_hash(temp_user.password_hash, password):
                user_obj = temp_user  # Valid credentials

        if user_obj:
            login_user(user_obj, remember=remember)
            flash("Logged in successfully.", "success")
            # Redirect
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))
        else:
            flash("Invalid username or password.", "danger")

    # Render login form for GET request or failed POST
    return render_template_string(LOGIN_TEMPLATE)


@app.route("/logout")
@login_required
def logout():
    """Handles user logout."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    """Serves the main control panel page."""
    servers = get_server_folders()
    server_details = {}
    for server_name in servers:
        server_path = os.path.join(SERVERS_BASE_DIR, server_name)
        properties = get_server_properties(server_path)
        icon = get_server_icon(server_path)
        server_details[server_name] = {
            "motd": properties.get("motd", "No MOTD found"),
            "version": properties.get("version", ""),
            "icon": icon,
            "port": properties.get("server-port", "N/A"),
        }

    # Pass server status (running or not) to the template
    server_status = {
        name: (proc_info["process"] is not None and proc_info["process"].poll() is None)
        for name, proc_info in running_processes.items()
        if proc_info and "process" in proc_info
    }
    return render_template_string(
        HTML_TEMPLATE,
        servers=servers,
        server_status=server_status,
        server_details=server_details,
        username=current_user.username,
        resource_monitor_interval=RESOURCE_MONITOR_INTERVAL,
        resource_monitor_enabled=RESOURCE_MONITOR_ENABLED,
        max_resource_history=MAX_RESOURCE_HISTORY,
    )


@app.route("/start/<server_name>", methods=["GET", "POST"])  # <--- Allow both GET and POST
@login_required
def start_server(server_name):
    """
    Starts the batch file for the specified server.
    Handles both POST (from UI button) and GET (direct URL access).
    """
    global running_processes
    servers = get_server_folders()  # Re-check available servers

    # --- Validation (Common for GET and POST) ---
    if server_name not in servers:
        if request.method == "POST":
            # Abort for POST is fine, leads to JS error handling
            abort(404, "Invalid server name.")
        else:  # request.method == 'GET'
            # For GET, flash a message and redirect
            flash(f"Error: Invalid server name '{server_name}'.", "danger")
            return redirect(url_for("index"))

    server_path = os.path.join(SERVERS_BASE_DIR, server_name)
    batch_path = os.path.join(server_path, BATCH_FILE_NAME)

    if not os.path.isfile(batch_path):
        if request.method == "POST":
            abort(404, f"{BATCH_FILE_NAME} not found in {server_name}.")
        else:
            flash(f"Error: {BATCH_FILE_NAME} not found for server '{server_name}'.", "danger")
            return redirect(url_for("index"))

    # --- Check if already running (Common for GET and POST, needs thread safety) ---
    # Use a temporary lock if the server entry doesn't exist yet to avoid race conditions on first start
    # This lock is just for the check, the actual process info will have its own lock later
    check_lock = running_processes.get(server_name, {}).get("lock", threading.Lock())

    with check_lock:
        process_info = running_processes.get(server_name)
        if process_info and process_info.get("process") and process_info["process"].poll() is None:
            # Server is already running
            if request.method == "POST":
                return jsonify({"status": "error", "message": f"{server_name} is already running."}), 400
            else:
                flash(f"Info: Server '{server_name}' is already running.", "info")
                return redirect(url_for("index"))

    # --- Start the process (Common logic) ---
    pre_start_logs = [f"STY:marker:--- Starting {server_name} ({BATCH_FILE_NAME}) ---"]
    port_to_return = None

    # --- UPnP Port Forwarding Logic ---
    if UPNP_ENABLED:
        pre_start_logs.append("STY:log:UPnP enabled. Discovering router and finding available port...")
        found_port, upnp_logs = setup_upnp_port_forwarding(server_name, PORT_RANGE)
        pre_start_logs.extend(upnp_logs)

        if found_port:
            port_to_return = found_port
            pre_start_logs.append(f"STY:log:Using port: {found_port}. Updating server.properties...")
            success, message = update_server_properties_port(server_path, found_port)
            if success:
                pre_start_logs.append(f"STY:log:server.properties updated successfully. {message}")
            else:
                message = f"Failed to update server.properties: {message}"
                pre_start_logs.append(f"STY:error:{message}")
                cleanup_server_port_mapping(server_name)
                if request.method == "POST":
                    return jsonify({"status": "error", "message": message}), 500
                else:
                    flash(f"Error for '{server_name}': {message}", "danger")
                    return redirect(url_for("index"))
        else:
            message = f"Failed to find and forward a port via UPnP: {upnp_logs[-1]}."
            if request.method == "POST":
                return jsonify({"status": "error", "message": message}), 500
            else:
                flash(f"Error for '{server_name}': {message}", "danger")
                return redirect(url_for("index"))
    else:
        pre_start_logs.append("STY:log:UPnP is disabled. Using port from server.properties.")
        properties = get_server_properties(server_path)
        port_to_return = properties.get("server-port")

    try:
        process = subprocess.Popen(
            [batch_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=server_path,
            shell=False,  # Important for security and avoiding shell injection
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,  # Windows specific for reliable termination
        )

        # Store process info and start output reading thread
        # Create the lock *before* adding the entry to avoid race conditions
        new_lock = threading.RLock()
        running_processes[server_name] = {
            "process": process,
            "output": pre_start_logs,
            "lock": new_lock,
            "stop_requested": False,
            "resources": {  # Initialize with empty deques
                "cpu": deque(maxlen=MAX_RESOURCE_HISTORY),
                "ram": deque(maxlen=MAX_RESOURCE_HISTORY),
            },
        }
        thread = threading.Thread(target=read_process_output, args=(server_name, process), daemon=True)
        thread.start()

        # Start resource monitoring thread
        if MAX_RESOURCE_HISTORY > 0 and RESOURCE_MONITOR_INTERVAL > 0:
            resource_thread = threading.Thread(target=monitor_process_resources, args=(server_name, process.pid), daemon=True)
            resource_thread.start()

        print(f"Started process for {server_name} with PID: {process.pid}")

        # --- Response Generation (Different for GET and POST) ---
        if request.method == "POST":
            response_data = {"status": "success", "message": f"Started {server_name}."}
            if port_to_return:
                response_data["port"] = port_to_return
            return jsonify(response_data)
        else:
            flash(f"Success: Started server '{server_name}'.", "success")
            return redirect(url_for("index"))

    except Exception as e:
        print(f"Error starting {server_name}: {e}")
        # Attempt to clean up if process partially started but failed later
        # Need to handle potential race condition if entry was just added
        error_lock = running_processes.get(server_name, {}).get("lock")
        if error_lock:
            with error_lock:
                if server_name in running_processes:  # Check again inside lock
                    del running_processes[server_name]
        else:
            if server_name in running_processes:
                del running_processes[server_name]

        if request.method == "POST":
            return jsonify({"status": "error", "message": f"Failed to start {server_name}: {e}"}), 500
        else:
            flash(f"Error: Failed to start server '{server_name}': {e}", "danger")
            return redirect(url_for("index"))  # Redirect back to the main page


@app.route("/stop/<server_name>", methods=["POST"])
@login_required
def stop_server(server_name):
    """Initiates a graceful stop for the specified server."""
    global running_processes

    if server_name not in running_processes or not running_processes[server_name].get("process"):
        return jsonify({"status": "error", "message": f"{server_name} is not running or already stopped."}), 404

    process_info = running_processes[server_name]
    process = process_info["process"]

    with process_info["lock"]:
        if process.poll() is not None:
            return jsonify({"status": "error", "message": f"{server_name} has already finished."}), 400

        if process_info.get("stop_requested"):
            return jsonify({"status": "info", "message": "Stop already in progress."}), 202

        print(f"Attempting graceful stop for {server_name} (PID: {process.pid})...")
        process_info["output"].append("STY:marker:--- GRACEFUL STOP REQUESTED ---")
        process_info["output"].append("STY:stdin:stop")
        process_info["stop_requested"] = True

    # Release the lock before writing to stdin to prevent deadlock with the output reader thread
    time.sleep(0.05)

    try:
        process.stdin.write(b"stop\n")
        process.stdin.flush()

        with process_info["lock"]:

            def force_stop_after_delay():
                time.sleep(60)
                if server_name in running_processes:
                    proc_info_timer = running_processes[server_name]
                    with proc_info_timer["lock"]:
                        # Check if the process is still running and a stop was requested
                        if (
                            proc_info_timer.get("process")
                            and proc_info_timer["process"].poll() is None
                            and proc_info_timer.get("stop_requested")
                        ):
                            print(f"Graceful stop for {server_name} timed out. Forcing termination.")
                            proc_info_timer["output"].append("STY:marker:--- GRACEFUL STOP TIMEOUT: FORCING STOP ---")
                            _force_kill_process(server_name, proc_info_timer)

            timer_thread = threading.Thread(target=force_stop_after_delay, daemon=True)
            timer_thread.start()
            process_info["graceful_stop_timer"] = timer_thread

        return jsonify(
            {
                "status": "success",
                "message": "Graceful stop initiated. Server will be force-stopped in 60 seconds if it doesn't exit.",
            }
        )

    except Exception as e:
        print(f"Error initiating graceful stop for {server_name}: {e}")
        with process_info["lock"]:
            process_info["output"].append(f"STY:error:--- ERROR INITIATING GRACEFUL STOP: {e} ---")
        return jsonify({"status": "error", "message": f"Error initiating graceful stop: {e}"}), 500


def _force_kill_process(server_name, process_info):
    """Internal helper to forcefully terminate a process. Assumes lock is held."""
    process = process_info.get("process")
    if not process or process.poll() is not None:
        return "already stopped"

    print(f"Force killing process for {server_name} (PID: {process.pid})...")
    try:
        subprocess.call(["taskkill", "/F", "/T", "/PID", str(process.pid)])
        time.sleep(1)  # Give it a moment
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

        final_status = "stopped" if process.poll() is not None else "failed to stop"
        process_info["output"].append(f"STY:marker:--- SCRIPT FORCE {final_status.upper()} ---")
        process_info["process"] = None

        # Trigger backup on successful forced stop
        if final_status == "stopped":
            cleanup_server_port_mapping(server_name)
            server_path = os.path.join(SERVERS_BASE_DIR, server_name)
            try:
                copy_latest_backup(server_name, server_path)
            except Exception as backup_e:
                print(f"Critical error calling backup function for {server_name} after force kill: {backup_e}")

        return final_status
    except Exception as e:
        print(f"Error during force kill for {server_name}: {e}")
        process_info["output"].append(f"STY:error:--- ERROR DURING FORCE KILL: {e} ---")
        return "error"


@app.route("/force_stop/<server_name>", methods=["POST"])
@login_required
def force_stop_server(server_name):
    """Forcefully stops the running server process."""
    global running_processes

    if server_name not in running_processes or not running_processes[server_name].get("process"):
        return jsonify({"status": "error", "message": f"{server_name} is not running or already stopped."}), 404

    process_info = running_processes[server_name]
    with process_info["lock"]:
        if process_info["process"].poll() is not None:
            return jsonify({"status": "error", "message": f"{server_name} has already finished."}), 400

        process_info["output"].append("STY:marker:--- MANUAL FORCE STOP REQUESTED ---")
        final_status = _force_kill_process(server_name, process_info)

        if final_status != "error":
            return jsonify({"status": "success", "message": f"{server_name} forcefully {final_status}."})
        else:
            return jsonify({"status": "error", "message": f"An error occurred while trying to force stop {server_name}."}), 500


@app.route("/output/<server_name>")
@login_required
def stream_output(server_name):
    """Streams the output of a running/finished process using SSE."""
    if server_name not in running_processes:
        # Return an event indicating the server isn't running or hasn't been started
        def initial_event():
            yield "event: status\ndata: Not Found\n\n"
            yield "event: close\ndata: Stream closing\n\n"  # Signal client to close

        return Response(initial_event(), mimetype="text/event-stream")

    # Check if process info exists before proceeding
    process_info = running_processes.get(server_name)
    if not process_info:

        def not_found_event():
            yield "event: status\ndata: Not Found\n\n"
            yield "event: close\ndata: Stream closing\n\n"

        return Response(not_found_event(), mimetype="text/event-stream")

    def generate_output():
        last_index = 0
        process_info = running_processes[server_name]
        last_resource_timestamp_sent = 0

        last_sent_time = time.time()
        while True:
            resource_payload = None
            with process_info["lock"]:
                current_len = len(process_info["output"])
                new_lines = process_info["output"][last_index:current_len]

                if RESOURCE_MONITOR_ENABLED:
                    cpu_deque = process_info.get("resources", {}).get("cpu")
                    if cpu_deque:
                        latest_timestamp, latest_cpu = cpu_deque[-1]
                        if latest_timestamp > last_resource_timestamp_sent:
                            ram_deque = process_info.get("resources", {}).get("ram", [])
                            latest_ram = 0
                            if ram_deque and ram_deque[-1][0] == latest_timestamp:
                                latest_ram = ram_deque[-1][1]
                            resource_payload = json.dumps({"cpu": latest_cpu, "ram": latest_ram, "timestamp": latest_timestamp})
                            last_resource_timestamp_sent = latest_timestamp

                # Check process status *inside* the lock to ensure consistency with output read
                process_obj = process_info.get("process")
                process_running = process_obj is not None and process_obj.poll() is None
                stop_req = process_info.get("stop_requested", False)

            if new_lines:
                for line in new_lines:
                    yield f"event: message\ndata: {line}\n\n"
                last_index = current_len
                last_sent_time = time.time()

            if resource_payload:
                yield f"event: resources\ndata: {resource_payload}\n\n"
                last_sent_time = time.time()

            if not new_lines and not resource_payload and time.time() - last_sent_time > 10:
                yield ":heartbeat\n\n"
                last_sent_time = time.time()

            # Send final status and close
            if not process_running:
                status_message = "Stopped" if stop_req else "Finished"
                yield f"event: status\ndata: {status_message}\n\n"
                yield "event: close\ndata: Stream closing\n\n"
                break  # Stop streaming

            time.sleep(0.5)  # Adjust polling frequency as needed

    return Response(stream_with_context(generate_output()), mimetype="text/event-stream")


@app.route("/command/<server_name>", methods=["POST"])
@login_required
def send_command(server_name):
    """Sends a command to the stdin of a running server process."""
    global running_processes
    global COMMAND_PASSWORD_HASH

    if not request.is_json:
        return jsonify({"status": "error", "message": "Invalid request format, JSON expected."}), 400

    data = request.get_json()
    command_text = data.get("command")
    provided_cmd_password = data.get("command_password")

    if not command_text or not provided_cmd_password:
        return jsonify({"status": "error", "message": "Missing command or command password."}), 400

    # Verify the command password
    if not check_password_hash(COMMAND_PASSWORD_HASH, provided_cmd_password):
        return jsonify({"status": "error", "message": "Invalid command password."}), 403

    process_info = running_processes.get(server_name)
    if not process_info or not process_info.get("process") or process_info["process"].poll() is not None:
        return jsonify({"status": "error", "message": f"{server_name} is not running or already stopped."}), 404

    process = process_info["process"]

    try:
        # Ensure command ends with a newline, as most console apps expect this
        if not command_text.endswith("\n"):
            command_text += "\n"

        process.stdin.write(command_text.encode("utf-8"))
        process.stdin.flush()  # Ensure it's sent immediately

        # Log the command to the server's output display as well
        with process_info["lock"]:
            process_info["output"].append(f"STY:stdin:{command_text.strip()}")

        return jsonify({"status": "success", "message": "Command sent."})
    except Exception as e:
        print(f"Error sending command to {server_name}: {e}")
        with process_info["lock"]:
            process_info["output"].append(f"STY:error:--- ERROR SENDING COMMAND: {e} ---")
        return jsonify({"status": "error", "message": f"Error sending command: {e}"}), 500


def monitor_process_resources(server_name, pid):
    """Monitors CPU and RAM usage for a given process PID and all its children."""
    global running_processes
    try:
        parent_proc = psutil.Process(pid)
        # Store Process objects to maintain the state required for cpu_percent(interval=None)
        tracked_procs = {}

        while server_name in running_processes and running_processes[server_name].get("process"):
            process_info = running_processes[server_name]
            if not parent_proc.is_running() or process_info["process"].poll() is not None:
                break

            total_cpu_usage = 0
            total_ram_usage_bytes = 0

            current_procs_in_tree: dict[str, psutil.Process] = {}
            try:
                # Get all processes in the tree for this polling cycle
                all_procs_list = [parent_proc] + parent_proc.children(recursive=True)
                for p in all_procs_list:
                    current_procs_in_tree[p.pid] = p
            except psutil.NoSuchProcess:
                break

            # Add newly spawned processes to our tracking dictionary and initialize them
            for pid, proc in current_procs_in_tree.items():
                if pid not in tracked_procs:
                    proc.cpu_percent(interval=None)  # First call is for initialization
                    tracked_procs[pid] = proc

            # Remove processes that have terminated
            for pid in list(tracked_procs.keys()):
                if pid not in current_procs_in_tree:
                    del tracked_procs[pid]

            # Calculate total resource usage from our tracked, stateful Process objects
            for pid, proc in tracked_procs.items():
                try:
                    if proc.is_running():
                        total_cpu_usage += proc.cpu_percent(interval=None)
                        total_ram_usage_bytes += proc.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            with process_info["lock"]:
                timestamp = time.time() * 1000  # Use milliseconds for JS charts
                if "resources" not in process_info:
                    process_info["resources"] = {
                        "cpu": deque(maxlen=MAX_RESOURCE_HISTORY),
                        "ram": deque(maxlen=MAX_RESOURCE_HISTORY),
                    }
                process_info["resources"]["cpu"].append((timestamp, total_cpu_usage))
                process_info["resources"]["ram"].append((timestamp, total_ram_usage_bytes))

            time.sleep(RESOURCE_MONITOR_INTERVAL)
    except psutil.NoSuchProcess:
        print(f"Resource monitor for {server_name} (PID: {pid}) exiting: Process not found.")
    except Exception as e:
        print(f"Error in resource monitor for {server_name} (PID: {pid}): {e}")
    finally:
        print(f"Resource monitoring thread finished for {server_name}")


@app.route("/resources/<server_name>")
@login_required
@limiter.exempt
def get_resource_usage(server_name):
    """Returns the latest and historical resource usage for a server."""
    if server_name not in running_processes:
        return jsonify({"status": "error", "message": "Server not running or not found."}), 404

    process_info = running_processes.get(server_name)
    if not process_info or "resources" not in process_info:
        return jsonify({"cpu": {"latest": 0, "history": []}, "ram": {"latest": 0, "history": []}})

    with process_info["lock"]:
        cpu_history = list(process_info["resources"]["cpu"])
        ram_history = list(process_info["resources"]["ram"])

    latest_cpu = cpu_history[-1][1] if cpu_history else 0
    latest_ram = ram_history[-1][1] if ram_history else 0

    return jsonify(
        {"cpu": {"latest": latest_cpu, "history": cpu_history}, "ram": {"latest": latest_ram, "history": ram_history}}
    )


def get_human_readable_size(size, decimal_places=2):
    """Converts a size in bytes to a human-readable format."""
    if size is None:
        return ""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f} {unit}"


PUBLIC_FILES_LIST_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Public Files for {{ server_name }} - Server Control Panel</title>
    <link rel="icon" href="{{ url_for('favicon') }}">
    <script>
        // Apply theme immediately to prevent flashing
        (function() {
            const theme = localStorage.getItem('theme') || 'light';
            if (theme === 'dark') {
                document.documentElement.classList.add('dark-mode');
            }
        })();
    </script>
    <style>
        :root {
            --bg-color: #f4f4f4;
            --text-color: #333;
            --navbar-bg: #333;
            --navbar-text: white;
            --navbar-hover: #555;
            --container-bg: #fff;
            --header-color: #555;
            --border-color: #eee;
            --table-border: #ddd;
            --th-bg: #f8f9fa;
            --path-bg: #e9ecef;
            --link-color: #007bff;
            --button-bg: #6c757d;
            --button-hover-bg: #5a6268;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        .dark-mode {
            --bg-color: #1a1a1a;
            --text-color: #e0e0e0;
            --navbar-bg: #252525;
            --navbar-text: #e0e0e0;
            --navbar-hover: #444;
            --container-bg: #2c2c2c;
            --header-color: #ccc;
            --border-color: #444;
            --table-border: #555;
            --th-bg: #3a3a3a;
            --path-bg: #333;
            --link-color: #58a6ff;
            --button-bg: #555;
            --button-hover-bg: #777;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.3);
        }

        ::-webkit-scrollbar { width: 12px; height: 12px; }
        ::-webkit-scrollbar-button { display: none; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background-color: rgba(0,0,0,0);
            border-radius: 20px;
            border: 3px solid transparent;
            background-clip: content-box;
        }
        ::-webkit-scrollbar-thumb:hover { background-color: rgba(255,255,255,0.3); }

        body { font-family: sans-serif; line-height: 1.6; margin: 0; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.2s, color 0.2s; }
        .navbar { background-color: var(--navbar-bg); padding: 10px 20px; color: var(--navbar-text); display: flex; justify-content: space-between; align-items: center; }
        .navbar .left-nav, .navbar .right-nav { display: flex; align-items: center; gap: 15px; }
        .navbar a { color: var(--navbar-text); text-decoration: none; padding: 5px 10px; border-radius: 4px; }
        .navbar a:hover { background-color: var(--navbar-hover); }
        #theme-toggle { background: none; border: 1px solid var(--navbar-text); color: var(--navbar-text); cursor: pointer; border-radius: 5px; padding: 5px 8px; font-size: 1.2em; }
        .container { max-width: 900px; margin: 20px auto; background: var(--container-bg); padding: 20px; border-radius: 8px; box-shadow: var(--box-shadow); }
        h1 { color: var(--header-color); border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 20px; }
        .path-display { background-color: var(--path-bg); padding: 10px; border-radius: 4px; margin-bottom: 20px; font-family: monospace; word-break: break-all; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--table-border); }
        th { background-color: var(--th-bg); }
        td a { text-decoration: none; color: var(--link-color); display: block; }
        td a:hover { text-decoration: underline; }
        .back-link { display: inline-block; margin-top: 20px; padding: 8px 15px; background-color: var(--button-bg); color: white; border-radius: 4px; text-decoration: none; }
        .back-link:hover { background-color: var(--button-hover-bg); }
        .icon { margin-right: 8px; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="left-nav">
            <span>Server Manager - Public Files</span>
        </div>
        <div class="right-nav">
            <a href="{{ url_for('index') }}">Main Panel</a>
            <span>Welcome, {{ current_user.username }}!</span>
            <a href="{{ url_for('logout') }}">Logout</a>
            <button id="theme-toggle">◐</button>
        </div>
    </div>
    <div class="container">
        <h1>Public Files for: {{ server_name }}</h1>
        <div class="path-display">Current Path: /public/{{ current_path }}</div>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Last Modified</th>
                </tr>
            </thead>
            <tbody>
                {% if parent_path is not none %}
                <tr>
                    <td colspan="3">
                        <a href="{{ url_for('list_public_files', server_name=server_name, subpath=parent_path) }}">
                            <span class="icon">&#128193;</span>../ (Parent Directory)
                        </a>
                    </td>
                </tr>
                {% endif %}
                {% for dir in directories %}
                <tr>
                    <td colspan="3">
                        <a href="{{ url_for('list_public_files', server_name=server_name, subpath=dir.path) }}">
                            <span class="icon">&#128193;</span>{{ dir.name }}/
                        </a>
                    </td>
                </tr>
                {% endfor %}
                {% for file in files %}
                <tr>
                    <td>
                        <a href="{{ url_for('download_public_file', server_name=server_name, path=file.path) }}" target="_blank">
                        <span class="icon">&#128196;</span>{{ file.name }}
                        </a>
                    </td>
                    <td>{{ file.size_human }}</td>
                    <td>{{ file.modified }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% if not directories and not files and parent_path is none %}
        <p>This directory is empty.</p>
        {% endif %}
        <a href="{{ url_for('index') }}" class="back-link">Back to Main Panel</a>
    </div>
    <script>
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const html = document.documentElement;
            html.classList.toggle('dark-mode');
            const theme = html.classList.contains('dark-mode') ? 'dark' : 'light';
            localStorage.setItem('theme', theme);
        });
    </script>
</body>
</html>
"""


@app.route("/public/<server_name>/", defaults={"subpath": ""})
@app.route("/public/<server_name>/<path:subpath>")
@login_required
def list_public_files(server_name, subpath):
    """Lists files and directories in the server's public folder."""
    servers = get_server_folders()
    if server_name not in servers:
        abort(404, "Server not found.")

    base_public_dir = os.path.abspath(os.path.join(SERVERS_BASE_DIR, server_name, "public"))
    requested_path = os.path.abspath(os.path.join(base_public_dir, subpath))

    # Security Check: Ensure the requested path is inside the public directory
    if not requested_path.startswith(base_public_dir) or not os.path.isdir(requested_path):
        abort(404, "Directory not found or access denied.")

    directories = []
    files = []

    try:
        for item_name in sorted(os.listdir(requested_path), key=str.lower):
            full_path = os.path.join(requested_path, item_name)
            # Create a relative path from the *base* public dir for URL generation
            relative_path = os.path.relpath(full_path, base_public_dir).replace("\\", "/")

            stat_info = os.stat(full_path)
            modified_time = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

            if os.path.isdir(full_path):
                directories.append({"name": item_name, "path": relative_path})
            else:
                files.append(
                    {
                        "name": item_name,
                        "path": relative_path,
                        "size_human": get_human_readable_size(stat_info.st_size),
                        "modified": modified_time,
                    }
                )
    except OSError as e:
        flash(f"Error reading directory: {e}", "danger")

    parent_path = None
    if requested_path != base_public_dir:
        parent_path = os.path.dirname(subpath)

    return render_template_string(
        PUBLIC_FILES_LIST_TEMPLATE,
        server_name=server_name,
        current_path=subpath,
        parent_path=parent_path,
        directories=directories,
        files=files,
        username=current_user.username,
    )


@app.route("/download/<server_name>/<path:path>")
@login_required
def download_public_file(server_name, path):
    """Serves a specific file for download/viewing."""
    servers = get_server_folders()
    if server_name not in servers:
        abort(404, "Server not found.")

    public_dir = os.path.abspath(os.path.join(SERVERS_BASE_DIR, server_name, "public"))

    # send_from_directory handles security checks against path traversal
    return send_from_directory(public_dir, path, as_attachment=False)  # as_attachment=False tries to display in browser


# --- Server-Specific Log Viewing ---
LOGS_PER_PAGE = 15

SERVER_LOGS_LIST_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logs for {{ server_name }} - Server Control Panel</title>
    <link rel="icon" href="{{ url_for('favicon') }}">
    <script>
        // Apply theme immediately to prevent flashing
        (function() {
            const theme = localStorage.getItem('theme') || 'light';
            if (theme === 'dark') {
                document.documentElement.classList.add('dark-mode');
            }
        })();
    </script>
    <style>
        :root {
            --bg-color: #f4f4f4;
            --text-color: #333;
            --navbar-bg: #333;
            --navbar-text: white;
            --navbar-hover: #555;
            --container-bg: #fff;
            --header-color: #555;
            --border-color: #eee;
            --table-border: #ddd;
            --th-bg: #f0f0f0;
            --link-color: #007bff;
            --button-bg: #6c757d;
            --button-hover-bg: #5a6268;
            --pagination-border: #ddd;
            --pagination-disabled: #ccc;
            --pagination-current-bg: #007bff;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        .dark-mode {
            --bg-color: #1a1a1a;
            --text-color: #e0e0e0;
            --navbar-bg: #252525;
            --navbar-text: #e0e0e0;
            --navbar-hover: #444;
            --container-bg: #2c2c2c;
            --header-color: #ccc;
            --border-color: #444;
            --table-border: #555;
            --th-bg: #3a3a3a;
            --link-color: #58a6ff;
            --button-bg: #555;
            --button-hover-bg: #777;
            --pagination-border: #555;
            --pagination-disabled: #555;
            --pagination-current-bg: #58a6ff;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.3);
        }

        ::-webkit-scrollbar { width: 12px; height: 12px; }
        ::-webkit-scrollbar-button { display: none; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background-color: rgba(255,255,255,0.2);
            border-radius: 20px;
            border: 3px solid transparent;
            background-clip: content-box;
        }
        ::-webkit-scrollbar-thumb:hover { background-color: rgba(255,255,255,0.3); }

        body { font-family: sans-serif; line-height: 1.6; margin: 0; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.2s, color 0.2s; }
        .navbar { background-color: var(--navbar-bg); padding: 10px 20px; color: var(--navbar-text); display: flex; justify-content: space-between; align-items: center; }
        .navbar .left-nav, .navbar .right-nav { display: flex; align-items: center; gap: 15px; }
        .navbar a { color: var(--navbar-text); text-decoration: none; padding: 5px 10px; border-radius: 4px; }
        .navbar a:hover { background-color: var(--navbar-hover); }
        #theme-toggle { background: none; border: 1px solid var(--navbar-text); color: var(--navbar-text); cursor: pointer; border-radius: 5px; padding: 5px 8px; font-size: 1.2em; }
        .container { max-width: 900px; margin: 20px auto; background: var(--container-bg); padding: 20px; border-radius: 8px; box-shadow: var(--box-shadow); }
        h1 { color: var(--header-color); border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 20px; }
        .flash-messages { list-style: none; padding: 0; margin-bottom: 15px; }
        .flash-messages li { padding: 10px 15px; margin-bottom: 10px; border-radius: 4px; }
        .flash-danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .flash-warning { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
        .dark-mode .flash-danger { background-color: #582a2e; color: #f5c6cb; border-color: #721c24; }
        .dark-mode .flash-warning { background-color: #66542c; color: #ffeeba; border-color: #856404; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--table-border); }
        th { background-color: var(--th-bg); }
        a { color: var(--link-color); text-decoration: none; }
        a:hover { text-decoration: underline; }
        .pagination { margin-top: 20px; text-align: center; }
        .pagination a, .pagination span { display: inline-block; padding: 8px 12px; margin: 0 2px; border: 1px solid var(--pagination-border); border-radius: 4px; color: var(--link-color); }
        .pagination span.current { background-color: var(--pagination-current-bg); color: white; border-color: var(--pagination-current-bg); }
        .pagination span.disabled { color: var(--pagination-disabled); border-color: #eee; }
        .dark-mode .pagination span.disabled { color: #666; border-color: #444; }
        .back-link { display: inline-block; margin-top: 20px; padding: 8px 15px; background-color: var(--button-bg); color: white; border-radius: 4px; text-decoration: none; }
        .back-link:hover { background-color: var(--button-hover-bg); }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="left-nav">
            <span>Server Manager - Logs for {{ server_name }}</span>
        </div>
        <div class="right-nav">
            <a href="{{ url_for('index') }}">Main Panel</a>
            <span>Welcome, {{ current_user.username }}!</span>
            <a href="{{ url_for('logout') }}">Logout</a>
            <button id="theme-toggle">◐</button>
        </div>
    </div>
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class="flash-messages">
                {% for category, message in messages %}
                    <li class="flash-{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        <h1>Logs for Server: {{ server_name }}</h1>
        {% if log_files %}
            <table>
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Last Modified</th>
                        <th>Size (Bytes)</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in log_files %}
                    <tr>
                        <td>{{ log.name }}</td>
                        <td>{{ log.modified_time }}</td>
                        <td>{{ log.size }}</td>
                        <td><a href="{{ url_for('view_server_log_file', server_name=server_name, log_filename=log.name) }}">View</a></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% if total_pages > 1 %}
            <div class="pagination">
                {% if current_page > 1 %}
                    <a href="{{ url_for('list_server_logs_paginated', server_name=server_name, page=current_page-1) }}">&laquo; Prev</a>
                {% else %}
                    <span class="disabled">&laquo; Prev</span>
                {% endif %}

                {% for page_num in range(1, total_pages + 1) %}
                    {% if page_num == current_page %}
                        <span class="current">{{ page_num }}</span>
                    {# Show nearby pages, and always first/last page with ellipsis if needed #}
                    {% elif page_num == 1 or page_num == total_pages or (page_num >= current_page - 2 and page_num <= current_page + 2) %}
                        {# Add ellipsis if not adjacent to shown numbers and not first/last page #}
                        {% if page_num == 1 and current_page > 4 and current_page - 2 > 2 %} {# Ellipsis after first page #}
                            <span>...</span>
                        {% elif page_num == total_pages and current_page < total_pages - 3 and current_page + 2 < total_pages -1 %} {# Ellipsis before last page #}
                            <span>...</span>
                        {% endif %}
                        <a href="{{ url_for('list_server_logs_paginated', server_name=server_name, page=page_num) }}">{{ page_num }}</a>
                    {% elif (page_num == current_page - 3 and current_page > 4) or (page_num == current_page + 3 and current_page < total_pages - 3) %} {# Ensure ellipsis is shown once #}
                        <span>...</span>
                    {% endif %}
                {% endfor %}

                {% if current_page < total_pages %}
                    <a href="{{ url_for('list_server_logs_paginated', server_name=server_name, page=current_page+1) }}">Next &raquo;</a>
                {% else %}
                    <span class="disabled">Next &raquo;</span>
                {% endif %}
            </div>
            {% endif %}
        {% else %}
            <p>No log files found in the 'logs' directory for server '{{ server_name }}', or the directory is not accessible.</p>
            <p>Expected path: {{ server_logs_path }}</p>
        {% endif %}
        <a href="{{ url_for('index') }}" class="back-link">Back to Main Panel</a>
    </div>
    <script>
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const html = document.documentElement;
            html.classList.toggle('dark-mode');
            const theme = html.classList.contains('dark-mode') ? 'dark' : 'light';
            localStorage.setItem('theme', theme);
        });
    </script>
</body>
</html>
"""

SERVER_LOG_VIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View Log: {{ log_filename }} ({{ server_name }}) - Server Control Panel</title>
    <link rel="icon" href="{{ url_for('favicon') }}">
    <script>
        // Apply theme immediately to prevent flashing
        (function() {
            const theme = localStorage.getItem('theme') || 'light';
            if (theme === 'dark') {
                document.documentElement.classList.add('dark-mode');
            }
        })();
    </script>
    <style>
        :root {
            --bg-color: #f4f4f4;
            --text-color: #333;
            --navbar-bg: #333;
            --navbar-text: white;
            --navbar-hover: #555;
            --container-bg: #fff;
            --header-color: #555;
            --border-color: #eee;
            --button-bg: #6c757d;
            --button-hover-bg: #5a6268;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            --log-bg: #222;
            --log-text: #eee;
            --log-border: #444;
        }

        .dark-mode {
            --bg-color: #1a1a1a;
            --text-color: #e0e0e0;
            --navbar-bg: #252525;
            --navbar-text: #e0e0e0;
            --navbar-hover: #444;
            --container-bg: #2c2c2c;
            --header-color: #ccc;
            --border-color: #444;
            --button-bg: #555;
            --button-hover-bg: #777;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.3);
            /* Log colors are already dark, so they don't need to change much */
        }

        ::-webkit-scrollbar { width: 12px; height: 12px; }
        ::-webkit-scrollbar-button { display: none; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background-color: rgba(255,255,255,0.2);
            border-radius: 20px;
            border: 3px solid transparent;
            background-clip: content-box;
        }
        ::-webkit-scrollbar-thumb:hover { background-color: rgba(255,255,255,0.3); }

        body { font-family: sans-serif; line-height: 1.6; margin: 0; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.2s, color 0.2s; }
        .navbar { background-color: var(--navbar-bg); padding: 10px 20px; color: var(--navbar-text); display: flex; justify-content: space-between; align-items: center; }
        .navbar .left-nav, .navbar .right-nav { display: flex; align-items: center; gap: 15px; }
        .navbar a { color: var(--navbar-text); text-decoration: none; padding: 5px 10px; border-radius: 4px; }
        .navbar a:hover { background-color: var(--navbar-hover); }
        #theme-toggle { background: none; border: 1px solid var(--navbar-text); color: var(--navbar-text); cursor: pointer; border-radius: 5px; padding: 5px 8px; font-size: 1.2em; }
        .container { max-width: 1200px; margin: 20px auto; background: var(--container-bg); padding: 20px; border-radius: 8px; box-shadow: var(--box-shadow); }
        h1 { color: var(--header-color); border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 20px; }
        .log-content { background-color: var(--log-bg); color: var(--log-text); font-family: 'Courier New', Courier, monospace; padding: 15px; border-radius: 5px; margin-top: 10px; max-height: 70vh; overflow-y: scroll; white-space: pre-wrap; font-size: 0.85em; border: 1px solid var(--log-border); }
        .back-link { display: inline-block; margin-top: 20px; padding: 8px 15px; background-color: var(--button-bg); color: white; border-radius: 4px; text-decoration: none; }
        .back-link:hover { background-color: var(--button-hover-bg); }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="left-nav">
            <span>Server Manager - Log Viewer</span>
        </div>
        <div class="right-nav">
            <a href="{{ url_for('list_server_logs_default', server_name=server_name) }}">Back to {{ server_name }} Logs</a>
            <a href="{{ url_for('index') }}">Main Panel</a>
            <span>Welcome, {{ current_user.username }}!</span>
            <a href="{{ url_for('logout') }}">Logout</a>
            <button id="theme-toggle">◐</button>
        </div>
    </div>
    <div class="container">
        <h1>Log: {{ log_filename }} <small>(Server: {{ server_name }})</small></h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class="flash-messages">
                {% for category, message in messages %}
                    <li class="flash-{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}
        <div class="log-content">
            {{ log_content }}
        </div>
        <a href="{{ url_for('list_server_logs_default', server_name=server_name) }}" class="back-link">Back to {{ server_name }} Log List</a>
    </div>
    <script>
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const html = document.documentElement;
            html.classList.toggle('dark-mode');
            const theme = html.classList.contains('dark-mode') ? 'dark' : 'light';
            localStorage.setItem('theme', theme);
        });
    </script>
</body>
</html>
"""


@app.route("/server/<server_name>/logs/", defaults={"page": 1}, endpoint="list_server_logs_default")
@app.route("/server/<server_name>/logs/page/<int:page>", endpoint="list_server_logs_paginated")
@login_required
def list_server_logs(server_name, page):
    servers = get_server_folders()
    if server_name not in servers:
        flash(f"Server '{server_name}' not found.", "danger")
        return redirect(url_for("index"))

    server_path = os.path.join(SERVERS_BASE_DIR, server_name)
    server_logs_path = os.path.join(server_path, "logs")

    if not os.path.isdir(server_logs_path):
        flash(f"Logs directory not found for server '{server_name}' at {server_logs_path}", "warning")
        return render_template_string(
            SERVER_LOGS_LIST_TEMPLATE,
            server_name=server_name,
            log_files=[],
            current_page=1,
            total_pages=0,
            server_logs_path=server_logs_path,
            username=current_user.username,
        )

    all_log_files_details = []
    try:
        for item_name in os.listdir(server_logs_path):
            if item_name.endswith((".log", ".log.gz")):  # NOTE: Filter for log files
                full_path = os.path.join(server_logs_path, item_name)
                if os.path.isfile(full_path):
                    try:
                        stat_info = os.stat(full_path)
                        all_log_files_details.append(
                            {
                                "name": item_name,
                                "modified_time_obj": datetime.fromtimestamp(stat_info.st_mtime),  # For sorting
                                "size": stat_info.st_size,
                            }
                        )
                    except OSError as e:
                        print(f"Could not stat file {full_path} for server {server_name}: {e}")
                        flash(f"Could not access metadata for {item_name} in {server_name}'s logs.", "warning")

        # NOTE: Sort logs by modification time (datetime object), newest first.
        all_log_files_details.sort(key=lambda x: x["modified_time_obj"], reverse=True)

        # NOTE: Convert datetime to string for display after sorting
        for log_file in all_log_files_details:
            log_file["modified_time"] = log_file["modified_time_obj"].strftime("%Y-%m-%d %H:%M:%S")
            del log_file["modified_time_obj"]  # Remove temporary sort key

    except OSError as e:
        flash(f"Error reading logs directory for server '{server_name}': {e}", "danger")
        print(f"Error reading logs directory {server_logs_path}: {e}")
        return render_template_string(
            SERVER_LOGS_LIST_TEMPLATE,
            server_name=server_name,
            log_files=[],
            current_page=1,
            total_pages=0,
            server_logs_path=server_logs_path,
            username=current_user.username,
        )

    total_files = len(all_log_files_details)
    total_pages = (total_files + LOGS_PER_PAGE - 1) // LOGS_PER_PAGE
    # NOTE: Ensure current_page is within valid bounds
    current_page = max(1, min(page, total_pages if total_pages > 0 else 1))

    start_index = (current_page - 1) * LOGS_PER_PAGE
    end_index = start_index + LOGS_PER_PAGE
    paginated_log_files = all_log_files_details[start_index:end_index]

    return render_template_string(
        SERVER_LOGS_LIST_TEMPLATE,
        server_name=server_name,
        log_files=paginated_log_files,
        current_page=current_page,
        total_pages=total_pages,
        server_logs_path=server_logs_path,  # Pass for display if no logs found
        username=current_user.username,
    )


@app.route("/server/<server_name>/logs/view/<path:log_filename>")
@login_required
def view_server_log_file(server_name, log_filename):
    servers = get_server_folders()
    if server_name not in servers:
        flash(f"Server '{server_name}' not found.", "danger")
        return redirect(url_for("index"))

    server_path = os.path.join(SERVERS_BASE_DIR, server_name)
    server_logs_path = os.path.join(server_path, "logs")

    # NOTE: Security: Normalize paths and check if the requested file is within the server's log directory
    normalized_server_logs_path = os.path.abspath(server_logs_path)
    # NOTE: Ensure log_filename is treated as a relative path component and re-join with the normalized log path
    # This helps prevent issues if log_filename somehow contains '..'
    requested_log_file_path = os.path.abspath(os.path.join(normalized_server_logs_path, os.path.basename(log_filename)))

    if (
        not requested_log_file_path.startswith(normalized_server_logs_path)
        or not os.path.isfile(requested_log_file_path)
        or not (log_filename.endswith(".log") or log_filename.endswith(".log.gz"))
    ):  # Ensure it's a log file
        abort(
            404, f"Log file '{log_filename}' not found, is not a valid log file, or access denied for server '{server_name}'."
        )

    content = ""
    try:
        if log_filename.endswith(".gz"):
            with gzip.open(requested_log_file_path, "rt", encoding="utf-8", errors="replace") as f:
                content = f.read()
        else:
            with open(requested_log_file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
    except Exception as e:
        flash(f"Error reading log file '{log_filename}' for server '{server_name}': {e}", "danger")
        print(f"Error reading log file {requested_log_file_path}: {e}")
        content = f"--- ERROR READING FILE ---\n{e}\nPath: {requested_log_file_path}"  # Add path for debugging

    return render_template_string(
        SERVER_LOG_VIEW_TEMPLATE,
        server_name=server_name,
        log_filename=log_filename,
        log_content=content,
        username=current_user.username,
    )


# --- HTML Templates ---

"""
            text-shadow:
                -1px -1px 0 #000,
                 1px -1px 0 #000,
                -1px  1px 0 #000,
                 1px  1px 0 #000,
                -1px  0   0 #000,
                 1px  0   0 #000,
                 0   -1px 0 #000,
                 0    1px 0 #000;
"""

# Template for the main control panel
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Control Panel</title>
    <link rel="icon" href="{{ url_for('favicon') }}">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@2.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <script>
        // Apply theme immediately to prevent flashing
        (function() {
            const theme = localStorage.getItem('theme') || 'light';
            if (theme === 'dark') {
                document.documentElement.classList.add('dark-mode');
            }
        })();
    </script>
    <style>
        :root {
            --bg-color: #f4f4f4;
            --text-color: #333;
            --navbar-bg: #333;
            --navbar-text: white;
            --navbar-hover: #555;
            --container-bg: #fff;
            --header-color: #555;
            --border-color: #eee;
            --server-item-bg: #e9e9e9;
            --server-motd-color: #6c757d;
            --input-bg: white;
            --input-border: #ccc;
            --input-text: #333;
            --status-text: #666;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.1);

            --flash-success-bg: #d4edda;
            --flash-success-text: #155724;
            --flash-success-border: #c3e6cb;
            --flash-danger-bg: #f8d7da;
            --flash-danger-text: #721c24;
            --flash-danger-border: #f5c6cb;
            --flash-info-bg: #d1ecf1;
            --flash-info-text: #0c5460;
            --flash-info-border: #bee5eb;
        }

        .dark-mode {
            --bg-color: #1a1a1a;
            --text-color: #e0e0e0;
            --navbar-bg: #252525;
            --navbar-text: #e0e0e0;
            --navbar-hover: #444;
            --container-bg: #2c2c2c;
            --header-color: #ccc;
            --border-color: #444;
            --server-item-bg: #3a3a3a;
            --server-motd-color: #aaa;
            --input-bg: #252525;
            --input-border: #555;
            --input-text: #e0e0e0;
            --status-text: #aaa;
            --box-shadow: 0 2px 5px rgba(0,0,0,0.3);

            --flash-success-bg: #2a4b37;
            --flash-success-text: #d4edda;
            --flash-success-border: #155724;
            --flash-danger-bg: #582a2e;
            --flash-danger-text: #f8d7da;
            --flash-danger-border: #721c24;
            --flash-info-bg: #2c5a68;
            --flash-info-text: #d1ecf1;
            --flash-info-border: #0c5460;
        }

        ::-webkit-scrollbar { width: 12px; height: 12px; }
        ::-webkit-scrollbar-button { display: none; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb {
            background-color: rgba(255,255,255,0.2);
            border-radius: 20px;
            border: 3px solid transparent;
            background-clip: content-box;
        }
        ::-webkit-scrollbar-thumb:hover { background-color: rgba(255,255,255,0.3); }

        body { font-family: sans-serif; line-height: 1.6; margin: 0; background-color: var(--bg-color); color: var(--text-color); transition: background-color 0.2s, color 0.2s; }
        .navbar { background-color: var(--navbar-bg); padding: 10px 20px; color: var(--navbar-text); display: flex; justify-content: space-between; align-items: center; }
        .navbar .left-nav, .navbar .right-nav { display: flex; align-items: center; gap: 15px; }
        .navbar a { color: var(--navbar-text); text-decoration: none; padding: 5px 10px; border-radius: 4px; }
        .navbar a:hover { background-color: var(--navbar-hover); }
        #theme-toggle { background: none; border: 1px solid var(--navbar-text); color: var(--navbar-text); cursor: pointer; border-radius: 5px; padding: 5px 8px; font-size: 1.2em; }
        .container { max-width: 900px; margin: 20px auto; background: var(--container-bg); padding: 20px; border-radius: 8px; box-shadow: var(--box-shadow); }
        h1, h2 { color: var(--header-color); border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 20px; }
        .flash-messages { list-style: none; padding: 0; margin-bottom: 15px; }
        .flash-messages li { padding: 10px 15px; margin-bottom: 10px; border-radius: 4px; }
        .flash-success { background-color: var(--flash-success-bg); color: var(--flash-success-text); border: 1px solid var(--flash-success-border); }
        .flash-danger { background-color: var(--flash-danger-bg); color: var(--flash-danger-text); border: 1px solid var(--flash-danger-border); }
        .flash-info { background-color: var(--flash-info-bg); color: var(--flash-info-text); border: 1px solid var(--flash-info-border); }
        .server-list { list-style: none; padding: 0; }
        .server-item { background: var(--server-item-bg); margin-bottom: 15px; padding: 15px; border-radius: 5px; display: flex; flex-direction: column; gap: 10px; position: relative; }
        .server-controls { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: nowrap; }
        .server-details-container { display: flex; align-items: center; gap: 10px; flex-grow: 1; min-width: 0; }
        .server-icon { width: 64px; height: 64px; image-rendering: pixelated; margin-right: 10px; border-radius: 4px; flex-shrink: 0; }
        .server-name-motd { display: flex; flex-direction: column; min-width: 0; }
        .server-name { font-weight: bold; }
        .server-motd { color: var(--server-motd-color); font-size: 0.9em; font-family: 'Minecraftia', monospace; white-space: pre-wrap; word-break: break-all; }
        .server-actions { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
        button, input[type="text"], input[type="password"] { padding: 8px 12px; border-radius: 4px; font-size: 0.9em; }
        button { border: none; cursor: pointer; transition: background-color 0.2s ease; }
        input[type="text"], input[type="password"] { border: 1px solid var(--input-border); background-color: var(--input-bg); color: var(--input-text); }
        .start-button { background-color: #28a745; color: white; }
        .start-button:hover:not(:disabled) { background-color: #218838; }
        .stop-button { background-color: #dc3545; color: white; }
        .force-stop-button { background-color: #b32532; color: white; display: none; }
        .stop-button:hover:not(:disabled) { background-color: #c82333; }
        .command-button { background-color: #007bff; color: white; }
        .command-button:hover:not(:disabled) { background-color: #0056b3; }
        .logs-button { background-color: #17a2b8; color: white; }
        .public-button { background-color: #6c757d; color: white; }
        .logs-button, .public-button { text-decoration: none; padding: 8px 12px; border-radius: 4px; font-size: 0.9em; display: inline-block; line-height: normal; vertical-align: middle; }
        .logs-button:hover { background-color: #138496; }
        .public-button:hover { background-color: #5a6268; }
        button:disabled { background-color: #cccccc; cursor: not-allowed; }
        .dark-mode button:disabled { background-color: #555; color: #aaa; }
        .status { font-style: italic; color: var(--status-text); font-size: 0.9em; min-width: 80px; text-align: right; }
        .resource-monitor { background-color: rgba(0,0,0,0.1); padding: 5px 10px; border-radius: 4px; margin-top: 10px; cursor: pointer; transition: background-color 0.2s; }
        .dark-mode .resource-monitor { background-color: rgba(255,255,255,0.05); }
        .resource-monitor:hover { background-color: rgba(0,0,0,0.2); }
        .dark-mode .resource-monitor:hover { background-color: rgba(255,255,255,0.1); }
        .resource-item { display: inline-block; margin-right: 15px; font-size: 0.9em; }
        .resource-graph-container { margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border-color); display: none; }
        .command-section { margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border-color); display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
        .command-section input[type="text"], .command-section input[type="password"] { flex-grow: 1; min-width: 150px; }
        .output-area { background-color: #222; color: #eee; font-family: 'Courier New', Courier, monospace; padding: 15px; border-radius: 5px; margin-top: 10px; height: 300px; overflow-y: scroll; white-space: pre-wrap; font-size: 0.85em; border: 1px solid #444; word-break: break-all; }
        .output-area p { margin: 0 0 2px 0; padding: 0; line-height: 1.3; }
        .log-stdin { color: #e5e549; }
        .log-marker { color: #7bb5b5; }
        .log-error { color: #e54949; }
        .log-log { color: #90d690; }
        .output-container { position: relative; }
        .scroll-to-bottom { position: absolute; bottom: 10px; right: 10px; background-color: #007bff; color: white; border: none; border-radius: 50%; width: 40px; height: 40px; font-size: 24px; cursor: pointer; display: none; }
        .output-title { font-weight: bold; margin-bottom: 5px; color: #bbb; }
        .server-port-display { position: absolute; top: 5px; right: 5px; font-size: 0.8em; font-family: monospace; color: var(--status-text); background-color: rgba(0,0,0,0.05); padding: 2px 6px; border-radius: 3px; display: none; z-index: 10; }
        .dark-mode .server-port-display { background-color: rgba(255,255,255,0.05); }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="left-nav">
            <span>Server Manager</span>
        </div>
        <div class="right-nav">
            <span>Welcome, {{ username }}!</span>
            <a href="{{ url_for('logout') }}">Logout</a>
            <button id="theme-toggle">◐</button>
        </div>
    </div>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class="flash-messages">
                {% for category, message in messages %}
                    <li class="flash-{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}

        <h1>Server Control Panel</h1>
        <h2>Available Servers</h2>
        <ul class="server-list">
            {% if servers %}
                {% for server in servers %}
                <li class="server-item" id="server-{{ server }}">
                    <div class="server-controls">
                        <div class="server-details-container">
                            {% if server_details[server]['icon'] %}
                                <img src="{{ server_details[server]['icon'] }}" alt="Server Icon" class="server-icon">
                            {% endif %}
                            <div class="server-name-motd">
                                <span class="server-name">{{ server }}</span>
                                <span class="server-motd" data-motd="{{ server_details[server]['motd'] }}">{{ server_details[server]['motd'] }}</span>
                            </div>
                            {% if resource_monitor_enabled %}
                            <div class="resource-monitor" id="resource-monitor-{{ server }}" style="display: {% if server_status.get(server) %}block{% else %}none{% endif %};">
                                <span class="resource-item">CPU: <b id="cpu-{{ server }}">0.0</b>%</span>
                                <span class="resource-item">RAM: <b id="ram-{{ server }}">0 MB</b></span>
                            </div>
                            {% endif %}
                        </div>
                        <div class="server-actions">
                            <button class="start-button" data-server="{{ server }}" {% if server_status.get(server) %}disabled{% endif %}>Start</button>
                            <button class="stop-button" data-server="{{ server }}" {% if not server_status.get(server) %}disabled{% endif %}>Stop</button>
                            <button class="force-stop-button" data-server="{{ server }}">Force Stop</button>
                            <a href="{{ url_for('list_server_logs_default', server_name=server) }}" class="logs-button" data-server="{{ server }}">View Logs</a>
                            <a href="{{ url_for('list_public_files', server_name=server) }}" class="public-button" data-server="{{ server }}">Public Files</a>
                            <span class="status" id="status-{{ server }}">{% if server_status.get(server) %}Running{% else %}Stopped{% endif %}</span>
                        </div>
                    </div>
                    <div class="command-section" id="command-section-{{ server }}" style="display: {% if server_status.get(server) %}flex{% else %}none{% endif %};">
                        <input type="text" class="command-input" data-server="{{ server }}" placeholder="Enter command...">
                        <input type="password" class="command-password-input" data-server="{{ server }}" placeholder="Cmd Password...">
                        <button class="command-button" data-server="{{ server }}" {% if not server_status.get(server) %}disabled{% endif %}>&#10148;&#xFE0E; Send</button>
                    </div>
                    <div class="output-container">
                        <div class="output-area" id="output-{{ server }}" style="display: {% if server_status.get(server) %}block{% else %}none{% endif %};">
                            <div class="output-title">Output for {{ server }}:</div>
                        </div>
                        <button class="scroll-to-bottom" id="scroll-{{ server }}">&darr;</button>
                    </div>
                    {% if resource_monitor_enabled %}
                    <div class="resource-graph-container" id="resource-graph-container-{{ server }}">
                        <canvas id="resource-chart-{{ server }}"></canvas>
                    </div>
                    {% endif %}
                    <div class="server-port-display">{{ server_details[server]['port'] }}</div>
                </li>
                {% endfor %}
            {% else %}
                <li>No server folders found in the configured base directory or the directory doesn't exist.</li>
            {% endif %}
        </ul>
    </div>

    <script>
        const RESOURCE_MONITOR_INTERVAL = {{ resource_monitor_interval }};
        const MAX_RESOURCE_HISTORY = {{ max_resource_history }};

        // --- Theme Toggle ---
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const html = document.documentElement;
            html.classList.toggle('dark-mode');
            const theme = html.classList.contains('dark-mode') ? 'dark' : 'light';
            localStorage.setItem('theme', theme);
        });

        // --- JavaScript for handling buttons and SSE (Server-Sent Events) ---
        document.addEventListener('DOMContentLoaded', () => {
            function parseMotd(motd) {
                const colorMap = {
                    '0': '#000000', '1': '#000077', '2': '#007700', '3': '#007777',
                    '4': '#770000', '5': '#770077', '6': '#BB7700', '7': '#777777',
                    '8': '#383838', '9': '#3838BB', 'a': '#38BB38', 'b': '#38BBBB',
                    'c': '#BB3838', 'd': '#BB38BB', 'e': '#BBBB38', 'f': '#BBBBBB'
                };
                const styleMap = {
                    'l': 'font-weight: bold;',
                    'm': 'text-decoration: line-through;',
                    'n': 'text-decoration: underline;',
                    'o': 'font-style: italic;',
                    'k': 'minecraft-obfuscated' // Class for garbled text
                };

                const parts = motd.split(/(§[0-9a-fk-or])/);
                let html = '';
                let openSpans = 0;
                
                const closeSpans = () => {
                    while (openSpans > 0) {
                        html += '</span>';
                        openSpans--;
                    }
                };

                parts.forEach(part => {
                    if (!part) return;
                    if (part.startsWith('§')) {
                        const code = part[1];
                        if (colorMap[code]) {
                            closeSpans();
                            html += `<span style="color: ${colorMap[code]}">`;
                            openSpans++;
                        } else if (styleMap[code]) {
                            if (code === 'k') {
                                html += `<span class="${styleMap[code]}">`;
                            } else {
                                html += `<span style="${styleMap[code]}">`;
                            }
                            openSpans++;
                        } else if (code === 'r') {
                            closeSpans();
                        }
                    } else {
                        // Basic escaping for HTML
                        const escapedPart = part.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
                        html += escapedPart;
                    }
                });

                closeSpans();
                return html;
            }
            
            function obfuscateText() {
                // Find all elements that need to be garbled.
                const elements = document.querySelectorAll('.minecraft-obfuscated');
                if (elements.length === 0) return; // Exit if there's nothing to do.

                const allowedChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`';

                // Store the original text of each element in a data attribute.
                // This is needed to know the correct length for the garbled text.
                elements.forEach(el => {
                    el.dataset.originalText = el.textContent;
                });

                // Use a single interval to update all elements at once for better performance.
                setInterval(() => {
                    elements.forEach(element => {
                        const originalText = element.dataset.originalText;
                        if (!originalText) return;

                        let newText = '';
                        for (let j = 0; j < originalText.length; j++) {
                            // Preserve spaces, but garble everything else.
                            if (originalText[j] === ' ') {
                                newText += ' ';
                            } else {
                                const randomIndex = Math.floor(Math.random() * allowedChars.length);
                                newText += allowedChars[randomIndex];
                            }
                        }
                        element.textContent = newText;
                    });
                }, 50);
            }

            const serverItems = document.querySelectorAll('.server-item');
            let eventSources = {}; // SSE
            let resourceIntervals = {}; // Resource monitoring
            let resourceCharts = {};

            function formatBytes(bytes, decimals = 2) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const dm = decimals < 0 ? 0 : decimals;
                const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
            }

            serverItems.forEach(item => {
                const motdElement = item.querySelector('.server-motd');
                if (motdElement) {
                    const rawMotd = motdElement.getAttribute('data-motd');
                    motdElement.innerHTML = parseMotd(rawMotd);
                }
                const serverName = item.id.replace('server-', '');
                const startButton = item.querySelector('.start-button');
                const stopButton = item.querySelector('.stop-button');
                const forceStopButton = item.querySelector('.force-stop-button');
                const statusSpan = item.querySelector('.status');
                const outputArea = item.querySelector('.output-area');
                const commandSection = item.querySelector('.command-section');
                const commandInput = item.querySelector('.command-input');
                const commandPasswordInput = item.querySelector('.command-password-input');
                const commandButton = item.querySelector('.command-button');
                const resourceMonitor = item.querySelector('.resource-monitor');


                // --- Event Handlers ---
                startButton.addEventListener('click', () => handleStart(serverName));
                stopButton.addEventListener('click', () => handleStop(serverName));
                forceStopButton.addEventListener('click', () => handleForceStop(serverName));
                if (commandButton) {
                    commandButton.addEventListener('click', () => handleSendCommand(serverName));
                }
                if (resourceMonitor) {
                    resourceMonitor.addEventListener('click', () => {
                        const graphContainer = document.getElementById(`resource-graph-container-${serverName}`);
                        graphContainer.style.display = graphContainer.style.display === 'none' ? 'block' : 'none';
                    });
                }


                if (commandInput) {
                    commandInput.addEventListener('keydown', (event) => {
                        if (event.key === 'Enter') {
                            event.preventDefault();
                            handleSendCommand(serverName);
                        }
                    });
                }
 
 
                // --- Initial State ---
                if (statusSpan.textContent === 'Running') {
                    startListening(serverName);
                    const portDisplay = item.querySelector('.server-port-display');
                    if (portDisplay) portDisplay.style.display = 'block';
                }
            });
            
            obfuscateText();

            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'visible') {
                    console.log('Page is visible again, checking SSE connections.');
                    document.querySelectorAll('.server-item').forEach(item => {
                        const serverName = item.id.replace('server-', '');
                        const statusSpan = item.querySelector('.status');

                        if (statusSpan && (statusSpan.textContent === 'Running' || statusSpan.textContent === 'Stopping...' || statusSpan.textContent === 'Starting...')) {
                            const es = eventSources[serverName];
                            // 0=CONNECTING, 1=OPEN, 2=CLOSED
                            if (!es || es.readyState === 2) {
                                console.log(`SSE connection for ${serverName} is closed or missing. Reconnecting.`);
                                startListening(serverName);
                            }
                        }
                    });
                }
            });

            // --- Action Functions ---
            function handleStart(serverName) {
                console.log(`Starting ${serverName}...`);
                updateUI(serverName, 'starting', 'Starting...');
                fetch(`/start/${serverName}`, { method: 'POST' })
                    .then(response => {
                        if (!response.ok) {
                            return response.json().then(err => { throw new Error(err.message || `HTTP error ${response.status}`) });
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (data.status === 'success') {
                            console.log(`${serverName} started successfully.`);
                            updateUI(serverName, 'running', 'Running');
                            if (data.port) {
                                const item = document.getElementById(`server-${serverName}`);
                                const portDisplay = item.querySelector('.server-port-display');
                                if (portDisplay) {
                                    portDisplay.textContent = data.port;
                                }
                            }
                            startListening(serverName);
                        } else {
                            // This part might not be reached if response.ok is false, but good as a fallback
                            console.error(`Error starting ${serverName}:`, data.message);
                            alert(`Error starting ${serverName}: ${data.message}`);
                            updateUI(serverName, 'stopped', 'Error');
                        }
                    })
                    .catch(error => {
                        console.error('Error during start fetch:', error);
                        alert(`Error starting ${serverName}: ${error.message}`);
                        updateUI(serverName, 'stopped', 'Error');
                    });
            }

            function handleStop(serverName) {
                console.log(`Requesting graceful stop for ${serverName}...`);
                updateUI(serverName, 'stopping', 'Stopping...');
                fetch(`/stop/${serverName}`, { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            console.log(`Graceful stop for ${serverName} initiated.`);
                            // Show the "Force Stop" button
                            const forceStopButton = document.querySelector(`.force-stop-button[data-server="${serverName}"]`);
                            if (forceStopButton) forceStopButton.style.display = 'inline-block';
                        } else {
                            console.error(`Error initiating stop for ${serverName}:`, data.message);
                            alert(`Error initiating stop for ${serverName}: ${data.message}`);
                            updateUI(serverName, 'running', 'Running'); // Revert UI if stop command failed
                        }
                    })
                    .catch(error => {
                        console.error('Error during graceful stop fetch:', error);
                        alert(`Error initiating stop: ${error.message}`);
                        updateUI(serverName, 'running', 'Running');
                    });
            }

            function handleForceStop(serverName) {
                if (!confirm(`Are you sure you want to forcefully stop ${serverName}? This may cause data loss.`)) {
                    return;
                }
                console.log(`Forcing stop for ${serverName}...`);
                updateUI(serverName, 'stopping', 'Forcing Stop...');
                fetch(`/force_stop/${serverName}`, { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            console.log(`${serverName} force stop requested.`);
                            // UI will be fully updated by SSE
                        } else {
                            console.error(`Error force stopping ${serverName}:`, data.message);
                            alert(`Error force stopping ${serverName}: ${data.message}`);
                            updateUI(serverName, 'running', 'Error'); // Revert UI if it failed
                        }
                    })
                    .catch(error => {
                        console.error('Error during force stop fetch:', error);
                        alert(`Error force stopping: ${error.message}`);
                        updateUI(serverName, 'running', 'Error');
                    });
            }

            function handleSendCommand(serverName) {
                const item = document.getElementById(`server-${serverName}`);
                const commandInput = item.querySelector('.command-input');
                const commandPasswordInput = item.querySelector('.command-password-input');
                const commandButton = item.querySelector('.command-button');

                const commandText = commandInput.value.trim();
                const commandPassword = commandPasswordInput.value;

                if (!commandText) {
                    alert('Please enter a command.');
                    commandInput.focus();
                    return;
                }
                if (!commandPassword) {
                    alert('Please enter the command password.');
                    commandPasswordInput.focus();
                    return;
                }

                console.log(`Sending command to ${serverName}: ${commandText}`);
                commandButton.disabled = true; // Disable button during request

                fetch(`/command/${serverName}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        command: commandText,
                        command_password: commandPassword
                    })
                })
                .then(response => response.json()) // Assume server always returns JSON
                .then(data => {
                    if (data.status === 'success') {
                        console.log(`Command sent to ${serverName} successfully.`);
                        // commandInput.value = ''; // Clear command input on success
                        // commandPasswordInput.value = '';
                    } else {
                        console.error(`Error sending command to ${serverName}:`, data.message);
                        alert(`Error sending command: ${data.message}`);
                    }
                })
                .catch(error => {
                    console.error('Error during command fetch:', error);
                    alert(`Error sending command: ${error.toString()}`);
                })
                .finally(() => {
                    // Re-enable button only if server is still running
                    const statusSpan = document.getElementById(`status-${serverName}`);
                    if (statusSpan && (statusSpan.textContent === 'Running' || statusSpan.textContent === 'Starting...')) {
                        commandButton.disabled = false;
                    }
                });
            }

            function startResourceMonitor(serverName) {
                const cpuElement = document.getElementById(`cpu-${serverName}`);
                const ramElement = document.getElementById(`ram-${serverName}`);
                const ctx = document.getElementById(`resource-chart-${serverName}`).getContext('2d');

                const chartConfig = {
                    type: 'line',
                    data: {
                        datasets: [{
                            label: 'CPU (%)',
                            borderColor: 'rgba(255, 99, 132, 1)',
                            backgroundColor: 'rgba(255, 99, 132, 0.2)',
                            yAxisID: 'yCpu',
                            tension: 0.1,
                            data: []
                        }, {
                            label: 'RAM (MB)',
                            borderColor: 'rgba(54, 162, 235, 1)',
                            backgroundColor: 'rgba(54, 162, 235, 0.2)',
                            yAxisID: 'yRam',
                            tension: 0.1,
                            data: []
                        }]
                    },
                    options: {
                        responsive: true,
                        animation: false,
                        scales: {
                            x: {
                                type: 'time',
                                time: {
                                    unit: 'minute',
                                    displayFormats: {
                                        minute: 'HH:mm:ss'
                                    }
                                },
                                ticks: { color: document.documentElement.classList.contains('dark-mode') ? '#e0e0e0' : '#333' }
                            },
                            yCpu: {
                                position: 'left',
                                title: { display: true, text: 'CPU (%)', color: document.documentElement.classList.contains('dark-mode') ? '#e0e0e0' : '#333' },
                                ticks: { color: 'rgba(255, 99, 132, 1)' }
                            },
                            yRam: {
                                position: 'right',
                                title: { display: true, text: 'RAM (MB)', color: document.documentElement.classList.contains('dark-mode') ? '#e0e0e0' : '#333' },
                                ticks: { color: 'rgba(54, 162, 235, 1)' },
                                grid: { drawOnChartArea: false }
                            }
                        },
                        elements: {
                            point: {
                                radius: 0
                            }
                        },
                        plugins: {
                            legend: { labels: { color: document.documentElement.classList.contains('dark-mode') ? '#e0e0e0' : '#333' } }
                        }
                    }
                };

                if (resourceCharts[serverName]) {
                    resourceCharts[serverName].destroy();
                }
                resourceCharts[serverName] = new Chart(ctx, chartConfig);

                // Clear any old polling interval, just in case.
                if (resourceIntervals[serverName]) {
                    clearInterval(resourceIntervals[serverName]);
                    delete resourceIntervals[serverName];
                }

                // Fetch initial history once. Live updates will come from SSE.
                fetch(`/resources/${serverName}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'error') {
                            console.error(`Resource fetch error for ${serverName}:`, data.message);
                            return;
                        }
                        cpuElement.textContent = data.cpu.latest.toFixed(1);
                        ramElement.textContent = formatBytes(data.ram.latest);

                        const chart = resourceCharts[serverName];
                        if (chart) {
                            chart.data.datasets[0].data = data.cpu.history.map(d => ({ x: d[0], y: d[1] }));
                            chart.data.datasets[1].data = data.ram.history.map(d => ({ x: d[0], y: d[1] / (1024*1024) })); // Convert to MB
                            chart.update('quiet');
                        }
                    })
                    .catch(error => console.error(`Error fetching resources for ${serverName}:`, error));
            }

            // --- Server-Sent Events (SSE) ---
            function startListening(serverName) {
                // Close existing connection if any
                stopListening(serverName);

                console.log(`Opening SSE connection for ${serverName}`);
                {% if resource_monitor_enabled %}
                startResourceMonitor(serverName);
                {% endif %}
                const outputArea = document.getElementById(`output-${serverName}`);
                const outputTitle = outputArea.querySelector('.output-title');
                outputArea.style.display = 'block'; // Show output area
                // Clear previous output except title
                outputArea.innerHTML = ''; // Clear previous content entirely
                if (outputTitle) outputArea.appendChild(outputTitle); // Re-add the title if it exists

                const es = new EventSource(`/output/${serverName}`);
                eventSources[serverName] = es;

                let userHasScrolled = false;

                outputArea.addEventListener('scroll', () => {
                    // If user scrolls up, disable auto-scrolling and show the button
                    const isAtBottom = outputArea.scrollHeight - outputArea.clientHeight <= outputArea.scrollTop + 1;
                    const scrollToBottomButton = document.getElementById(`scroll-${serverName}`);
                   
                    if (!isAtBottom) {
                        userHasScrolled = true;
                        scrollToBottomButton.style.display = 'block';
                    } else {
                        // If user scrolls back to the bottom, re-enable auto-scrolling
                        userHasScrolled = false;
                        scrollToBottomButton.style.display = 'none';
                    }
                });

                es.addEventListener('resources', event => {
                    const data = JSON.parse(event.data);
                    const cpuElement = document.getElementById(`cpu-${serverName}`);
                    const ramElement = document.getElementById(`ram-${serverName}`);

                    if (cpuElement) cpuElement.textContent = data.cpu.toFixed(1);
                    if (ramElement) ramElement.textContent = formatBytes(data.ram);

                    const chart = resourceCharts[serverName];
                    if (chart) {
                        const datasetCpu = chart.data.datasets[0].data;
                        const datasetRam = chart.data.datasets[1].data;

                        datasetCpu.push({ x: data.timestamp, y: data.cpu });
                        datasetRam.push({ x: data.timestamp, y: data.ram / (1024*1024) }); // Convert to MB

                        // Prune old data points to prevent memory leak and keep chart clean
                        while (datasetCpu.length > MAX_RESOURCE_HISTORY) {
                            datasetCpu.shift();
                        }
                        while (datasetRam.length > MAX_RESOURCE_HISTORY) {
                            datasetRam.shift();
                        }

                        chart.update('quiet');
                    }
                });

                es.addEventListener('message', event => {
                    const line = document.createElement('p');
                    const message = event.data;

                    // Check for our special style prefix
                    if (message.startsWith('STY:')) {
                        // Split into parts: "STY", "type", "actual message"
                        const parts = message.split(':');
                        const type = parts[1]; // e.g., "stdin", "marker", "error", "log"
                        parts.splice(0, 2);
                        const text = parts.join(':');
                        line.textContent = text;
                        line.classList.add(`log-${type}`); // Apply the CSS class
                    } else {
                        line.textContent = message; // stdout/stderr
                    }

                    outputArea.appendChild(line);

                    // Auto-scroll if the user hasn't manually scrolled up
                    if (!userHasScrolled) {
                        outputArea.scrollTop = outputArea.scrollHeight;
                    }
                });

                const scrollToBottomButton = document.getElementById(`scroll-${serverName}`);
                scrollToBottomButton.addEventListener('click', () => {
                    userHasScrolled = false; // Re-enable auto-scrolling
                    outputArea.scrollTop = outputArea.scrollHeight;
                    scrollToBottomButton.style.display = 'none';
                });

                es.addEventListener('status', event => {
                    console.log(`Status update for ${serverName}: ${event.data}`);
                    const status = event.data.toLowerCase(); // e.g., "finished", "stopped", "not found"
                    updateUI(serverName, (status === 'finished' || status === 'stopped' || status === 'not found') ? 'stopped' : 'running', event.data);
                });

                es.addEventListener('close', event => {
                    console.log(`SSE stream closed by server for ${serverName}: ${event.data}`);
                    stopListening(serverName);
                });


                es.onerror = (err) => {
                    console.error(`EventSource failed for ${serverName}:`, err);
                    // Update UI to reflect potential stopped state if connection is lost abruptly
                    const statusSpan = document.getElementById(`status-${serverName}`);
                    if (statusSpan && statusSpan.textContent !== 'Stopped' && statusSpan.textContent !== 'Finished') {
                        updateUI(serverName, 'stopped', 'Comms Error');
                    }
                    stopListening(serverName);
                };
            }

            function stopListening(serverName) {
                if (eventSources[serverName]) {
                    console.log(`Closing SSE connection for ${serverName}`);
                    eventSources[serverName].close();
                    delete eventSources[serverName];
                }
                if (resourceIntervals[serverName]) {
                    console.log(`Stopping resource monitor for ${serverName}`);
                    clearInterval(resourceIntervals[serverName]);
                    delete resourceIntervals[serverName];
                }
                if (resourceCharts[serverName]) {
                    // The chart is intentionally left in its final state.
                    // The polling interval is cleared, so it will no longer update.
                }
            }

            // --- UI Update Function ---
            function updateUI(serverName, state, statusText) {
                const item = document.getElementById(`server-${serverName}`);
                if (!item) return;

                const startButton = item.querySelector('.start-button');
                const stopButton = item.querySelector('.stop-button');
                const forceStopButton = item.querySelector('.force-stop-button');
                const statusSpan = item.querySelector('.status');
                const outputArea = item.querySelector('.output-area');
                const commandSection = item.querySelector('.command-section');
                const commandButton = item.querySelector('.command-button');
                const commandInput = item.querySelector('.command-input');
                const commandPasswordInput = item.querySelector('.command-password-input');
                const resourceMonitor = item.querySelector('.resource-monitor');
                const resourceGraphContainer = item.querySelector('.resource-graph-container');
                const portDisplay = item.querySelector('.server-port-display');


                statusSpan.textContent = statusText;

                switch (state) {
                    case 'running':
                        startButton.disabled = true;
                        stopButton.disabled = false;
                        if (forceStopButton) forceStopButton.style.display = 'none';
                        outputArea.style.display = 'block';
                        if(commandSection) commandSection.style.display = 'flex';
                        if(commandButton) commandButton.disabled = false;
                        if(commandInput) commandInput.disabled = false;
                        if(commandPasswordInput) commandPasswordInput.disabled = false;
                        if(resourceMonitor) resourceMonitor.style.display = 'block';
                        if(portDisplay) portDisplay.style.display = 'block';
                        break;
                    case 'stopped':
                        startButton.disabled = false;
                        stopButton.disabled = true;
                        if (forceStopButton) forceStopButton.style.display = 'none';
                        if(commandSection) commandSection.style.display = 'none';
                        if(commandButton) commandButton.disabled = true;
                        if(commandInput) commandInput.disabled = true;
                        if(commandPasswordInput) commandPasswordInput.disabled = true;
                        if(portDisplay) portDisplay.style.display = 'none';
                        // Keep the resource monitor and graph visible in their last state.
                        // The user can still interact with them (e.g., close the graph).
                        // Keep output area visible after run
                        break;
                    case 'starting':
                    case 'stopping':
                        startButton.disabled = true;
                        stopButton.disabled = true;
                        if(commandButton) commandButton.disabled = true;
                        if(commandInput) commandInput.disabled = true;
                        if(commandPasswordInput) commandPasswordInput.disabled = true;
                        if(portDisplay) portDisplay.style.display = 'block';
                        if(commandSection && state === 'stopping') {
                            // Keep command section visible during stopping if it was already visible
                        } else if (commandSection) {
                            commandSection.style.display = 'none';
                        }
                        break;
                }
            }
        });
    </script>
</body>
</html>
"""

# Template for the Login Page
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Server Control Panel</title>
    <link rel="icon" href="{{ url_for('favicon') }}">
    <script>
        // Apply theme immediately to prevent flashing
        (function() {
            const theme = localStorage.getItem('theme') || 'light';
            if (theme === 'dark') {
                document.documentElement.classList.add('dark-mode');
            }
        })();
    </script>
    <style>
        :root {
            --bg-color: #f4f4f4;
            --text-color: #333;
            --login-bg: #fff;
            --header-color: #555;
            --input-bg: white;
            --input-border: #ccc;
            --input-text: #333;
            --button-bg: #007bff;
            --button-hover: #0056b3;
            --box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            --flash-danger-bg: #f8d7da;
            --flash-danger-text: #721c24;
            --flash-danger-border: #f5c6cb;
            --flash-info-bg: #d1ecf1;
            --flash-info-text: #0c5460;
            --flash-info-border: #bee5eb;
        }
        .dark-mode {
            --bg-color: #1a1a1a;
            --text-color: #e0e0e0;
            --login-bg: #2c2c2c;
            --header-color: #ccc;
            --input-bg: #252525;
            --input-border: #555;
            --input-text: #e0e0e0;
            --button-bg: #007bff;
            --button-hover: #0056b3;
            --box-shadow: 0 4px 10px rgba(0,0,0,0.3);
            --flash-danger-bg: #582a2e;
            --flash-danger-text: #f8d7da;
            --flash-danger-border: #721c24;
            --flash-info-bg: #2c5a68;
            --flash-info-text: #d1ecf1;
            --flash-info-border: #0c5460;
        }
        ::-webkit-scrollbar { width: 12px; }
        ::-webkit-scrollbar-track { background: var(--bg-color); }
        ::-webkit-scrollbar-thumb {
            background-color: #555;
            border-radius: 20px;
            border: 3px solid var(--bg-color);
        }
        body { font-family: sans-serif; background-color: var(--bg-color); color: var(--text-color); display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; transition: background-color 0.2s, color 0.2s; }
        .login-container { background: var(--login-bg); padding: 30px 40px; border-radius: 8px; box-shadow: var(--box-shadow); text-align: center; width: 100%; max-width: 400px; position: relative; }
        #theme-toggle { position: absolute; top: 10px; right: 10px; background: none; border: 1px solid var(--text-color); color: var(--text-color); cursor: pointer; border-radius: 50%; width: 30px; height: 30px; font-size: 1.2em; line-height: 1; padding: 0; }
        h1 { color: var(--header-color); margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; text-align: left; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: var(--text-color); }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid var(--input-border); background-color: var(--input-bg); color: var(--input-text); border-radius: 4px; box-sizing: border-box; }
        .remember-me { margin-bottom: 20px; text-align: left; display: flex; align-items: center; }
        .remember-me input { margin-right: 5px; }
        button { background-color: var(--button-bg); color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; width: 100%; transition: background-color 0.2s ease; }
        button:hover { background-color: var(--button-hover); }
        .flash-messages { list-style: none; padding: 0; margin-bottom: 15px; }
        .flash-messages li { padding: 10px 15px; margin-bottom: 10px; border-radius: 4px; text-align: center; }
        .flash-danger { background-color: var(--flash-danger-bg); color: var(--flash-danger-text); border: 1px solid var(--flash-danger-border); }
        .flash-info { background-color: var(--flash-info-bg); color: var(--flash-info-text); border: 1px solid var(--flash-info-border); }
    </style>
</head>
<body>
    <div class="login-container">
        <button id="theme-toggle">◐</button>
        <h1>Server Manager Login</h1>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul class="flash-messages">
                {% for category, message in messages %}
                    <li class="flash-{{ category }}">{{ message }}</li>
                {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}

        <form method="POST" action="{{ url_for('login') }}">
            {{ form.csrf_token if form and form.csrf_token }} <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="remember-me">
                <input type="checkbox" id="remember" name="remember">
                <label for="remember">Remember Me</label>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        document.getElementById('theme-toggle').addEventListener('click', () => {
            const html = document.documentElement;
            html.classList.toggle('dark-mode');
            const theme = html.classList.contains('dark-mode') ? 'dark' : 'light';
            localStorage.setItem('theme', theme);
        });
    </script>
</body>
</html>
"""


# --- Cleanup and Signal Handling ---
def cleanup_processes():
    """Attempts to stop all running server processes."""
    global running_processes
    global shutting_down

    if shutting_down:  # Avoid re-entry if already called
        return

    shutting_down = True
    print(" - Initiating shutdown of all running server subprocesses...")

    server_names_to_stop = list(running_processes.keys())

    for server_name in server_names_to_stop:
        process_info = running_processes.get(server_name)
        if process_info and process_info.get("process"):
            process = process_info["process"]
            with process_info["lock"]:
                if process.poll() is None:
                    print(f" - Stopping server {server_name} (PID: {process.pid}):")
                    process_info["stop_requested"] = True
                    if "output" in process_info:
                        process_info["output"].append("STY:marker:--- MAIN APP SHUTDOWN: STOP REQUESTED ---")

                    try:
                        # Using Popen for taskkill to allow timeout and non-blocking
                        kill_proc = subprocess.Popen(
                            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        try:
                            kill_proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            print(
                                f"   - taskkill for {server_name} (PID: {process.pid}) timed out. Process might still be terminating."
                            )
                            kill_proc.kill()

                        # Check process status after attempting taskkill
                        if process.poll() is None:
                            print(
                                f"   - Process {process.pid} for {server_name} did not terminate via taskkill, forcing kill..."
                            )
                            process.kill()  # Force kill the original process
                            try:
                                process.wait(timeout=5)  # Wait for forced kill
                            except subprocess.TimeoutExpired:
                                print(f"   - Forced kill for {server_name} (PID: {process.pid}) timed out.")

                        status = "stopped" if process.poll() is not None else "failed to stop"
                        if "output" in process_info:
                            process_info["output"].append(f"STY:marker:--- MAIN APP SHUTDOWN: SCRIPT {status.upper()} ---")
                        print(f"   - Server {server_name} {status} during main app shutdown")
                        process_info["process"] = None
                    except Exception as e:
                        print(f"   - Error stopping {server_name} during main app shutdown: {e}")
                        if "output" in process_info:
                            process_info["output"].append(f"STY:marker:--- MAIN APP SHUTDOWN: ERROR STOPPING SCRIPT: {e} ---")
                else:
                    if process_info.get("process") is None and "output" in process_info:
                        process_info["output"].append(
                            f"STY:marker:--- MAIN APP SHUTDOWN: Server {server_name} already stopped or not fully started ---"
                        )
                    print(f" - Server {server_name} already stopped")

    print("All subprocesses handled")

    # --- UPnP Cleanup ---
    if UPNP_ENABLED and upnp_mappings:
        print(" - Cleaning up all UPnP port mappings...")
        all_ports = list(upnp_mappings.values())
        for port in all_ports:
            logs = remove_upnp_port_forwarding(port)
            for log in logs:
                # Strip the STY prefix for cleaner console logging
                clean_log = log.split(":", 2)[-1] if log.startswith("STY:") else log
                print(f"   - {clean_log}")
        upnp_mappings.clear()
        print(" - UPnP cleanup complete.")


def signal_handler(sig, frame):
    """Handles SIGINT (Ctrl+C) and SIGTERM for graceful shutdown."""
    print(f"Signal {signal.Signals(sig).name} received, initiating graceful shutdown...")
    cleanup_processes()
    print("Flask app exiting...")
    sys.exit(0)


# --- Main Execution ---
if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    try:
        signal.signal(signal.SIGTERM, signal_handler)
    except AttributeError:  # SIGTERM may not be available on all Windows versions/Python builds
        print("SIGTERM signal not available on this platform. SIGINT (Ctrl+C) is handled.")
    except ValueError:  # Can happen if trying to register a signal not supported
        print("Could not register SIGTERM handler. SIGINT (Ctrl+C) is handled.")

    # Basic validation
    if not os.path.isdir(SERVERS_BASE_DIR):
        print(f"ERROR: The specified servers base directory does not exist:")
        print(f"  '{SERVERS_BASE_DIR}'")
        print("Please create the directory or correct the SERVERS_BASE_DIR path in the script.")
        sys.exit(1)
    if PASSWORD == "password":
        print("WARNING: Default admin password is being used. Please change the PASSWORD variable in the script.")
    if COMMAND_PASSWORD == "cmdpass":
        print("WARNING: Default command password is being used. Please change the COMMAND_PASSWORD variable in the script.")
    if "FLASK_SECRET_KEY" not in os.environ and SECRET_KEY == _generated_secret_key_default:
        print(
            "INFO: Using a randomly generated SECRET_KEY for this session because FLASK_SECRET_KEY environment variable is not set. For consistent sessions across restarts, set this environment variable or a fixed value in the script."
        )

    print(f"Starting server control panel...")
    print(f" - Monitoring directory: {SERVERS_BASE_DIR}")
    print(f" - Looking for batch file: {BATCH_FILE_NAME}")
    print(f" - Access URL: http{'s' if os.path.exists(SSL_CERT_PATH) and os.path.exists(SSL_KEY_PATH) else ''}://{HOST}:{PORT}")
    print(f" - Login with user: {USERNAME}")
    print("Press CTRL+C to stop the server.")

    # Determine SSL context
    ssl_context = None
    if os.path.exists(SSL_CERT_PATH) and os.path.exists(SSL_KEY_PATH):
        ssl_context = (SSL_CERT_PATH, SSL_KEY_PATH)
        print(f" - SSL/TLS enabled using {SSL_CERT_PATH} and {SSL_KEY_PATH}")
        print("   (Note: Browser will likely show a warning for self-signed certificates)")
    else:
        print(" - SSL/TLS disabled (cert.pem or key.pem not found). Running over HTTP.")

    # Use Flask's development server (or deploy with a production server like Waitress/Gunicorn)
    try:
        # Use threaded=True to handle multiple requests (like SSE and actions) concurrently
        # use_reloader=False is important for custom signal handling to work reliably,
        # especially on Windows, as the reloader runs the app in a child process.

        if USE_SSL:
            app.run(host=HOST, port=PORT, debug=False, threaded=True, ssl_context=ssl_context, use_reloader=False)
        else:
            app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt caught in main __name__ block. Ensuring cleanup...")
        cleanup_processes()  # Ensure cleanup is attempted
    finally:
        if not shutting_down:  # If signal_handler wasn't called or didn't complete
            print("Application exiting without explicit signal handling completion. Attempting final cleanup...")
            cleanup_processes()
        print("Finished!")
