import os
import subprocess
import threading
import time
import shutil
import secrets
from dotenv import load_dotenv
from flask import Flask, render_template_string, request, Response, jsonify, stream_with_context, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
load_dotenv()  # Load from .env file if present

SERVERS_BASE_DIR = r"C:\\path\\to\\servers"              # !!! IMPORTANT: SET THIS PATH !!!
BATCH_FILE_NAME = "starter.bat"                          # Name of the batch file in each server folder
BACKUPS_DIR = "Backups"                                  # Name of the backup directory (relative to SERVERS_BASE_DIR)
HOST = "0.0.0.0"                                         # Listen on all network interfaces (Change to "127.0.0.1" for local access only)
PORT = 25564                                             # Port for the web server
USERNAME = "admin"                                       # Global username for login
PASSWORD = os.getenv("PASSWORD", "password")             # !!! CHANGE THIS PASSWORD !!!
COMMAND_PASSWORD = os.getenv("CMD_PASSWORD", "cmdpass")  # !!! CHANGE THIS COMMAND PASSWORD !!!
# Generate a strong secret key. Keep this key secret and consistent across restarts.
# For production, set this via environment variable or config file.
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(24))
# SSL Certificate (Optional - uncomment app.run line below to enable)
SSL_CERT_PATH = "C:\\Users\\Me\\cert.pem"  # "C:\\Users\\Me\\server.crt"
SSL_KEY_PATH = "C:\\Users\\Me\\key.pem"    # "C:\\Users\\Me\\server.key"
# ---------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# --- Rate Limiting Setup ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"], # General limits
    storage_uri="memory://", # Memory storage for simplicity
)

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Route name for the login page
login_manager.login_message_category = 'info' # Flash message category

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
        if user_id == '1':
             # IMPORTANT: Store the HASH of the password, not the plain password
            hashed_password = users_storage.get(USERNAME)
            if hashed_password:
                return User(id='1', username=USERNAME, password_hash=hashed_password)
        return None

# Store user credentials securely (using password hashes)
users_storage = {
    USERNAME: generate_password_hash(PASSWORD)
}
# Store command password hash
COMMAND_PASSWORD_HASH = generate_password_hash(COMMAND_PASSWORD)


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login callback to load a user from the 'database'."""
    return User.get(user_id)

# --- Process Management ---
# In-memory storage for running processes and their output
running_processes = {} # { 'server_name': {'process': Popen_object, 'output': ['line1', 'line2'], 'lock': threading.Lock(), 'stop_requested': False} }

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
    if server_name not in running_processes: return # Safety check

    process_info = running_processes[server_name]

    try:
        # Read stdout line by line
        for line in iter(process.stdout.readline, b''):
            decoded_line = line.decode(errors='replace').strip()
            with process_info['lock']:
                if not process_info['stop_requested']:
                    process_info['output'].append(decoded_line)
                else:
                    break # Exit if stop was requested
            # time.sleep(0.01) # Optional sleep

        for line in iter(process.stderr.readline, b''):
             decoded_line = f"ERROR: {line.decode(errors='replace').strip()}"
             with process_info['lock']:
                 if not process_info['stop_requested']:
                     process_info['output'].append(decoded_line)
                 else:
                     break
             # time.sleep(0.01)

    except Exception as e:
        print(f"Error reading output for {server_name}: {e}")
        with process_info['lock']:
             # Check if still exists before appending
             if server_name in running_processes:
                 running_processes[server_name]['output'].append(f"--- Error reading output: {e} ---")
    finally:
        if process:
            if process.stdout: process.stdout.close()
            if process.stderr: process.stderr.close()
            process.wait()

        print(f"Output reading thread finished for {server_name}")
        # Safely update status if the process entry still exists
        if server_name in running_processes:
            with running_processes[server_name]['lock']:
                if not running_processes[server_name]['stop_requested']:
                     running_processes[server_name]['output'].append("--- SCRIPT FINISHED ---")
                     # Keep the entry but mark process as None to indicate it finished
                     running_processes[server_name]['process'] = None

# --- Backup Helper ---
def _log_to_server_output(server_name, message):
    """Helper to log messages to a specific server's output stream, displayed in the UI."""
    # NOTE: This is an internal helper.
    global running_processes
    if server_name in running_processes:
        process_info = running_processes[server_name]
        with process_info.get('lock', threading.Lock()): # Use existing lock or a temp one if somehow missing
            if 'output' in process_info:
                 process_info['output'].append(message)
            else:
                print(f"Warning: 'output' list not found for server {server_name} during backup logging.")
    else:
        print(f"Warning: Process info for server {server_name} not found during backup logging.")


def find_latest_backup_folder(backup_dir):
    """Finds the latest file or folder in the backup directory based on name sorting."""
    if not os.path.isdir(backup_dir):
        return None
    try:
        items = os.listdir(backup_dir)
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
    _log_to_server_output(server_name, "--- BACKUP START ---")
    source_backups_dir = os.path.join(server_path, 'backups')
    # SERVERS_BASE_DIR/BACKUPS_DIR
    target_parent_dir = os.path.abspath(os.path.join(SERVERS_BASE_DIR, BACKUPS_DIR))

    log_msg_checking = f"Checking for backups in: {source_backups_dir}"
    print(log_msg_checking)
    _log_to_server_output(server_name, log_msg_checking)
    latest_item_name = find_latest_backup_folder(source_backups_dir)

    if latest_item_name:
        log_msg_found = f"Found latest backup item: {latest_item_name}"
        print(log_msg_found)
        _log_to_server_output(server_name, log_msg_found)
        source_path = os.path.join(source_backups_dir, latest_item_name)
        is_source_dir = os.path.isdir(source_path)
        dest_item_name = f"{server_name}_{latest_item_name}"
        dest_path = os.path.join(target_parent_dir, dest_item_name)
        log_msg_attempting = f"Attempting to copy backup from '{source_path}' to '{dest_path}'"
        print(log_msg_attempting)
        _log_to_server_output(server_name, log_msg_attempting)

        try:
            os.makedirs(target_parent_dir, exist_ok=True)

            if os.path.exists(dest_path):
                skip_message = f"Destination backup item '{dest_item_name}' already exists. Skipping copy."
                print(f"Warning: {skip_message}")
                _log_to_server_output(server_name, skip_message)
                _log_to_server_output(server_name, "--- BACKUP COMPLETE ---")
                return f"Backup skipped (destination exists: {dest_item_name})"

            if is_source_dir:
                shutil.copytree(source_path, dest_path)
            else:
                shutil.copy2(source_path, dest_path) # copy2 preserves metadata

            success_message = f"Successfully copied backup '{dest_item_name}' to shared Backups."
            print(success_message)
            _log_to_server_output(server_name, success_message)
            _log_to_server_output(server_name, "--- BACKUP COMPLETE ---")
            return f"Backup copied ({dest_item_name})"
        except OSError as e:
            error_message = f"Error copying backup for {server_name}: {e}"
            print(error_message)
            _log_to_server_output(server_name, error_message)
            _log_to_server_output(server_name, "--- BACKUP COMPLETE ---")
            return f"Backup failed (Error: {e})"
        except Exception as e:
            error_message = f"Unexpected error during backup copy for {server_name}: {e}"
            print(error_message)
            _log_to_server_output(server_name, error_message)
            _log_to_server_output(server_name, "--- BACKUP COMPLETE ---")
            return f"Backup failed (Unexpected Error: {e})"
    else:
        not_found_message = f"No backup items found or accessible in {source_backups_dir}"
        print(not_found_message)
        _log_to_server_output(server_name, not_found_message)
        _log_to_server_output(server_name, "--- BACKUP COMPLETE ---")
        return "No backups found to copy"

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Apply rate limit specifically to login attempts
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        stored_password_hash = users_storage.get(username)
        user_obj = None
        if stored_password_hash:
             # Only create User object if username exists to check password
             temp_user = User(id='1', username=username, password_hash=stored_password_hash) # ID '1' is placeholder
             if check_password_hash(temp_user.password_hash, password):
                  user_obj = temp_user # Valid credentials

        if user_obj:
            login_user(user_obj, remember=remember)
            flash('Logged in successfully.', 'success')
            # Redirect
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    # Render login form for GET request or failed POST
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Serves the main control panel page."""
    servers = get_server_folders()
    # Pass server status (running or not) to the template
    server_status = {name: (proc_info['process'] is not None and proc_info['process'].poll() is None)
                     for name, proc_info in running_processes.items() if proc_info and 'process' in proc_info}
    return render_template_string(HTML_TEMPLATE, servers=servers, server_status=server_status, username=current_user.username)

@app.route('/start/<server_name>', methods=['GET', 'POST']) # <--- Allow both GET and POST
@login_required
def start_server(server_name):
    """
    Starts the batch file for the specified server.
    Handles both POST (from UI button) and GET (direct URL access).
    """
    global running_processes
    servers = get_server_folders() # Re-check available servers

    # --- Validation (Common for GET and POST) ---
    if server_name not in servers:
        if request.method == 'POST':
            # Abort for POST is fine, leads to JS error handling
            abort(404, "Invalid server name.")
        else: # request.method == 'GET'
            # For GET, flash a message and redirect
            flash(f"Error: Invalid server name '{server_name}'.", "danger")
            return redirect(url_for('index'))

    server_path = os.path.join(SERVERS_BASE_DIR, server_name)
    batch_path = os.path.join(server_path, BATCH_FILE_NAME)

    if not os.path.isfile(batch_path):
        if request.method == 'POST':
             abort(404, f"{BATCH_FILE_NAME} not found in {server_name}.")
        else:
            flash(f"Error: {BATCH_FILE_NAME} not found for server '{server_name}'.", "danger")
            return redirect(url_for('index'))

    # --- Check if already running (Common for GET and POST, needs thread safety) ---
    # Use a temporary lock if the server entry doesn't exist yet to avoid race conditions on first start
    # This lock is just for the check, the actual process info will have its own lock later
    check_lock = running_processes.get(server_name, {}).get('lock', threading.Lock())

    with check_lock:
        process_info = running_processes.get(server_name)
        if process_info and process_info.get('process') and process_info['process'].poll() is None:
            # Server is already running
            if request.method == 'POST':
                return jsonify({"status": "error", "message": f"{server_name} is already running."}), 400
            else:
                flash(f"Info: Server '{server_name}' is already running.", "info")
                return redirect(url_for('index'))

    # --- Start the process (Common logic) ---
    try:
        process = subprocess.Popen(
            [batch_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=server_path,
            shell=False, # Important for security and avoiding shell injection
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP # Windows specific for reliable termination
        )

        # Store process info and start output reading thread
        # Create the lock *before* adding the entry to avoid race conditions
        new_lock = threading.RLock()
        running_processes[server_name] = {
            'process': process,
            'output': [f"--- Starting {server_name} ({BATCH_FILE_NAME}) ---"],
            'lock': new_lock,
            'stop_requested': False
        }
        thread = threading.Thread(target=read_process_output, args=(server_name, process), daemon=True)
        thread.start()

        print(f"Started process for {server_name} with PID: {process.pid}")

        # --- Response Generation (Different for GET and POST) ---
        if request.method == 'POST':
            return jsonify({"status": "success", "message": f"Started {server_name}."})
        else:
            flash(f"Success: Started server '{server_name}'.", "success")
            return redirect(url_for('index'))

    except Exception as e:
        print(f"Error starting {server_name}: {e}")
        # Attempt to clean up if process partially started but failed later
        # Need to handle potential race condition if entry was just added
        error_lock = running_processes.get(server_name, {}).get('lock')
        if error_lock:
             with error_lock:
                  if server_name in running_processes: # Check again inside lock
                       del running_processes[server_name]
        else:
             if server_name in running_processes:
                  del running_processes[server_name]


        if request.method == 'POST':
            return jsonify({"status": "error", "message": f"Failed to start {server_name}: {e}"}), 500
        else:
            flash(f"Error: Failed to start server '{server_name}': {e}", "danger")
            return redirect(url_for('index')) # Redirect back to the main page

@app.route('/stop/<server_name>', methods=['POST'])
@login_required
def stop_server(server_name):
    """Stops the running batch file for the specified server."""
    global running_processes

    if server_name not in running_processes or not running_processes[server_name].get('process'):
        return jsonify({"status": "error", "message": f"{server_name} is not running or already stopped."}), 404

    process_info = running_processes[server_name]
    process = process_info['process']

    # Use lock for thread safety when accessing process info
    with process_info['lock']:
        if process.poll() is not None:
             return jsonify({"status": "error", "message": f"{server_name} has already finished."}), 400

        try:
            print(f"Attempting to stop process for {server_name} (PID: {process.pid})...")
            process_info['stop_requested'] = True
            process_info['output'].append("--- STOP REQUESTED ---")

            # Terminate the process group (Windows specific)
            subprocess.call(['taskkill', '/F', '/T', '/PID', str(process.pid)])

            time.sleep(1)

            # Check if it's really stopped (poll doesn't need lock)
            if process.poll() is None:
                 print(f"Process {process.pid} did not terminate gracefully, forcing kill...")
                 process.kill()
                 process.wait(timeout=5) # Wait briefly for kill confirmation

            final_status = "stopped" if process.poll() is not None else "failed to stop"
            process_info['output'].append(f"--- SCRIPT {final_status.upper()} ---")
            process_info['process'] = None

            # --- Backup Copy ---
            backup_message = "Backup copy not attempted."
            if final_status == "stopped": # Only attempt backup if stop was successful
                server_path = os.path.join(SERVERS_BASE_DIR, server_name)
                try:
                    backup_message = copy_latest_backup(server_name, server_path)
                except Exception as backup_e:
                    print(f"Critical error calling backup function for {server_name}: {backup_e}")
                    backup_message = "Backup function failed critically."
            # --------------------

            print(f"Process for {server_name} {final_status}.")
            response_message = f"{server_name} {final_status}. {backup_message}."
            return jsonify({"status": "success", "message": response_message})

        except Exception as e:
            print(f"Error stopping {server_name}: {e}")
            process_info['output'].append(f"--- ERROR STOPPING SCRIPT: {e} ---")
            return jsonify({"status": "error", "message": f"Error stopping {server_name}: {e}"}), 500


@app.route('/output/<server_name>')
@login_required
def stream_output(server_name):
    """Streams the output of a running/finished process using SSE."""
    if server_name not in running_processes:
        # Return an event indicating the server isn't running or hasn't been started
        def initial_event():
            yield "event: status\ndata: Not Found\n\n"
            yield "event: close\ndata: Stream closing\n\n" # Signal client to close
        return Response(initial_event(), mimetype='text/event-stream')

    # Check if process info exists before proceeding
    process_info = running_processes.get(server_name)
    if not process_info:
         def not_found_event():
            yield "event: status\ndata: Not Found\n\n"
            yield "event: close\ndata: Stream closing\n\n"
         return Response(not_found_event(), mimetype='text/event-stream')


    def generate_output():
        last_index = 0
        process_info = running_processes[server_name]

        while True:
            with process_info['lock']:
                current_len = len(process_info['output'])
                new_lines = process_info['output'][last_index:current_len]
                # Check process status *inside* the lock to ensure consistency with output read
                process_obj = process_info.get('process')
                process_running = process_obj is not None and process_obj.poll() is None
                stop_req = process_info.get('stop_requested', False)

            for line in new_lines:
                yield f"event: message\ndata: {line}\n\n"
            last_index = current_len

            # Send final status and close
            if not process_running:
                 status_message = "Stopped" if stop_req else "Finished"
                 yield f"event: status\ndata: {status_message}\n\n"
                 yield "event: close\ndata: Stream closing\n\n"
                 break # Stop streaming

            time.sleep(0.5) # Adjust polling frequency as needed

    return Response(stream_with_context(generate_output()), mimetype='text/event-stream')

@app.route('/command/<server_name>', methods=['POST'])
@login_required
def send_command(server_name):
    """Sends a command to the stdin of a running server process."""
    global running_processes
    global COMMAND_PASSWORD_HASH

    if not request.is_json:
        return jsonify({"status": "error", "message": "Invalid request format, JSON expected."}), 400

    data = request.get_json()
    command_text = data.get('command')
    provided_cmd_password = data.get('command_password')

    if not command_text or not provided_cmd_password:
        return jsonify({"status": "error", "message": "Missing command or command password."}), 400

    # Verify the command password
    if not check_password_hash(COMMAND_PASSWORD_HASH, provided_cmd_password):
        return jsonify({"status": "error", "message": "Invalid command password."}), 403

    process_info = running_processes.get(server_name)
    if not process_info or not process_info.get('process') or process_info['process'].poll() is not None:
        return jsonify({"status": "error", "message": f"{server_name} is not running or already stopped."}), 404

    process = process_info['process']

    try:
        # Ensure command ends with a newline, as most console apps expect this
        if not command_text.endswith('\n'):
            command_text += '\n'

        process.stdin.write(command_text.encode('utf-8'))
        process.stdin.flush() # Ensure it's sent immediately

        # Log the command to the server's output display as well
        with process_info['lock']:
            process_info['output'].append(f">>> CMD: {command_text.strip()}")

        return jsonify({"status": "success", "message": "Command sent."})
    except Exception as e:
        print(f"Error sending command to {server_name}: {e}")
        # Also log this error to the server's output display
        with process_info['lock']:
            process_info['output'].append(f"--- ERROR SENDING COMMAND: {e} ---")
        return jsonify({"status": "error", "message": f"Error sending command: {e}"}), 500


# --- HTML Templates ---

# Template for the main control panel
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Control Panel</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; margin: 0; background-color: #f4f4f4; color: #333; }
        .navbar { background-color: #333; padding: 10px 20px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .navbar a { color: white; text-decoration: none; padding: 5px 10px; border-radius: 4px; }
        .navbar a:hover { background-color: #555; }
        .container { max-width: 900px; margin: 20px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h1, h2 { color: #555; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
        .flash-messages { list-style: none; padding: 0; margin-bottom: 15px; }
        .flash-messages li { padding: 10px 15px; margin-bottom: 10px; border-radius: 4px; }
        .flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .flash-danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .flash-info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .server-list { list-style: none; padding: 0; }
        .server-item { background: #e9e9e9; margin-bottom: 15px; padding: 15px; border-radius: 5px; display: flex; flex-direction: column; gap: 10px; }
        .server-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
        .server-name { font-weight: bold; flex-grow: 1; min-width: 100px; }
        button, input[type="text"], input[type="password"] { padding: 8px 12px; border-radius: 4px; font-size: 0.9em; }
        button { border: none; cursor: pointer; transition: background-color 0.2s ease; }
        input[type="text"], input[type="password"] { border: 1px solid #ccc; }
        .start-button { background-color: #28a745; color: white; }
        .start-button:hover:not(:disabled) { background-color: #218838; }
        .stop-button { background-color: #dc3545; color: white; }
        .stop-button:hover:not(:disabled) { background-color: #c82333; }
        .command-button { background-color: #007bff; color: white; }
        .command-button:hover:not(:disabled) { background-color: #0056b3; }
        button:disabled { background-color: #cccccc; cursor: not-allowed; }
        .status { font-style: italic; color: #666; font-size: 0.9em; min-width: 80px; text-align: right; }
        .command-section { margin-top: 10px; padding-top: 10px; border-top: 1px solid #ddd; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
        .command-section input[type="text"], .command-section input[type="password"] { flex-grow: 1; min-width: 150px; }
        .output-area { background-color: #222; color: #eee; font-family: 'Courier New', Courier, monospace; padding: 15px; border-radius: 5px; margin-top: 10px; height: 300px; overflow-y: scroll; white-space: pre-wrap; font-size: 0.85em; border: 1px solid #444; }
        .output-area p { margin: 0 0 2px 0; padding: 0; line-height: 1.3; }
        .output-title { font-weight: bold; margin-bottom: 5px; color: #bbb; }
    </style>
</head>
<body>
    <div class="navbar">
        <span>Server Manager</span>
        <span>Welcome, {{ username }}! <a href="{{ url_for('logout') }}">Logout</a></span>
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
                        <span class="server-name">{{ server }}</span>
                        <button class="start-button" data-server="{{ server }}" {% if server_status.get(server) %}disabled{% endif %}>Start</button>
                        <button class="stop-button" data-server="{{ server }}" {% if not server_status.get(server) %}disabled{% endif %}>Stop</button>
                        <span class="status" id="status-{{ server }}">{% if server_status.get(server) %}Running{% else %}Stopped{% endif %}</span>
                    </div>
                    <div class="command-section" id="command-section-{{ server }}" style="display: {% if server_status.get(server) %}flex{% else %}none{% endif %};">
                        <input type="text" class="command-input" data-server="{{ server }}" placeholder="Enter command...">
                        <input type="password" class="command-password-input" data-server="{{ server }}" placeholder="Cmd Password...">
                        <button class="command-button" data-server="{{ server }}" {% if not server_status.get(server) %}disabled{% endif %}>Send</button>
                    </div>
                    <div class="output-area" id="output-{{ server }}" style="display: {% if server_status.get(server) %}block{% else %}none{% endif %};">
                        <div class="output-title">Output for {{ server }}:</div>
                    </div>
                </li>
                {% endfor %}
            {% else %}
                <li>No server folders found in the configured base directory or the directory doesn't exist.</li>
            {% endif %}
        </ul>
    </div>

    <script>
        // --- JavaScript for handling buttons and SSE (Server-Sent Events) ---
        document.addEventListener('DOMContentLoaded', () => {
            const serverItems = document.querySelectorAll('.server-item');
            let eventSources = {}; // Store EventSource objects { server_name: eventSource }

            serverItems.forEach(item => {
                const serverName = item.id.replace('server-', '');
                const startButton = item.querySelector('.start-button');
                const stopButton = item.querySelector('.stop-button');
                const statusSpan = item.querySelector('.status');
                const outputArea = item.querySelector('.output-area');
                const commandSection = item.querySelector('.command-section');
                const commandInput = item.querySelector('.command-input');
                const commandPasswordInput = item.querySelector('.command-password-input');
                const commandButton = item.querySelector('.command-button');


                // --- Event Handlers ---
                startButton.addEventListener('click', () => handleStart(serverName));
                stopButton.addEventListener('click', () => handleStop(serverName));
                if (commandButton) { // Ensure command button exists
                    commandButton.addEventListener('click', () => handleSendCommand(serverName));
                }


                // --- Initial State ---
                if (statusSpan.textContent === 'Running') {
                    startListening(serverName);
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
                console.log(`Stopping ${serverName}...`);
                updateUI(serverName, 'stopping', 'Stopping...');
                fetch(`/stop/${serverName}`, { method: 'POST' })
                     .then(response => {
                        if (!response.ok) {
                             return response.json().then(err => { throw new Error(err.message || `HTTP error ${response.status}`) });
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (data.status === 'success') {
                            console.log(`${serverName} stop requested.`);
                            // Status will be updated via SSE when process actually ends
                        } else {
                            console.error(`Error stopping ${serverName}:`, data.message);
                            alert(`Error stopping ${serverName}: ${data.message}`);
                            const statusSpan = document.getElementById(`status-${serverName}`);
                            updateUI(serverName, statusSpan.textContent.toLowerCase() === 'running' ? 'running' : 'stopped', 'Error Stopping');
                        }
                    })
                    .catch(error => {
                        console.error('Error during stop fetch:', error);
                        alert(`Error stopping ${serverName}: ${error.message}`);
                        const statusSpan = document.getElementById(`status-${serverName}`);
                        updateUI(serverName, statusSpan.textContent.toLowerCase() === 'running' ? 'running' : 'stopped', 'Error Stopping');
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
                        commandInput.value = ''; // Clear command input on success
                        // Optionally clear password or keep it based on preference
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

            // --- Server-Sent Events (SSE) ---
            function startListening(serverName) {
                // Close existing connection if any
                stopListening(serverName);

                console.log(`Opening SSE connection for ${serverName}`);
                const outputArea = document.getElementById(`output-${serverName}`);
                const outputTitle = outputArea.querySelector('.output-title');
                outputArea.style.display = 'block'; // Show output area
                // Clear previous output except title
                outputArea.innerHTML = ''; // Clear previous content entirely
                if (outputTitle) outputArea.appendChild(outputTitle); // Re-add the title if it exists

                const es = new EventSource(`/output/${serverName}`);
                eventSources[serverName] = es;

                es.addEventListener('message', event => {
                    const line = document.createElement('p');
                    line.textContent = event.data;
                    outputArea.appendChild(line);
                    outputArea.scrollTop = outputArea.scrollHeight; // Auto-scroll
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
            }

            // --- UI Update Function ---
            function updateUI(serverName, state, statusText) {
                const item = document.getElementById(`server-${serverName}`);
                if (!item) return;

                const startButton = item.querySelector('.start-button');
                const stopButton = item.querySelector('.stop-button');
                const statusSpan = item.querySelector('.status');
                const outputArea = item.querySelector('.output-area');
                const commandSection = item.querySelector('.command-section');
                const commandButton = item.querySelector('.command-button');
                const commandInput = item.querySelector('.command-input');
                const commandPasswordInput = item.querySelector('.command-password-input');


                statusSpan.textContent = statusText;

                switch (state) {
                    case 'running':
                        startButton.disabled = true;
                        stopButton.disabled = false;
                        outputArea.style.display = 'block';
                        if(commandSection) commandSection.style.display = 'flex';
                        if(commandButton) commandButton.disabled = false;
                        if(commandInput) commandInput.disabled = false;
                        if(commandPasswordInput) commandPasswordInput.disabled = false;
                        break;
                    case 'stopped':
                        startButton.disabled = false;
                        stopButton.disabled = true;
                        if(commandSection) commandSection.style.display = 'none';
                        if(commandButton) commandButton.disabled = true;
                        if(commandInput) commandInput.disabled = true;
                        if(commandPasswordInput) commandPasswordInput.disabled = true;
                        // Keep output area visible after run
                        break;
                    case 'starting':
                    case 'stopping':
                        startButton.disabled = true;
                        stopButton.disabled = true;
                        if(commandButton) commandButton.disabled = true;
                        if(commandInput) commandInput.disabled = true;
                        if(commandPasswordInput) commandPasswordInput.disabled = true;
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
    <style>
        body { font-family: sans-serif; background-color: #f4f4f4; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .login-container { background: #fff; padding: 30px 40px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); text-align: center; width: 100%; max-width: 400px; }
        h1 { color: #555; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; text-align: left; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .remember-me { margin-bottom: 20px; text-align: left; display: flex; align-items: center; }
        .remember-me input { margin-right: 5px; }
        button { background-color: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; width: 100%; transition: background-color 0.2s ease; }
        button:hover { background-color: #0056b3; }
        .flash-messages { list-style: none; padding: 0; margin-bottom: 15px; }
        .flash-messages li { padding: 10px 15px; margin-bottom: 10px; border-radius: 4px; text-align: center; }
        .flash-danger { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .flash-info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
    </style>
</head>
<body>
    <div class="login-container">
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
</body>
</html>
"""


# --- Main Execution ---
if __name__ == '__main__':
    # Basic validation
    if not os.path.isdir(SERVERS_BASE_DIR):
        print(f"ERROR: The specified servers base directory does not exist:")
        print(f"  '{SERVERS_BASE_DIR}'")
        print("Please create the directory or correct the SERVERS_BASE_DIR path in the script.")
        exit(1)
    if PASSWORD == "password":
         print("WARNING: Default admin password is being used. Please change the PASSWORD variable in the script.")
    if COMMAND_PASSWORD == "cmdpass":
         print("WARNING: Default command password is being used. Please change the COMMAND_PASSWORD variable in the script.")
    if SECRET_KEY == secrets.token_hex(24):
        print("INFO: Using a randomly generated SECRET_KEY. For consistent sessions across restarts, set the FLASK_SECRET_KEY environment variable or a fixed value in the script.")

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
    # Use threaded=True to handle multiple requests (like SSE and actions) concurrently
    #app.run(host=HOST, port=PORT, debug=False, threaded=True, ssl_context=ssl_context)
    # To run *without* SSL/TLS if certs don't exist or aren't needed:
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
