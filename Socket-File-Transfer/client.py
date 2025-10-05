import socket
import json
import hashlib
import struct
import os
import threading
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import time
import tqdm
# Constants
MAX_PACKET_SIZE = 12800

# Operation Constants
OP_SAVE = 'SAVE'
OP_DELETE = 'DELETE'
OP_GET = 'GET'
OP_UPLOAD = 'UPLOAD'
OP_DOWNLOAD = 'DOWNLOAD'
OP_BYE = 'BYE'
OP_LOGIN = 'LOGIN'
OP_ERROR = 'ERROR'

# Type Constants
TYPE_FILE = 'FILE'
TYPE_DATA = 'DATA'
TYPE_AUTH = 'AUTH'
DIR_EARTH = 'EARTH'

# Field Constants
FIELD_OPERATION = 'operation'
FIELD_DIRECTION = 'direction'
FIELD_TYPE = 'type'
FIELD_USERNAME = 'username'
FIELD_PASSWORD = 'password'
FIELD_TOKEN = 'token'
FIELD_KEY = 'key'
FIELD_SIZE = 'size'
FIELD_TOTAL_BLOCK = 'total_block'
FIELD_MD5 = 'md5'
FIELD_BLOCK_SIZE = 'block_size'
FIELD_STATUS = 'status'
FIELD_STATUS_MSG = 'status_msg'
FIELD_BLOCK_INDEX = 'block_index'
DIR_REQUEST = 'REQUEST'
DIR_RESPONSE = 'RESPONSE'
server_address = ('127.0.0.1', 1379)

def md5_hash(string):
    return hashlib.md5(string.encode()).hexdigest()


# Helper function to create a STEP protocol packet
def make_packet(json_data, bin_data=None):
    j = json.dumps(json_data, ensure_ascii=False)
    j_encoded = j.encode('utf-8')
    j_len = len(j_encoded)
    if bin_data is None:
        b_len = 0
    else:
        b_len = len(bin_data)
    header = struct.pack('!II', j_len, b_len)
    if bin_data is None:
        return header + j_encoded
    else:
        return header + j_encoded + bin_data


# Helper function to receive a complete STEP protocol packet
def receive_packet(sock):
    # Receive header first (8 bytes)
    header = b''
    while len(header) < 8:
        chunk = sock.recv(8 - len(header))
        if not chunk:
            raise ConnectionError("Socket connection closed unexpectedly.")
        header += chunk
    j_len, b_len = struct.unpack('!II', header)

    # Receive JSON data
    json_data = b''
    while len(json_data) < j_len:
        chunk = sock.recv(min(j_len - len(json_data), 4096))
        if not chunk:
            raise ConnectionError("Socket connection closed while receiving JSON data.")
        json_data += chunk
    try:
        json_decoded = json.loads(json_data.decode())
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to decode JSON: {e}")

    # Receive binary data if any
    bin_data = b''
    if b_len > 0:
        while len(bin_data) < b_len:
            chunk = sock.recv(min(b_len - len(bin_data), 4096))
            if not chunk:
                raise ConnectionError("Socket connection closed while receiving binary data.")
            bin_data += chunk

    return json_decoded, bin_data


# Function to handle login and obtain authorization token
def login_to_server(sock, username, output_func=print):
    try:
        # Prepare login data
        login_data = {
            FIELD_OPERATION: OP_LOGIN,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_AUTH,
            FIELD_USERNAME: username,
            FIELD_PASSWORD: md5_hash(username)  # Using the MD5 of username as password
        }

        # Send login request to server
        sock.sendall(make_packet(login_data))
        output_func("Login request sent.")

        # Receive response from server
        response_json, _ = receive_packet(sock)

        if FIELD_TOKEN in response_json:
            output_func(f"Login successful! Token received: {response_json[FIELD_TOKEN]}")
            return response_json[FIELD_TOKEN]
        else:
            output_func(f"Login failed: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
            return None

    except Exception as e:
        output_func(f"An error occurred during login: {e}")
        return None


# Function to upload a file to the server
'''def upload_file_to_server(sock, token, file_path, output_func=print):
    try:
        # Step 1: Request upload plan (OP_SAVE)
        file_size = os.path.getsize(file_path)
        upload_request = {
            FIELD_OPERATION: OP_SAVE,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_SIZE: file_size,
            FIELD_TOKEN: token
        }

        # Send request to get the upload plan
        sock.sendall(make_packet(upload_request))
        output_func("Upload plan request sent.")

        # Receive upload plan from server
        response_json, _ = receive_packet(sock)

        if response_json.get(FIELD_STATUS) != 200:
            output_func(f"Failed to get upload plan: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
            return

        key = response_json.get(FIELD_KEY)
        block_size = response_json.get(FIELD_BLOCK_SIZE, MAX_PACKET_SIZE)
        total_blocks = response_json.get(FIELD_TOTAL_BLOCK, 1)

        output_func(f"Upload plan received: key={key}, block_size={block_size}, total_blocks={total_blocks}")

        # Step 2: Upload the file block by block using the "key"
        with open(file_path, 'rb') as f:
            for block_index in range(total_blocks):
                block_data = f.read(block_size)
                if not block_data:
                    break  # EOF

                # Create block upload packet
                block_upload_request = {
                    FIELD_OPERATION: OP_UPLOAD,
                    FIELD_DIRECTION: DIR_REQUEST,
                    FIELD_TYPE: TYPE_FILE,
                    FIELD_KEY: key,
                    FIELD_BLOCK_INDEX: block_index,
                    FIELD_TOKEN: token
                }

                # Send the block to the server
                sock.sendall(make_packet(block_upload_request, block_data))
                output_func(f"Block {block_index + 1}/{total_blocks} upload request sent.")

                # Receive response for the block upload
                response_json, _ = receive_packet(sock)

                if response_json.get(FIELD_STATUS) != 200:
                    output_func(
                        f"Failed to upload block {block_index}: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
                    return
                else:
                    output_func(f"Block {block_index + 1}/{total_blocks} uploaded successfully.")

        output_func("File upload completed.")

    except Exception as e:
        output_func(f"An error occurred during file upload: {e}")'''

'''def upload_block(sock, token, file_path, key, block_index, block_size, output_func):
    try:
        # Open the file and read the block
        with open(file_path, 'rb') as f:
            f.seek(block_index * block_size)  # Move the pointer to the correct block
            block_data = f.read(block_size)
            if not block_data:
                output_func(f"Block {block_index + 1} is empty.")
                return

            # Create block upload packet
            block_upload_request = {
                FIELD_OPERATION: OP_UPLOAD,
                FIELD_DIRECTION: DIR_REQUEST,
                FIELD_TYPE: TYPE_FILE,
                FIELD_KEY: key,
                FIELD_BLOCK_INDEX: block_index,
                FIELD_TOKEN: token
            }

            # Send the block to the server
            sock.sendall(make_packet(block_upload_request, block_data))
            output_func(f"Block {block_index + 1} upload request sent.")

            # Receive response for the block upload
            response_json, _ = receive_packet(sock)

            if response_json.get(FIELD_STATUS) != 200:
                output_func(
                    f"Failed to upload block {block_index}: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
            else:
                output_func(f"Block {block_index + 1} uploaded successfully.")

    except Exception as e:
        output_func(f"Error uploading block {block_index}: {e}")'''

import threading
import socket
from concurrent.futures import ThreadPoolExecutor

# Assume make_packet, receive_packet, FIELD_OPERATION, etc. are defined

def upload_block(server_address, token, file_path, key, block_index, block_size, output_func):
    try:
        # 每个线程创建独立的套接字连接
        with socket.create_connection(server_address) as sock:
            # Open the file and read the block
            with open(file_path, 'rb') as f:
                f.seek(block_index * block_size)  # Move the pointer to the correct block
                block_data = f.read(block_size)
                if not block_data:
                    output_func(f"Block {block_index + 1} is empty.")
                    return

                # Create block upload packet
                block_upload_request = {
                    FIELD_OPERATION: OP_UPLOAD,
                    FIELD_DIRECTION: DIR_REQUEST,
                    FIELD_TYPE: TYPE_FILE,
                    FIELD_KEY: key,
                    FIELD_BLOCK_INDEX: block_index,
                    FIELD_TOKEN: token
                }

                # Send the block to the server using the new socket
                sock.sendall(make_packet(block_upload_request, block_data))
                output_func(f"Block {block_index + 1} upload request sent.")

                # Receive response for the block upload
                response_json, _ = receive_packet(sock)

                if response_json.get(FIELD_STATUS) != 200:
                    output_func(
                        f"Failed to upload block {block_index}: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
                else:
                    output_func(f"Block {block_index + 1} uploaded successfully.")

    except Exception as e:
        output_func(f"Error uploading block {block_index}: {e}")

def upload_file_to_server(server_address, token, file_path, output_func=print):

    try:
        # Step 1: Request upload plan (OP_SAVE)
        file_size = os.path.getsize(file_path)
        upload_request = {
            FIELD_OPERATION: OP_SAVE,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_SIZE: file_size,
            FIELD_TOKEN: token
        }

        # 使用一个套接字连接发送请求
        with socket.create_connection(server_address) as sock:
            sock.sendall(make_packet(upload_request))
            output_func("Upload plan request sent.")

            # Receive upload plan from server
            response_json, _ = receive_packet(sock)

            if response_json.get(FIELD_STATUS) != 200:
                output_func(f"Failed to get upload plan: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
                return

            key = response_json.get(FIELD_KEY)
            block_size = response_json.get(FIELD_BLOCK_SIZE, MAX_PACKET_SIZE)
            total_blocks = response_json.get(FIELD_TOTAL_BLOCK, 1)

            output_func(f"Upload plan received: key={key}, block_size={block_size}, total_blocks={total_blocks}")
        start_time = time.time()
        # Step 2: Create a thread pool for parallel upload
        max_workers = 4
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(upload_block, server_address, token, file_path, key, block_index, block_size, output_func)
                for block_index in range(total_blocks)
            ]
            # 等待所有线程完成
            for future in futures:
                future.result()

        end_time = time.time()
        elapsed_time = end_time - start_time
        output_func(f"File upload completed in {elapsed_time:.2f} seconds.")

    except Exception as e:
        output_func(f"An error occurred during file upload: {e}")




# Function to request file information from the server
def get_file_info(sock, token, file_key, output_func=print):
    try:
        # Prepare GET request for file information
        get_request = {
            FIELD_OPERATION: OP_GET,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_KEY: file_key,
            FIELD_TOKEN: token
        }

        # Send GET request to the server
        sock.sendall(make_packet(get_request))
        output_func(f"GET request sent for file key '{file_key}'.")

        # Receive the response with file info or download plan
        response_json, _ = receive_packet(sock)

        if response_json.get(FIELD_STATUS) == 200:
            output_func(f"File information received: {response_json}")
            return response_json
        else:
            output_func(f"Failed to get file information: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
            return None

    except Exception as e:
        output_func(f"An error occurred while getting file info: {e}")
        return None


# Function to download a file block by block from the server
def download_file_from_server(sock, token, file_info, destination_path, output_func=print):
    try:
        file_key = file_info.get(FIELD_KEY)
        total_blocks = file_info.get(FIELD_TOTAL_BLOCK)
        block_size = file_info.get(FIELD_BLOCK_SIZE)
        file_size = file_info.get(FIELD_SIZE)
        md5_expected = file_info.get(FIELD_MD5)

        if not all([file_key, total_blocks, block_size, file_size, md5_expected]):
            output_func("Incomplete file information received.")
            return

        output_func(f"Starting download for file key {file_key}, total blocks: {total_blocks}")

        # Open the file to write the downloaded content
        with open(destination_path, 'wb') as f:
            for block_index in range(total_blocks):
                # Request each block
                block_request = {

                    FIELD_OPERATION: OP_DOWNLOAD,
                    FIELD_DIRECTION: DIR_REQUEST,
                    FIELD_TYPE: TYPE_FILE,
                    FIELD_KEY: file_key,
                    FIELD_BLOCK_INDEX: block_index,
                    FIELD_TOKEN: token
                }
                sock.sendall(make_packet(block_request))
                output_func(f"Block {block_index + 1}/{total_blocks} download request sent.")

                # Receive block data from server
                response_json, bin_data = receive_packet(sock)

                if response_json.get(FIELD_STATUS) != 200:
                    output_func(
                        f"Failed to download block {block_index}: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
                    return
                else:
                    f.write(bin_data)
                    output_func(f"Block {block_index + 1}/{total_blocks} downloaded successfully.")

        # Verify MD5
        md5_downloaded = calculate_file_md5(destination_path)
        if md5_downloaded == md5_expected:
            output_func(f"File '{destination_path}' downloaded successfully and MD5 verified.")
        else:
            output_func(f"MD5 mismatch: expected {md5_expected}, got {md5_downloaded}")

    except Exception as e:
        output_func(f"An error occurred during file download: {e}")


# Helper function to calculate MD5 hash of a file
def calculate_file_md5(filename):
    m = hashlib.md5()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(2048)
            if not data:
                break
            m.update(data)
    return m.hexdigest()


# Function to delete a file on the server
def delete_file_on_server(sock, token, file_key, output_func=print):
    try:
        # Prepare DELETE request
        delete_request = {
            FIELD_OPERATION: OP_DELETE,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_KEY: file_key,
            FIELD_TOKEN: token
        }

        # Send DELETE request to the server
        sock.sendall(make_packet(delete_request))
        output_func(f"DELETE request sent for file key '{file_key}'.")

        # Receive response from server
        response_json, _ = receive_packet(sock)

        if response_json.get(FIELD_STATUS) == 200:
            output_func(f"File with key '{file_key}' deleted successfully.")
        else:
            output_func(f"Failed to delete file: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")

    except Exception as e:
        output_func(f"An error occurred during file deletion: {e}")


def list_files_on_server(sock, token, output_func=print):
    try:
        # Prepare GET request without FIELD_KEY
        get_request = {
            FIELD_OPERATION: OP_GET,
            FIELD_DIRECTION: DIR_REQUEST,
            FIELD_TYPE: TYPE_FILE,
            FIELD_TOKEN: token
        }

        # Send GET request to the server
        sock.sendall(make_packet(get_request))
        output_func("GET request sent to list all files.")

        # Receive the response with the list of files
        response_json, _ = receive_packet(sock)

        if response_json.get(FIELD_STATUS) == 200:
            file_list = response_json.get('file_list', [])
            output_func(f"Files on server: {file_list}")
            return file_list
        else:
            output_func(f"Failed to get list of files: {response_json.get(FIELD_STATUS_MSG, 'Unknown error')}")
            return None

    except Exception as e:
        output_func(f"An error occurred while listing files: {e}")
        return None


# Function to send BYE operation and disconnect
def disconnect_from_server(sock, token, output_func=print):
    try:
        if sock and token:
            # Prepare BYE request
            bye_request = {
                FIELD_OPERATION: OP_BYE,
                FIELD_DIRECTION: DIR_REQUEST,
                FIELD_TYPE: TYPE_AUTH,
                FIELD_TOKEN: token
            }
            sock.sendall(make_packet(bye_request))
            output_func("BYE request sent to server.")
            sock.close()
            output_func('Connection closed.')
    finally:
        try:
            sock.close()
        except:
            pass  # Ignore any errors during socket close


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Client Application")

        # Variables
        self.server_ip = tk.StringVar(value="127.0.0.1")
        self.server_port = tk.IntVar(value=1379)
        self.username = tk.StringVar()
        self.token = None
        self.client_socket = None

        # Create UI elements
        self.create_widgets()

    def create_widgets(self):
        # Server IP and port
        tk.Label(self.root, text="Server IP:").grid(row=0, column=0, sticky='e')
        tk.Entry(self.root, textvariable=self.server_ip).grid(row=0, column=1)

        tk.Label(self.root, text="Server Port:").grid(row=1, column=0, sticky='e')
        tk.Entry(self.root, textvariable=self.server_port).grid(row=1, column=1)

        # Username
        tk.Label(self.root, text="Username:").grid(row=2, column=0, sticky='e')
        tk.Entry(self.root, textvariable=self.username).grid(row=2, column=1)

        # Connect and Login button
        self.login_button = tk.Button(self.root, text="Connect and Login", command=self.connect_and_login)
        self.login_button.grid(row=3, column=0, columnspan=2)

        # Disconnect button
        self.disconnect_button = tk.Button(self.root, text="Disconnect", command=self.disconnect, state='disabled')
        self.disconnect_button.grid(row=4, column=0, columnspan=2)

        # Separator
        ttk.Separator(self.root, orient='horizontal').grid(row=5, column=0, columnspan=2, sticky='ew', pady=10)

        # Operations
        self.upload_button = tk.Button(self.root, text="Upload File", command=self.upload_file, state='disabled')
        self.upload_button.grid(row=6, column=0, columnspan=2, sticky='ew')

        self.list_files_button = tk.Button(self.root, text="List Files", command=self.list_files, state='disabled')
        self.list_files_button.grid(row=7, column=0, columnspan=2, sticky='ew')

        self.download_button = tk.Button(self.root, text="Download File", command=self.download_file, state='disabled')
        self.download_button.grid(row=8, column=0, columnspan=2, sticky='ew')

        self.delete_button = tk.Button(self.root, text="Delete File", command=self.delete_file, state='disabled')
        self.delete_button.grid(row=9, column=0, columnspan=2, sticky='ew')

        # File Key entry
        tk.Label(self.root, text="File Key:").grid(row=10, column=0, sticky='e')
        self.file_key_entry = tk.Entry(self.root)
        self.file_key_entry.grid(row=10, column=1)

        # Output (Text widget)
        self.output_text = tk.Text(self.root, width=50, height=15)
        self.output_text.grid(row=11, column=0, columnspan=2)

    def connect_and_login(self):
        # Connect to server and login
        threading.Thread(target=self._connect_and_login_thread).start()

    def _connect_and_login_thread(self):
        server_ip = self.server_ip.get()
        server_port = self.server_port.get()
        username = self.username.get()

        if not username:
            messagebox.showerror("Error", "Please enter a username")
            return

        try:
            # Create socket and connect
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, server_port))
            self.append_output(f"Connected to server at {server_ip}:{server_port}")

            # Perform login
            self.token = login_to_server(self.client_socket, username, self.append_output)
            if self.token:
                self.append_output("Login successful.")
                # Enable operation buttons
                self.enable_operation_buttons()
            else:
                self.append_output("Login failed.")
                self.client_socket.close()
                self.client_socket = None
        except Exception as e:
            self.append_output(f"An error occurred: {e}")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None

    def enable_operation_buttons(self):
        self.upload_button.config(state='normal')
        self.list_files_button.config(state='normal')
        self.download_button.config(state='normal')
        self.delete_button.config(state='normal')
        self.disconnect_button.config(state='normal')
        self.login_button.config(state='disabled')

    def disable_operation_buttons(self):
        self.upload_button.config(state='disabled')
        self.list_files_button.config(state='disabled')
        self.download_button.config(state='disabled')
        self.delete_button.config(state='disabled')
        self.disconnect_button.config(state='disabled')
        self.login_button.config(state='normal')

    def upload_file(self):
        # Select file to upload
        file_path = filedialog.askopenfilename()
        if file_path:
            threading.Thread(target=self._upload_file_thread, args=(file_path,)).start()

    def _upload_file_thread(self, file_path):
        if self.client_socket and self.token:
            #upload_file_to_server(self.client_socket, self.token, file_path, self.append_output)
            upload_file_to_server(server_address, self.token, file_path, self.append_output)
        else:
            self.append_output("Not connected or logged in.")

    def list_files(self):
        threading.Thread(target=self._list_files_thread).start()

    def _list_files_thread(self):
        if self.client_socket and self.token:
            file_list = list_files_on_server(self.client_socket, self.token, self.append_output)
            if file_list:
                self.append_output("Files on server:")
                for f_key in file_list:
                    self.append_output(f_key)
            else:
                self.append_output("No files found.")
        else:
            self.append_output("Not connected or logged in.")

    def download_file(self):
        file_key = self.file_key_entry.get().strip()
        if not file_key:
            messagebox.showerror("Error", "Please enter a file key")
            return
        # Select destination path
        destination_path = filedialog.asksaveasfilename()
        if destination_path:
            threading.Thread(target=self._download_file_thread, args=(file_key, destination_path)).start()

    def _download_file_thread(self, file_key, destination_path):
        if self.client_socket and self.token:
            file_info = get_file_info(self.client_socket, self.token, file_key, self.append_output)
            if file_info:
                download_file_from_server(self.client_socket, self.token, file_info, destination_path, self.append_output)
            else:
                self.append_output("Failed to get file info.")
        else:
            self.append_output("Not connected or logged in.")

    def delete_file(self):
        file_key = self.file_key_entry.get().strip()
        if not file_key:
            messagebox.showerror("Error", "Please enter a file key")
            return
        threading.Thread(target=self._delete_file_thread, args=(file_key,)).start()

    def _delete_file_thread(self, file_key):
        if self.client_socket and self.token:
            delete_file_on_server(self.client_socket, self.token, file_key, self.append_output)
        else:
            self.append_output("Not connected or logged in.")

    def disconnect(self):
        threading.Thread(target=self._disconnect_thread).start()

    def _disconnect_thread(self):
        if self.client_socket and self.token:
            disconnect_from_server(self.client_socket, self.token, self.append_output)
            self.client_socket = None
            self.token = None
            self.disable_operation_buttons()
            self.append_output("Disconnected. Please log in again to perform operations.")
        else:
            self.append_output("Not connected.")

    def append_output(self, text):
        # Use root.after to safely update the GUI from another thread
        self.root.after(0, self._append_output, text)

    def _append_output(self, text):
        self.output_text.insert(tk.END, text + '\n')
        self.output_text.see(tk.END)

    def on_closing(self):
        if self.client_socket and self.token:
            # Send BYE request
            try:
                disconnect_from_server(self.client_socket, self.token, self.append_output)
            except:
                pass
            self.client_socket = None
            self.token = None
        elif self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()

