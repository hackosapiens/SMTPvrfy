#!/usr/bin/env python
import socket
import time
import argparse
import os
import sys

from urllib.parse import urlparse

def read_file(filename):
    """Reads usernames from a specified file, returning them as a list."""
    with open(filename) as file:
        lines = file.read().splitlines()
    return lines

def get_usernames(usernames_arg):
    """Extracts usernames from the provided argument, considering files or direct input.

    Args:
        usernames_arg (str): The argument containing usernames or file paths.

    Returns:
        list: A list of usernames, handling potential errors gracefully.
    """

    usernames = []
    if usernames_arg:
        if os.path.isfile(usernames_arg):
            try:
                usernames = read_file(usernames_arg)
            except FileNotFoundError:
                print(f"Error: File '{usernames_arg}' not found.")
            except PermissionError:
                print(f"Error: Unable to access file '{usernames_arg}'.")
            except Exception as e:
                print(f"Error reading usernames from file: {e}")
        else:
            # Treat non-file argument as list of usernames or URLs
            for username_or_url in usernames_arg.split(' '):
                # Handle possible URL format (extract username part)
                parsed_url = urlparse(username_or_url)
                if parsed_url.scheme in ['http', 'https']:
                    username_or_url = parsed_url.path.strip('/')
                usernames.append(username_or_url)
    else:
        print("No usernames provided. Please specify either a file path or a list of usernames.")

    return usernames

def verify_smtp(verbose, usernames, ip, timeout_value, sleep_value, port=25):
    """Attempts to verify usernames on a specified SMTP server."""

    # Handle default port
    if port is None or port == " ":
        port = 25
    else:
        port = int(port)

    # Connect to the server
    if verbose > 0:
        print("[*] Connecting to %s on port %s to execute the test") % (ip, port)

    valid_users = []

    for user in usernames:
        try:
            sys.stdout.flush()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_value)
            s.connect((ip, port))  # Connect to the server

            banner = s.recv(1024)  # Receive the server banner
            if verbose > 0:
                print("[*] The system banner is: '%s'") % (str(banner))

            command = 'VRFY ' + user + '\n'  # Construct the VRFY command
            if verbose > 0:
                print("[*] Executing: %s") % (command)

            s.send(command)  # Send the VRFY command
            result = s.recv(1024)  # Receive the server response

            # Analyze server responses
            if "252" in result:
                valid_users.append(user)
                if verbose > 1:
                    print("[+] Username %s is valid") % (user)
            elif "550" in result:
                if verbose > 1:
                    print("[-] 550 Username doesn't exist")
            elif "503" in result:
                print("[!] The server requires authentication")
                break
            elif "500" in result:
                print("[!] The VRFY command is not supported")
                break

        except IOError as e:
            if verbose > 1:
                print("[!] The following error occurred: '%s'") % (str(e))
            if 'Operation now in progress' in str(e):  # Check for specific error
                print("[!] The connection to SMTP failed")
                break

        finally:
            s.close()
            if sleep_value != 0:  # Added colon here
                time.sleep(sleep_value)
                sys.stdout.flush()

    return valid_users

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify usernames using SMTP VRFY commands.")
    parser.add_argument("-v", "--verbose", action="count", help="Increase verbosity level (can be used multiple times)")
    parser.add_argument("usernames", help="File containing usernames or a list of usernames/URLs")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout value for connections")
    parser.add_argument("-s", "--sleep", type=int, default=0, help="Sleep time between username checks")
    parser.add_argument("-p", "--port", type=int, default=25, help="SMTP port (default: 25)")

    args = parser.parse_args()

    usernames = get_usernames(args.usernames)
    valid_users = verify_smtp(args.verbose, usernames, args.ip, args.timeout, args.sleep, args.port)

    if valid_users:
        print("[+] Valid usernames:")
        for user in valid_users:
            print(f"  - {user}")
    else:
        print("[!] No valid usernames found.")

