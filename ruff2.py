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
#endregion

#region local binary analysis
def analyze_local_server_binary_get_ports(target_binary, target_platform):
    log("warning: this will run the binary on your local machine, this could put you at risk")
    detect_ports = prompt_yn("magically detect ports?")
    if detect_ports:
        port = -1
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

def analyze_local_binary_get_offset(target_binary, target_platform, target_architecture, target_type, target_port):

    return 0

def analyze_local_binary_get_target_addresses(target_binary, target_platform, target_architecture, target_type, target_port, target_offset):
    
    return (0, 0)

def analyze_local_binary(target_binary, target_platform, target_architecture, target_type):
    # get port (if necessary)
    target_port = -1 # filler, unused for cli apps
    if target_type == APP_TYPE_SERVER:
        target_port = analyze_local_server_binary_get_ports(target_binary, target_platform)

    target_prefix = prompt_base("what prefix should be used for interaction? (leave blank for none)")

    target_offset = analyze_local_binary_get_offset(target_binary, target_platform, target_architecture, target_type, target_port)
    
    target_base_address, target_instruction_address = analyze_local_binary_get_target_addresses((target_binary, target_platform, target_architecture, target_type, target_port, target_offset))

    return (target_binary, target_platform, target_architecture, target_type, target_port, target_prefix, target_offset, target_base_address, target_instruction_address)
    
#endregion

#remote targeting

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
    