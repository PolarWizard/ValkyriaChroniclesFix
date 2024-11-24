"""
Patch Tool for `Valkyria.exe` executable

This script modifies a specific binary pattern in a game executable file based on a
provided YAML configuration. The configuration specifies the desired resolution
settings, and the script computes necessary values to update the executable.

The reason this script is needed as opposed to be part of the DLL that is injected
is that this code that we are modifying happens very very early on in the exe and
there is not enough time for the DLL to inject a hook to properly patch in a fix
to modify certain registers that contain important information using the desktop
resolution.
The code we replace:
```
Not gonna go into the inty gritty like later, but basically the game does a bunch
of math to compute some basic values. They must have been using a really old
C/C++ compiler to get this type of assembly generated, anyhow all the math here
gets replaced with hardcoded values from the yml file.
B8 39 8E E3 38 | mov eax,38E38E39 |
F7 E3          | mul ebx          |
8B FA          | mov edi, edx     |
B8 39 8E E3 38 | mov eax,38E38E39 |
F7 EB          | imul ebx         |
D1 FA          | sar edx, 1       |
8B C2          | mov eax, edx     |
C1 E8 1F       | shr eax, 1F      |
03 C2          | add eax, edx     |
2B C8          | sub ecx, eax     |
D1 EF          | shr edi, 1       |
D1 F9          | sar ecx, 1       |
```
We replace it with, for completeness we assume 5120x1440 resolution:
```
Just like above but we hardcode registers with stuff from the yml file and call it a day.
B8 00 14 00 00  | mov eax, 0x1400 | eax = 5120      | Width provided in yml
BB 00 5A 00 00  | mov ebx, 0x5A00 | ebx = 1440 << 4 | Height provided in yml shifted by 4 to the left
B9 00 00 00 00  | mov ecx, 0x0    | ecx = 0         | Viewport offset, centers image if width in yml > screen
BA 00 14 00 00  | mov edx, 0x1400 | edx = 5120      | Width provided in yml
BE A0 05 00 00  | mov esi, 0x5A0  | esi = 1440      | Height provided in yml
BF 00 14 00 00  | mov edi, 0x1400 | edi = 5120      | Width provided in yml
90              | nop             |                 | padding
```
Modules:
    yaml: For reading and parsing YAML configuration files.
    screeninfo: For retrieving the desktop resolution from the primary monitor.

Functions:
    read_yaml(yaml_path): Reads a YAML file and returns its content.
    get_desktop_resolution(): Retrieves the resolution of the primary desktop monitor.
    parse_signature(signature): Converts a string pattern into a byte array.
    edit_exe(game_path, search_pattern, replace_pattern): Finds and replaces binary patterns in the executable.
    patch(game_exe): Main function to read the YAML file, compute patterns, and apply the patch.

Usage:
    This script is designed for modifying the `Valkyria.exe` executable.
    This script should be placed in the scripts folder where the yml and .asi file is located and run from there,
    this tool should be a one time use case, edit the resolution portion of the yml file and run the tool.

Example:
    python patch_tool.py
"""

import yaml
from screeninfo import get_monitors

def read_yaml(yaml_path):
    """
    Reads a YAML file and returns its content as a Python object.

    Args:
        yaml_path (str): Path to the YAML file.

    Returns:
        dict or None: Parsed content of the YAML file, or None if an error occurs.
    """
    try:
        with open(yaml_path, 'r') as file:
            data = yaml.safe_load(file)  # Use safe_load to avoid potential code execution risks
        return data
    except FileNotFoundError:
        print(f"Error: File '{yaml_path}' not found.")
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
    return None

def get_desktop_resolution() -> tuple:
    """
    Gets the resolution of the primary desktop monitor.

    Returns:
        tuple: A tuple containing the width and height of the desktop resolution
               (e.g., (1920, 1080)). If no primary monitor is found, defaults to the first monitor.
    """
    for monitor in get_monitors():
        if monitor.is_primary:
            return monitor.width, monitor.height
    # Fallback: Return the resolution of the first monitor if no primary is found
    primary_monitor = get_monitors()[0]
    return primary_monitor.width, primary_monitor.height

def parse_signature(signature) -> bytes:
    """
    Parses a string signature into a byte array, replacing wildcards with placeholders.

    Args:
        signature (str): A string representation of the binary signature, with optional
                         wildcards ("?" or "??").

    Returns:
        bytes: A byte array corresponding to the parsed signature.
    """
    byte_array = []
    for token in signature.split():
        if token == "?" or token == "??":  # Wildcard
            byte_array.append(0)  # Placeholder for wildcard
        else:
            byte_array.append(int(token, 16))  # Convert hex to int
    return bytes(byte_array)

def edit_exe(game_path, search_pattern, replace_pattern) -> int:
    """
    Searches for a binary pattern in a game executable file and replaces it with another pattern.

    Args:
        game_path (str): Path to the game executable.
        search_pattern (str): Binary pattern to search for (in string format).
        replace_pattern (str): Binary pattern to replace with (in string format).

    Returns:
        int: Offset of the replaced pattern in the file, or None if the pattern is not found.
    """
    search_pattern = search_pattern.strip()
    sp1 = parse_signature(search_pattern)
    rp  = parse_signature(replace_pattern)

    try:
        with open("patch.txt", 'r') as file:
            print("patch.txt found")
            data = file.readlines()
            search_pattern = data[0].strip()
            print(f"Will search for pattern: {search_pattern}")
            sp1 = parse_signature(search_pattern)
    except FileNotFoundError:
        print("patch.txt not found")
        print(f"Will search using default pattern: {search_pattern}")
    except IOError as e:
        print(f"IO Error with file: {e}")

    try:
        with open(game_path, 'rb+') as file:
            data = file.read()
            offset = data.find(sp1, 0)
            if offset == -1:
                print(f"Cannot find: {search_pattern}")
                print("Delete and reinstall game and try again")
                return None
            print(f"Found: {search_pattern} @ 0x{hex(offset)}")
            file.seek(offset)
            file.write(rp)
            print(f"Replaced with: {replace_pattern} @ 0x{hex(offset)}")
            with open("patch.txt", "w") as file:
                file.write(replace_pattern)
    except FileNotFoundError:
        print(f"Error: File '{game_path}' not found")
    except IOError as e:
        print(f"IO Error with file: {e}")

def patch(game_exe) -> int:
    """
    Reads configuration from a YAML file, computes replacement patterns, and patches the game executable.

    Args:
        game_exe (str): Path to the game executable.

    Returns:
        int: The result of the `edit_exe` function, or None if the YAML file is invalid.
    """
    yaml_data = read_yaml("ValkyriaChroniclesFix.yml")
    if yaml_data is None:
        return
    width  = yaml_data['resolution']['width']
    height = yaml_data['resolution']['height']
    print(f"YAML: resolution: width:  {yaml_data['resolution']['width']}")
    print(f"YAML: resolution: height: {yaml_data['resolution']['height']}")
    desktop_width, desktop_height = get_desktop_resolution()
    if width == 0 or height == 0:
        width, height = desktop_width, desktop_height
    offset = int((desktop_width - width) / 2)
    special = (height << 4).to_bytes(4, byteorder="little", signed=False)
    width  = width.to_bytes(4, byteorder="little", signed=False)
    height = height.to_bytes(4, byteorder="little", signed=False)
    offset = offset.to_bytes(4, byteorder="little", signed=False)
    special = " ".join(f"{byte:02X}" for byte in special)
    width = " ".join(f"{byte:02X}" for byte in width)
    height = " ".join(f"{byte:02X}" for byte in height)
    offset = " ".join(f"{byte:02X}" for byte in offset)
    search_pattern1 = "B8 39 8E E3 38 F7 E3 8B FA B8 39 8E E3 38"
    replace_pattern = f"B8 {width} BB {special} B9 {offset} BA {width} BE {height} BF {width} 90"
    edit_exe(game_exe, search_pattern1, replace_pattern)

if __name__ == "__main__":
    patch("../Valkyria.exe")
    input("Press enter to exit...")
