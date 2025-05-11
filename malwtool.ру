import hashlib
import pefile
import lief
import os

# Helper function to compute file hashes (MD5, SHA1, SHA256)
def compute_file_hash(file_path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)
    
    return {
        "md5": hash_md5.hexdigest(),
        "sha1": hash_sha1.hexdigest(),
        "sha256": hash_sha256.hexdigest()
    }

# Function to extract strings from binary (e.g., PE files)
def extract_strings(file_path, min_length=4):
    with open(file_path, "rb") as f:
        data = f.read()

    # Extract printable ASCII characters
    strings = []
    current_string = []
    
    for byte in data:
        if 32 <= byte < 127:  # ASCII printable characters
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_length:
                strings.append("".join(current_string))
            current_string = []
    
    return strings

# Function to inspect PE (Portable Executable) files and check imports
def analyze_pe(file_path):
    pe = pefile.PE(file_path)
    
    print(f"Analyzing PE File: {file_path}")
    
    # Extract information about imports (commonly used for malware analysis)
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append(entry.dll.decode('utf-8'))
    
    print(f"Imports: {imports}")
    
    return imports

# Function to check if file is an executable and analyze it
def analyze_file(file_path):
    print(f"Analyzing file: {file_path}")
    
    # Check if the file is an executable (Windows PE or Linux ELF)
    try:
        if file_path.lower().endswith('.exe'):
            imports = analyze_pe(file_path)
        elif file_path.lower().endswith('.elf'):
            # ELF analysis can be done here using `lief` library (not implemented in detail)
            print("ELF File detected. ELF file analysis is not yet implemented.")
        else:
            print(f"Unknown file type: {file_path}")
            return

        # Extract strings from the file
        print("\nExtracting strings...")
        strings = extract_strings(file_path)
        print(f"\nStrings found: {strings[:10]}")  # Display first 10 strings

        # Compute file hashes (for signature-based detection)
        print("\nComputing file hash...")
        hashes = compute_file_hash(file_path)
        print(f"Hashes for {file_path}:")
        print(f"MD5: {hashes['md5']}")
        print(f"SHA1: {hashes['sha1']}")
        print(f"SHA256: {hashes['sha256']}")
        
        # Check for suspicious imports or known malware signatures
        suspicious_imports = ["WinExec", "CreateProcess", "LoadLibrary", "VirtualAlloc"]
        for imp in suspicious_imports:
            if imp in imports:
                print(f"Suspicious import found: {imp}")
                
    except Exception as e:
        print(f"Error during analysis: {e}")

# Function to perform automated analysis on all files in a directory
def analyze_directory(directory_path):
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            analyze_file(file_path)

if __name__ == "__main__":
    file_path = "sample.exe"  # Replace with path to the malware sample
    analyze_file(file_path)
    
    # Uncomment the following line to analyze all files in a directory
    # analyze_directory("path/to/directory")
