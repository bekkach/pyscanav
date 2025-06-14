import hashlib
import os

def hash_file(filepath):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def scan_file(filepath, signatures):
    """Scan a single file against virus signatures"""
    file_hash = hash_file(filepath)
    if file_hash is None:
        return None

    for sig, virus_name in signatures.items():
        if sig in filepath.lower():
            return (virus_name, "Name Match")
        if sig == file_hash:
            return (virus_name, "Hash Match")

    return None

def scan_directory(directory, signatures):
    infected_files = []
    for dirpath, _, filenames in os.walk(directory):
        for file in filenames:
            filepath = os.path.join(dirpath, file)
            result = scan_file(filepath, signatures)
            if result:
                infected_files.append((filepath, result[0], result[1]))
    return infected_files
