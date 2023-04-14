import json
import hashlib

def generate_fingerprint(config_file: str) -> str:
    """
    Generates a fingerprint based on inputs from a JSON configuration file.

    Args:
        config_file (str): Path to the JSON configuration file.

    Returns:
        str: The generated fingerprint.
    Raises:
        FileNotFoundError: If the configuration file does not exist.
    """

    # Load the configuration file
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f'Configuration file {config_file} not found.')

    # Get the inputs from the configuration file
    input1 = config['name']
    input2 = config['recipient']
    input3 = config['secret']

    # Generate the fingerprint using a widely accepted method
    fingerprint = hashlib.sha256(f"{input1}{input2}{input3}".encode()).hexdigest()

    return fingerprint