import paramiko
import xmltodict
from typing import Optional
import tempfile

from .config.schema import PfSense
from .config.settings import (
    CONFIG_DIR,
    BACKUP_CONFIG_DIR,
    PFSENSE_USERNAME,
    PFSENSE_PASSWORD,
    PFSENSE_HOST,
)

class PfSenseError(Exception):
    """Custom exception for pfSense operations."""
    pass

def fetch_pfsense_config(
    key_filepath: Optional[str] = None,
) -> PfSense:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if key_filepath:
        key = paramiko.RSAKey.from_private_key_file(key_filepath)
        client.connect(PFSENSE_HOST, username=PFSENSE_USERNAME, pkey=key)
    else:
        client.connect(
            PFSENSE_HOST, username=PFSENSE_USERNAME, password=PFSENSE_PASSWORD
        )

    _, stdout, stderr = client.exec_command(f"cat {CONFIG_DIR}")

    if stderr.channel.recv_exit_status() != 0:
        error_message = stderr.read().decode()
        print(f"[!] Error fetching config: {error_message}")
        client.close()
        raise PfSenseError("Failed to fetch pfSense configuration.")

    config_xml = stdout.read().decode()
    client.close()

    # Convert XML to dict
    config_dict = xmltodict.parse(config_xml, force_list=("user", "group", "staticmap"))
    # Parse with Pydantic
    pfsense_config = PfSense(**config_dict["pfsense"])

    return pfsense_config


def push_pfsense_config(config: PfSense) -> int:
    """Push a new configuration to the pfSense device.

    Args:
        config (PfSense): The pfSense configuration to push.

    Returns:
        int: 1 if successful, 0 otherwise.
    """
    remote_config = CONFIG_DIR
    backup_config = BACKUP_CONFIG_DIR

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(PFSENSE_HOST, username=PFSENSE_USERNAME, password=PFSENSE_PASSWORD)
    except paramiko.AuthenticationException:
        print("[!] Authentication failed. Please check your credentials.")
        return 0

    print("[*] Creating backup of current config...")
    ssh.exec_command(f"cp {remote_config} {backup_config}")

    print("[*] Uploading new config...")
    sftp = ssh.open_sftp()
    # Convert config (Pydantic model) to XML string
    config_dict = {"pfsense": config.model_dump(by_alias=True)}
    config_xml = xmltodict.unparse(config_dict, pretty=True)

    # Write XML to a temporary local file
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmpfile:
        tmpfile.write(config_xml)
        tmpfile.flush()
        local_path = tmpfile.name

    # Upload the temporary file to the remote device
    sftp.put(local_path, "/tmp/config.xml")
    sftp.close()

    print("[*] Replacing and reloading config...")
    ssh.exec_command(f"mv /tmp/config.xml {remote_config}")
    ssh.exec_command("rm /tmp/config.cache")
    ssh.exec_command("/etc/rc.reload_all")

    print("[+] Done.")
    ssh.close()
    return 1


def load_pfsense_config_from_file(file_path: str) -> PfSense:
    """Load a pfSense configuration from a file.

    Args:
        file_path (str): Path to the configuration file.

    Returns:
        PfSense: Parsed pfSense configuration.
    """
    with open(file_path, "r") as file:
        config_xml = file.read()

    # Convert XML to dict
    config_dict = xmltodict.parse(config_xml, force_list=("user", "group", "staticmap"))

    # Parse with Pydantic
    pfsense_config = PfSense(**config_dict["pfsense"])

    return pfsense_config
