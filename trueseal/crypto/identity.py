import hashlib
import platform
import subprocess
from pathlib import Path
class DeviceIdentity:
    """Represents the unique fingerprint of physical machine hardware."""
    @staticmethod
    def _get_hardware_id_windows() -> str:
        try:
            result = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            lines = result.stdout.strip().splitlines()
            if len(lines) > 1:
                uuid = lines[1].strip()
                if uuid and uuid.upper() != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                    return f"WMI:{uuid}"
        except Exception:
            pass
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                return f"REG:{machine_guid}"
        except Exception:
            pass
        return "UNKNOWN_WINDOWS"
    @staticmethod
    def _get_hardware_id_linux() -> str:
        dmi_uuid_path = Path("/sys/class/dmi/id/product_uuid")
        if dmi_uuid_path.exists():
            try:
                return f"DMI:{dmi_uuid_path.read_text().strip()}"
            except PermissionError:
                pass
        machine_id_path = Path("/etc/machine-id")
        if machine_id_path.exists():
            try:
                return f"OS:{machine_id_path.read_text().strip()}"
            except PermissionError:
                pass
        return "UNKNOWN_LINUX"
    @staticmethod
    def _get_hardware_id_macos() -> str:
        try:
            result = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in result.stdout.splitlines():
                if "IOPlatformUUID" in line:
                    uuid_part = line.split('"')[-2]
                    return f"MAC:{uuid_part}"
        except Exception:
            pass
        return "UNKNOWN_MACOS"
    @staticmethod
    def get_hardware_fingerprint() -> bytes:
        os_name = platform.system()
        try:
            if os_name == "Windows":
                hardware_id = DeviceIdentity._get_hardware_id_windows()
            elif os_name == "Linux":
                hardware_id = DeviceIdentity._get_hardware_id_linux()
            elif os_name == "Darwin":
                hardware_id = DeviceIdentity._get_hardware_id_macos()
            else:
                raise RuntimeError(f"Unsupported OS: {os_name}")
        except Exception as exc:
            raise RuntimeError(f"Unexpected error getting hardware ID: {exc}") from exc
        hardware_id = hardware_id.strip().lower()
        if not hardware_id:
            raise RuntimeError("Hardware ID is empty.")
        return hashlib.sha256(hardware_id.encode("utf-8")).digest()
    @staticmethod
    def verify_same_device(expected_device_id_hex: str) -> bool:
        import hmac
        try:
            current_fingerprint = DeviceIdentity.get_hardware_fingerprint()
            expected_bytes = bytes.fromhex(expected_device_id_hex)
            return hmac.compare_digest(current_fingerprint, expected_bytes)
        except Exception:
            return False
