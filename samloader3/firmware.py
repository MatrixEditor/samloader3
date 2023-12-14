from __future__ import annotations

import dataclasses as dc
import typing as t
import enum


class BinaryNature(enum.IntEnum):
    HOME = 0
    FACTORY = 1


class EncryptionType(enum.Enum):
    V4 = "enc4"
    V2 = "enc2"


@dc.dataclass(frozen=True)
class FirmwareInfo:
    """Represents information about firmware."""

    #: The version of the firmware.
    version: str

    #: A dictionary containing various firmware entries.
    entries: t.Dict[str, t.Optional[str]]

    @property
    def local_code(self) -> str:
        """Local code associated with the firmware."""
        return self.entries["DEVICE_LOCAL_CODE"]

    @property
    def model_name(self) -> str:
        """Model name associated with the firmware."""
        return self.entries["DEVICE_MODEL_NAME"]

    @property
    def model_path(self) -> str:
        """Model path associated with the firmware."""
        return self.entries["MODEL_PATH"]

    @property
    def description(self) -> str:
        """Description of the firmware."""
        return self.entries["DESCRIPTION"]

    @property
    def logic_value_home(self) -> str:
        """Logic value for a home binary."""
        return self.entries["LOGIC_VALUE_HOME"]

    @property
    def logic_value_factory(self) -> str:
        """Logic value for a factory binary."""
        return self.entries["LOGIC_VALUE_FACTORY"]

    @property
    def current_os_version(self) -> str:
        """Current operating system version."""
        return self.entries["CURRENT_OS_VERSION"]

    @property
    def binary_name(self) -> str:
        """Name of the binary."""
        return self.entries["BINARY_NAME"]

    @property
    def binary_nature(self) -> BinaryNature:
        """Nature of the binary (:class:`BinaryNature`)."""
        return BinaryNature(int(self.entries["BINARY_NATURE"]))

    @property
    def binary_byte_size(self) -> int:
        """Size of the binary in bytes."""
        return int(self.entries["BINARY_BYTE_SIZE"])

    @property
    def encryption_type(self) -> EncryptionType:
        """The encryption type of this firmware"""
        return EncryptionType(self.binary_name[-4:])


@dc.dataclass(frozen=True)
class FirmwareSpec:
    """Represents specifications for firmware."""

    #: The version of the firmware.
    version: str

    #: Optional Android version associated with the firmware.
    android_version: t.Optional[str] = None

    #: Optional file size of the firmware.
    file_size: t.Optional[int] = 0

    #: Optional revision count. (maybe)
    rcount: t.Optional[int] = 0

    @property
    def normalized_version(self) -> str:
        """
        Get the normalized version format.
        """
        parts = self.version.split("/")
        if len(parts) == 3:
            parts.append(parts[0])
        if not parts[2]:
            parts[2] = parts[0]
        return "/".join(parts)


@dc.dataclass(frozen=True)
class VersionInfo:
    """Represents version information."""

    #: Model associated with the version information.
    model: str

    #: Local code associated with the version information.
    local_code: str

    #: latest firmware specification.
    latest: t.Optional[FirmwareSpec] = None

    #: List of firmware specifications for upgrades.
    upgrade: t.List[FirmwareSpec] = dc.field(default_factory=list)
