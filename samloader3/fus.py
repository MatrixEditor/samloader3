# Copyright (C) 2023 MatrixEditor
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import typing as t
import dataclasses as dc
import hashlib

from xml.etree import ElementTree

import requests

from samloader3.firmware import FirmwareInfo, BinaryNature, FirmwareSpec, VersionInfo
from samloader3.crypto import get_logic_check, get_nonce, get_signature

from ._util import xml_find

# General constants
FUS_CLOUD_DOMAIN = "cloud-neofussvr.samsungmobile.com"
FUS_DOMAIN = "neofussvr.sslcs.cdngc.net"

FW_SPEC_DOMAIN = "fota-cloud-dn.ospserver.net"

NF_DownloadGenerateNonce = "NF_DownloadGenerateNonce"
NF_DownloadBinaryInform = "NF_DownloadBinaryInform"
NF_DownloadBinaryInitForMass = "NF_DownloadBinaryInitForMass"
NF_DownloadBinaryForMass = "NF_DownloadBinaryForMass"

FUS_USER_AGENT = "Kies2.0_FUS"
FUS_XML_VERSION = "1.0"

XML_MSG = "FUSMsg"
XML_HDR = "FUSHdr"
XML_BODY = "FUSBody"
XML_PROTO_VER = "ProtoVer"
XML_DATA = "Data"
XML_PUT = "Put"


class AuthenticationError(Exception):
    """
    Custom exception for authentication errors.
    """


def FUSHdr(message: ElementTree.Element, version: str = FUS_XML_VERSION) -> None:
    """
    Adds a header to the given XML message.

    :param message: The XML message to which the header is added.
    :type message: ElementTree.Element
    :param version: The protocol version for the header.
    :type version: str
    """
    header = ElementTree.SubElement(message, XML_HDR)
    ElementTree.SubElement(header, XML_PROTO_VER).text = version


def FUSBody(message: ElementTree.Element, data: t.Dict[str, t.Any]) -> None:
    """
    Adds a body with specified data to the given XML message.

    :param message: The XML message to which the body is added.
    :type message: ElementTree.Element
    :param data: A dictionary containing data to be included in the body.
    :type data: dict
    """
    body_doc = ElementTree.SubElement(message, XML_BODY)
    body = ElementTree.SubElement(body_doc, XML_PUT)
    for key, value in data.items():
        tag = ElementTree.SubElement(body, key)
        # make sure we convert the value to string
        ElementTree.SubElement(tag, "Data").text = str(value)


def FUSMsg(
    data: t.Dict[str, t.Any], version: str = FUS_XML_VERSION
) -> ElementTree.Element:
    """
    Creates an XML message with the specified data.

    :param data: A dictionary containing data to be included in the message body.
    :type data: dict
    :param version: The protocol version for the header.
    :type version: str
    :return: The created XML message.
    :rtype: ElementTree.Element
    """
    document = ElementTree.Element(XML_MSG)
    FUSHdr(document, version)
    FUSBody(document, data)
    return document


def firmware_spec_url(model_name: str, local_code: str) -> str:
    """
    Generates the URL for fetching firmware specifications.

    :param model_name: The model name for the firmware.
    :type model_name: str
    :param local_code: The local code for the firmware.
    :type local_code: str
    :return: The generated URL for fetching firmware specifications.
    :rtype: str
    """
    return f"https://{FW_SPEC_DOMAIN}/firmware/{local_code}/{model_name}/version.xml"


def v4_key(
    info: FirmwareInfo, nature: BinaryNature = BinaryNature.FACTORY
) -> t.Tuple[str, bytes]:
    """
    Generates a version 4 key for the provided firmware information.

    :param info: The firmware information.
    :type info: FirmwareInfo
    :param nature: The binary nature (BinaryNature).
    :type nature: BinaryNature
    :return: A tuple containing the key as a string and its MD5 digest.
    :rtype: tuple[str, bytes]
    """
    nonce = (
        info.logic_value_factory
        if nature == BinaryNature.FACTORY
        else info.logic_value_home
    )
    key = get_logic_check(info.version, nonce)
    return key, hashlib.md5(key.encode()).digest()


def v2_key(version: str, model_name: str, local_code: str) -> t.Tuple[str, bytes]:
    """
    Generates a version 2 key for the specified parameters.

    :param version: The firmware version.
    :type version: str
    :param model_name: The model name for the firmware.
    :type model_name: str
    :param local_code: The local code for the firmware.
    :type local_code: str
    :return: A tuple containing the key as a string and its MD5 digest.
    :rtype: tuple[str, bytes]
    """
    key = f"{local_code}:{model_name}:{version}"
    return key, hashlib.md5(key.encode()).digest()


@dc.dataclass
class FUSAuthorization:
    """
    Represents FUS (Firmware Update Server ?) authorization information.

    :param encrypted_nonce: The encrypted nonce.
    :type encrypted_nonce: str
    :param signature: The signature.
    :type signature: str
    :param nc: The nonce count.
    :type nc: str
    :param type: The authorization type.
    :type type: str
    :param realm: The authentication realm.
    :type realm: str
    :param newauth: Flag indicating new authentication.
    :type newauth: str
    """

    encrypted_nonce: str = ""
    signature: str = ""
    nc: str = ""
    type: str = ""
    realm: str = ""
    newauth: str = "1"

    def __str__(self) -> str:
        """
        Returns a string representation of the FUSAuthorization object.

        :return: A string representation of the object.
        :rtype: str
        """
        return (
            f'FUS nonce="{self.encrypted_nonce}", signature="{self.signature}", '
            f'nc="{self.nc}", type="{self.type}", realm="{self.realm}", '
            f'newauth="{self.newauth}"'
        )


class FUSClient:
    """
    Represents a client for interacting with the Firmware Update Server (FUS).

    :param user_agent: The user agent to use in HTTP requests.
    :type user_agent: str, optional
    :param timeout: The timeout for HTTP requests in seconds.
    :type timeout: int, optional
    """

    def __init__(
        self, user_agent: t.Optional[str] = None, timeout: int = 0x61A8
    ) -> None:
        self.auth = FUSAuthorization()
        self.session_id = ""
        self.nonce = ""
        self.user_agent = user_agent or FUS_USER_AGENT
        self.timeout = timeout

    @property
    def authv(self) -> str:
        """The string representation of the authentication information."""
        return str(self.auth)

    def setup(self) -> None:
        """
        Sets up the FUS client by generating a nonce.

        :return: None
        """
        self.request(NF_DownloadGenerateNonce, method="GET")

    def request(
        self,
        key: str,
        method="POST",
        payload: t.Optional[str] = None,
        query: t.Optional[str] = None,
        headers: t.Optional[t.Dict[str, t.Any]] = None,
        as_stream=False,
        from_cloud=False,
    ) -> requests.Response:
        """
        Makes a request to the FUS server.

        :param key: The key for the request.
        :type key: str
        :param method: The HTTP method for the request (default is "POST").
        :type method: str, optional
        :param payload: The payload for the request.
        :type payload: str, optional
        :param query: The query parameters for the request.
        :type query: str, optional
        :param headers: Additional headers for the request.
        :type headers: dict, optional
        :param as_stream: Flag indicating if the response should be streamed.
        :type as_stream: bool, optional
        :param from_cloud: Flag indicating if the request is to the cloud domain.
        :type from_cloud: bool, optional
        :return: The response from the FUS server.
        :rtype: requests.Response
        """
        domain = FUS_CLOUD_DOMAIN if from_cloud else FUS_DOMAIN
        url = f"https://{domain}/{key}.do"
        if query:
            url = f"{url}?{query}"

        headers = headers or {}
        headers.update(
            {
                "Authorization": self.authv,
                "User-Agent": self.user_agent,
            }
        )
        cookies = {"JSESSIONID": self.session_id}
        result = requests.request(
            method,
            url,
            data=payload or "",
            headers=headers,
            cookies=cookies,
            timeout=self.timeout,
            stream=as_stream,
        )
        if "NONCE" in result.headers:
            self.auth.encrypted_nonce = result.headers["NONCE"]
            self.nonce = get_nonce(self.auth.encrypted_nonce)
            self.auth.signature = get_signature(self.nonce)

        if "JSESSIONID" in result.cookies:
            self.session_id = result.cookies["JSESSIONID"]

        return result

    def fw_info(
        self,
        version: str,
        model_name: str,
        local_code: str,
        imei: str,
        nature: BinaryNature = BinaryNature.FACTORY,
        client_product: t.Optional[str] = None,
    ) -> FirmwareInfo:
        """
        Retrieves firmware information from the FUS server.

        :param version: The firmware version.
        :type version: str
        :param model_name: The model name.
        :type model_name: str
        :param local_code: The local code.
        :type local_code: str
        :param imei: The imei/serial number.
        :type imei: str
        :param nature: The binary nature.
        :type nature: BinaryNature, optional
        :param client_product: The client product name (default is "Smart Switch").
        :type client_product: str, optional
        :return: The firmware information.
        :rtype: FirmwareInfo
        """
        xml = FUSMsg(
            {
                "ACCESS_MODE": 2,
                "BINARY_NATURE": str(nature.value),
                "CLIENT_PRODUCT": client_product or "Bogus",
                "CLIENT_VERSION": "4.3.23123_1",
                "DEVICE_IMEI_PUSH": imei,
                "DEVICE_FW_VERSION": version,
                "DEVICE_LOCAL_CODE": local_code,
                "DEVICE_MODEL_NAME": model_name,
                "LOGIC_CHECK": get_logic_check(version, self.nonce),
            }
        )
        payload = ElementTree.tostring(xml, encoding="utf-8")
        result = self.request(NF_DownloadBinaryInform, payload=payload)
        # TODO:  validate response
        try:
            doc = ElementTree.fromstring(result.text)
        except ElementTree.ParseError:
            print(result.text)
        entries = {}
        for potential_entry in xml_find(doc, "./FUSBody/Put"):
            data = potential_entry.find("./Data")
            if data is None:
                continue

            entries[potential_entry.tag] = data.text

        return FirmwareInfo(version, entries)

    def init_download(self, info: FirmwareInfo) -> None:
        """
        Initializes the firmware download.

        :param info: The firmware information.
        :type info: FirmwareInfo
        :return: None
        """
        logic_input = info.binary_name.split(".")[0][-16:]
        xml = FUSMsg(
            {
                "BINARY_FILE_NAME": info.binary_name,
                "LOGIC_CHECK": get_logic_check(logic_input, self.nonce),
            }
        )
        self.request(
            NF_DownloadBinaryInitForMass,
            payload=ElementTree.tostring(xml, encoding="utf-8"),
        )

    def start_download(self, info: FirmwareInfo, start=0) -> requests.Response:
        """
        Starts the firmware download.

        :param info: The firmware information.
        :type info: FirmwareInfo
        :param start: The starting position for the download (default is 0).
        :type start: int, optional
        :return: The response from the FUS server.
        :rtype: requests.Response
        """
        return self.request(
            NF_DownloadBinaryForMass,
            method="GET",
            query=f"file={info.model_path}{info.binary_name}",
            headers={"start": str(start)},
            from_cloud=True,
            as_stream=True,
        )

    def firmware_exists(self, model_name: str, local_code: str) -> bool:
        """
        Checks if firmware exists for a given model and local code.

        :param model_name: The model name.
        :type model_name: str
        :param local_code: The local code.
        :type local_code: str
        :return: True if firmware exists, False otherwise.
        :rtype: bool
        """
        try:
            url = firmware_spec_url(model_name, local_code)
            result = requests.get(
                url, timeout=0x61A8, headers={"User-Agent": self.user_agent}
            )
            return result.status_code == 200
        except requests.Timeout:
            return False

    def get_firmware_specs(self, model_name: str, local_code: str) -> VersionInfo:
        """
        Retrieves firmware specifications for a given model and local code.

        :param model_name: The model name.
        :type model_name: str
        :param local_code: The local code.
        :type local_code: str
        :return: The firmware version information.
        :rtype: VersionInfo
        """
        url = firmware_spec_url(model_name, local_code)
        result = requests.get(
            url, timeout=0x61A8, headers={"User-Agent": self.user_agent}
        )
        if result.status_code != 200:
            raise AuthenticationError

        document = ElementTree.fromstring(result.text)
        model = xml_find(document, "./firmware/model", text=True)
        cc = xml_find(document, "./firmware/cc", text=True)
        versions = xml_find(document, "./firmware/version")

        latest = document.find("./firmware/version/latest")
        if latest is not None:
            latest = FirmwareSpec(str(latest.text), str(latest.get("o")))

        info = VersionInfo(model, cc, latest)
        for upgrade in versions.find("upgrade") or []:
            info.upgrade.append(
                FirmwareSpec(
                    str(upgrade.text),
                    file_size=int(upgrade.get("fwsize")),
                    rcount=int(upgrade.get("rcount")),
                )
            )
        return info
