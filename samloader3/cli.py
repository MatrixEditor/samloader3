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

import os
import typing as t
import argparse

import shlex
import cmd
import signal
import traceback

from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from rich import print as pprint
from rich.table import Table
from rich.live import Live
from rich.tree import Tree
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
    SpinnerColumn,
    FileSizeColumn,
)
from rich.markup import escape

from samloader3.fus import (
    FUSClient,
    firmware_spec_url,
    FUS_USER_AGENT,
    v4_key,
    v2_key,
    AuthenticationError,
    XMLPathError,
)
from samloader3.firmware import FirmwareSpec, FirmwareInfo
from samloader3 import crypto, __version__


def _print_ok(msg) -> None:
    pprint(r"\[   [bold green]Ok[/]   ] " + msg)


def _print_error(msg) -> None:
    pprint(r"\[  [bold red]Error[/] ] " + msg)


def _print_info(msg) -> None:
    pprint(r"\[  [bold cyan]Info[/]  ] " + msg)


def _print_warn(msg) -> None:
    pprint(r"\[  [bold yellow]Warn[/]  ] " + msg)


class CLIExit(Exception):
    pass


class Task:
    """
    Base class for tasks in SamLoader3CLI.

    :param client: The FUSClient instance.
    :type client: FUSClient
    :param argv: The command line arguments.
    :type argv: argparse.Namespace
    """

    def __init__(self, client: FUSClient, argv) -> None:
        self.client = client
        self.argv = argv
        self.progress = self._progress()
        self.done_event = Event()
        signal.signal(signal.SIGINT, self.handle_sigint)

    def _progress(self) -> Progress:
        """
        Abstract method to be implemented by subclasses to provide progress tracking.

        :raises NotImplementedError: This method must be implemented by subclasses.
        """
        raise NotImplementedError

    def handle_sigint(self, signum, frame):
        """
        Signal handler for SIGINT.

        :param signum: The signal number.
        :type signum: int
        :param frame: The current stack frame.
        :type frame: frame
        """
        self.done_event.set()


class Decrypt(Task):
    """
    Task for decrypting a file.

    :param client: The FUSClient instance.
    :type client: FUSClient
    :param argv: The command line arguments.
    :type argv: argparse.Namespace
    """

    def _progress(self) -> Progress:
        """
        Provides progress tracking for the decryption task.

        :return: The progress tracker.
        :rtype: Progress
        """
        return Progress(
            SpinnerColumn(),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "-",
            FileSizeColumn(),
        )

    def run(self, path: str, key: bytes, key_version: str) -> None:
        """
        Runs the decryption task.

        :param path: The path to the file to decrypt.
        :type path: str
        :param key: The decryption key.
        :type key: bytes
        :param key_version: The version of the key.
        :type key_version: str
        """
        block_size = self.argv.block_size
        if block_size % 16 != 0:
            _print_error(f"Invalid block size: {block_size} % 16 != 0")
            return

        _print_info(f"Running with block_size = {block_size}")
        with self.progress:
            total_size = os.stat(path).st_size
            task = self.progress.add_task("Decrypting File", total=total_size)

            def update():
                self.progress.advance(task, block_size)

            try:
                crypto.file_decrypt(
                    path, self.argv.out, key, block_size, key_version, update
                )
            except ValueError:
                _print_error(
                    "[bold]Invalid Padding:[/] Most likely due to a wrong input file!"
                )


class Download(Task):
    """
    Task for downloading firmware.

    :param client: The FUSClient instance.
    :type client: FUSClient
    :param argv: The command line arguments.
    :type argv: argparse.Namespace
    """

    def __init__(self, client: FUSClient, argv) -> None:
        super().__init__(client, argv)
        self.names = []

    def handle_sigint(self, signum, frame):
        if not self.done_event.is_set():
            _print_info("Download canceled!")
        super().handle_sigint(signum, frame)

    def _progress(self) -> Progress:
        """
        Provides progress tracking for the download task.

        :return: The progress tracker.
        :rtype: Progress
        """
        return Progress(
            TextColumn("[bold]{task.fields[filename]}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "-",
            DownloadColumn(),
            "-",
            TransferSpeedColumn(),
            "-",
            TimeRemainingColumn(),
        )

    def do_download(self, task_id: TaskID, info: FirmwareInfo, path: str) -> None:
        """
        Initiates the download of firmware.

        :param task_id: The ID of the task.
        :type task_id: TaskID
        :param info: The firmware information.
        :type info: FirmwareInfo
        :param path: The path to save the downloaded firmware.
        :type path: str
        """
        self.client.init_download(info)
        if os.path.isdir(path):
            path = os.path.join(path, info.binary_name)

        start = 0
        if os.path.exists(path) and not self.argv.no_cache:
            start = os.stat(path).st_size

        result = self.client.start_download(info, start)
        total = int(result.headers["Content-Length"])
        self.progress.update(task_id, total=total, advance=start)
        self.progress.start_task(task_id)
        if start < total:
            with open(path, "wb") as dest_fp:
                for chunk in result.iter_content(self.argv.chunk_size):
                    if self.done_event.is_set():
                        return

                    if chunk:
                        dest_fp.write(chunk)
                        self.progress.update(task_id, advance=len(chunk))

        if self.argv.decrypt:
            self.progress.update(task_id, completed=0, filename="Decrypting file...")
            if path.endswith(".enc4"):
                _, dkey = v4_key(info)
                key_version = "enc4"
            elif path.endswith(".enc2"):
                _, dkey = v2_key(info.version, info.model_name, info.local_code)
                key_version = "enc2"
            else:
                _print_error(f"Could not find a suitable decryptor for {path}")
                return

            def update():
                self.progress.update(task_id, advance=self.argv.block_size)

            out = path.removesuffix(key_version)
            crypto.file_decrypt(
                path, out, dkey, self.argv.block_size, key_version, update
            )

    def run(self, specs: t.List[FirmwareSpec], model, region, imei) -> None:
        """
        Runs the firmware download task.

        :param specs: The list of firmware specifications to download.
        :type specs: List[FirmwareSpec]
        :param model: The model name.
        :type model: str
        :param region: The region.
        :type region: str
        :param imei: The serial/imei number.
        :type imei: str
        """
        data = []
        try:
            for spec in specs:
                data.append(
                    self.client.fw_info(spec.normalized_version, model, region, imei)
                )
        except XMLPathError as xml_exc:
            _print_error(f"Invalid returned XML document: {xml_exc}")
            pprint(ElementTree.tostring(xml_exc.doc).decode())
            return

        with self.progress:
            pool = None
            if self.argv.parallel:
                pool = ThreadPoolExecutor(max_workers=10)

            for info in data:
                if info.binary_name in self.names:
                    continue

                self.names.append(info.binary_name)
                task_id = self.progress.add_task(
                    "download", filename=info.binary_name, start=False
                )
                if pool is not None:
                    pool.submit(self.do_download, task_id, info, self.argv.dest)
                else:
                    self.do_download(task_id, info, self.argv.dest)
                if self.done_event.is_set():
                    return

            if pool:
                pool.shutdown(wait=True)


class SamLoader3CLI(cmd.Cmd):
    """
    SamLoader3 Command Line Interface.

    :param external_parsers: External parsers for additional commands.
    :type external_parsers: Optional[Dict[str, argparse.ArgumentParser]]
    :param timeout: The timeout for requests.
    :type timeout: Optional[int]
    :param user_agent: The user agent string.
    :type user_agent: Optional[str]
    :param model_name: The default model name.
    :type model_name: Optional[str]
    :param region: The default region.
    :type region: Optional[str]
    :param imei: The imei/serial number.
    :type imei: Optional[str]
    """

    prompt = "(sl3)> "

    #: internal registry that stores all parsers
    parsers: t.Dict[str, argparse.ArgumentParser]

    #: the active FUS client
    client: FUSClient

    def __init__(
        self,
        external_parsers: t.Optional[t.Dict[str, argparse.ArgumentParser]] = None,
        timeout: t.Optional[int] = 0x61A8,
        user_agent: t.Optional[str] = None,
        model_name: t.Optional[str] = None,
        region: t.Optional[str] = None,
        imei: t.Optional[str] = None,
    ) -> None:
        super().__init__()
        self.parsers = external_parsers or {}
        self.client = FUSClient(user_agent, timeout)
        self.model = model_name
        self.region = region
        self.imei = imei
        self.setup_parsers()

        for name, parser in self.parsers.items():
            setattr(self, f"do_{name}", lambda args, name=name: self._run(name, args))
            setattr(self, f"help_{name}", lambda parser=parser: parser.print_help())

    def setup_parsers(self) -> None:
        """
        Sets up the parsers for the CLI commands.
        """
        info_mod = argparse.ArgumentParser("list")
        info_mod.add_argument(
            "-q",
            "--quiet",
            help="only print normalized version numbers",
            action="store_true",
        )
        info_mod.add_argument(
            "-l", "--latest", help="only print latest", action="store_true"
        )
        info_mod.add_argument(
            "version",
            nargs="*",
            help="print details about version",
            type=str,
        )
        info_mod.add_argument("-m", "--model", required=False)
        info_mod.add_argument("-r", "--region", required=False)
        info_mod.add_argument("-i", "--imei", required=False)
        info_mod.set_defaults(fn=self._list_info)
        self.parsers["list"] = info_mod

        download_mod = argparse.ArgumentParser("download")
        download_mod.add_argument("versions", nargs="+")
        download_mod.add_argument("-m", "--model", required=False)
        download_mod.add_argument("-r", "--region", required=False)
        download_mod.add_argument("-i", "--imei", required=False)
        download_mod.add_argument("--chunk-size", type=int, default=32768)
        download_mod.add_argument("-o", "--out", dest="dest", type=str, required=True)
        download_mod.add_argument("--no-cache", action="store_true")
        download_mod.add_argument("--decrypt", action="store_true")
        download_mod.add_argument("--parallel", action="store_true")
        download_mod.add_argument("--block-size", type=int, default=4096)
        download_mod.set_defaults(fn=self._download)
        self.parsers["download"] = download_mod

        decrypt_mod = argparse.ArgumentParser("decrypt")
        decrypt_mod.add_argument("path")
        decrypt_mod.add_argument("-m", "--model", required=False)
        decrypt_mod.add_argument("-r", "--region", required=False)
        decrypt_mod.add_argument("-i", "--imei", required=False)
        decrypt_mod.add_argument("--key-only", action="store_true")
        decrypt_mod.add_argument("-v", "--version", required=True)
        decrypt_mod.add_argument("-o", "--out", default=".")
        decrypt_mod.add_argument("--block-size", type=int, default=4096)
        decrypt_mod.set_defaults(fn=self._decrypt)
        self.parsers["decrypt"] = decrypt_mod

    def _run(self, name: str, args) -> None:
        """
        Runs a command.

        :param name: The name of the command.
        :type name: str
        :param args: The command arguments.
        :type args: str
        """
        argv = self.parsers[name].parse_args(shlex.split(args))
        argv.fn(argv)

    def do_exit(self, args) -> None:
        """
        Handles the exit command.
        """
        raise CLIExit

    def do_version(self, args) -> None:
        """Prints the library's version"""
        pprint(f"[bold]Version:[/] {__version__}")

    def do_setmodel(self, args) -> None:
        """Sets the model name to use"""
        self.model = args

    def do_setregion(self, args) -> None:
        """Sets the region code to use"""
        self.region = args

    def do_setimei(self, args) -> None:
        """Sets the imei/serial code to use"""
        self.imei = args

    def default(self, line) -> None:
        _print_warn(f"[bold]Unknown syntax:[/] {line}")

    def get_names(self):
        """
        Retrieves all command names.

        :return: The command names.
        :rtype: List[str]
        """
        return list(set(super().get_names() + dir(self)))

    def get_model(self, argv) -> t.Optional[str]:
        """
        Gets the model from command line arguments.

        :param argv: The command line arguments.
        :type argv: argparse.Namespace
        :return: The model name.
        :rtype: Optional[str]
        """
        return argv.model or self.model

    def get_region(self, argv) -> t.Optional[str]:
        """
        Gets the region from command line arguments.

        :param argv: The command line arguments.
        :type argv: argparse.Namespace
        :return: The region.
        :rtype: Optional[str]
        """
        return argv.region or self.region

    def get_imei(self, argv) -> t.Optional[str]:
        """
        Gets the region from command line arguments.

        :param argv: The command line arguments.
        :type argv: argparse.Namespace
        :return: The imei/serial number.
        :rtype: Optional[str]
        """
        return argv.imei or self.imei

    def get_candidates(
        self, specs, versions, include_all=False
    ) -> t.List[FirmwareSpec]:
        """
        Gets the firmware candidates.

        :param specs: The firmware specifications.
        :type specs: FirmwareSpec
        :param versions: The requested versions.
        :type versions: List[str]
        :param include_all: Whether to include all versions.
        :type include_all: bool
        :return: The list of firmware candidates.
        :rtype: List[FirmwareSpec]
        """
        all_specs = [specs.latest] + specs.upgrade
        candidates = list(
            filter(lambda x: x.normalized_version in versions or include_all, all_specs)
        )
        if len(candidates) == 0:
            _print_error(f"Could not find version in '{escape(str(versions))}'")
        return candidates

    ### IMPLEMENTATION ###
    def _connect(self) -> bool:
        if not self.client.auth.encrypted_nonce:
            try:
                self.client.setup()
            except AuthenticationError:
                _print_error("Could not connect to FUS-Server (invalid credentials)")
                return False
            if not self.client.auth.encrypted_nonce:
                _print_error("Could not connect to FUS-Server!")
                return False
        _print_ok("Connection to FUS-Server")
        return True

    def _verify_device_info(self, argv) -> bool:
        model = self.get_model(argv)
        region = self.get_region(argv)
        if not model or not region:
            _print_error("[bold]Device:[/] No device specified!")
            return False

        imei = self.get_imei(argv)
        if not imei:
            _print_error("[bold]Device:[/] IMEI not specified!")
            return False

        _print_ok(f"[bold]Device:[/] {model}/{region}/{imei}")
        return True

    def _verify_specs(self, model, region) -> bool:
        url = firmware_spec_url(model, region)
        if not self.client.firmware_exists(model, region):
            _print_error(f"Could not locate device firmware at {url}")
            return False

        _print_ok(f"Firmware spec at {url}")
        return True

    def _list_info(self, argv) -> None:
        if not self._verify_device_info(argv) or not self._connect():
            return

        model = self.get_model(argv)
        region = self.get_region(argv)
        imei = self.get_imei(argv)
        if not self._verify_specs(model, region):
            return

        specs = self.client.get_firmware_specs(model, region)
        pprint("\n[bold]Firmware Specifications:[/]")
        if argv.quiet:
            print(specs.latest.normalized_version)
            if not argv.latest:
                for upgrade in specs.upgrade:
                    print(upgrade.normalized_version)
            return

        versions = argv.version
        if "" in versions:
            versions.remove("")
        try:
            if len(argv.version) == 0:
                table = Table(title="Detailed Version Info")
                table.add_column("OS Version", justify="left", no_wrap=True)
                table.add_column("Version", justify="center")
                table.add_column("Latest", justify="center")

                with Live(table, refresh_per_second=4):
                    info = self.client.fw_info(
                        specs.latest.normalized_version, model, region, imei
                    )
                    table.add_row(
                        info.current_os_version, info.version, "[green]True[/]"
                    )
                    if not argv.latest:
                        for upgrade in specs.upgrade:
                            info = self.client.fw_info(
                                upgrade.normalized_version, model, region, imei
                            )
                            table.add_row(
                                info.current_os_version, info.version, "[red]False[/]"
                            )
            else:
                load_all = argv.version[0] == "*"
                candidates = self.get_candidates(specs, argv.version, load_all)
                if len(candidates) != 1:
                    return

                spec = candidates[0]
                info = self.client.fw_info(spec.normalized_version, model, region, imei)
                tree = Tree(f"({model}): {info.version}")
                for key, value in info.entries.items():
                    if value is not None:
                        tree.add(f'[italic]{key}[/] -> "{value}"')
                pprint(tree)
        except XMLPathError as xml_exc:
            _print_error(f"XML Error: {xml_exc} - Most likely due to an incompatible IMEI!")
            pprint(ElementTree.tostring(xml_exc.doc).decode())

    def _download(self, argv) -> None:
        if not self._verify_device_info(argv) or not self._connect():
            return

        model = self.get_model(argv)
        region = self.get_region(argv)
        imei = self.get_imei(argv)
        versions = argv.versions

        load_all = versions[0] == "*"
        if not load_all and not self._verify_specs(model, region):
            return

        specs = self.client.get_firmware_specs(model, region)
        candidates = self.get_candidates(specs, versions, include_all=load_all)
        if len(candidates) == 0:
            return

        _print_info(f"Initialising Download of {len(candidates)} candidates...")
        downloader = Download(self.client, argv)
        downloader.run(candidates, model, region, imei)

    def _decrypt(self, argv) -> None:
        if not self._verify_device_info(argv):
            return

        model = self.get_model(argv)
        region = self.get_region(argv)
        imei = self.get_imei(argv)

        version = argv.version
        path = str(argv.path)
        key_version = None
        if path.endswith(".enc4"):
            if not self._connect() or not self._verify_specs(model, region):
                return

            info = self.client.fw_info(version, model, region, imei)
            key, dkey = v4_key(info)
            key_version = "enc4"

        elif path.endswith(".enc2"):
            key, dkey = v2_key(version, model, region)
            key_version = "enc2"
        else:
            _print_error(f"Could not find a suitable decryptor for {path}")
            return

        _print_ok(f"[bold]Key:[/] {key}, [bold]MD5:[/] {dkey}")
        if not argv.key_only:
            decryptor = Decrypt(self.client, argv)
            decryptor.run(path, dkey, key_version)


def run_with_args(args: t.Optional[t.List[str]] = None) -> None:
    """
    Main entry point to run the SamLoader3CLI with command-line arguments.

    :param args: Optional list of command-line arguments.
    :type args: t.Optional[t.List[str]]
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-U", "--user-agent", default=FUS_USER_AGENT)
    parser.add_argument("-R", "--region", required=False)
    parser.add_argument("-M", "--model", required=False)
    parser.add_argument("-I", "--imei", required=False)
    parser.add_argument("-T", "--timeout", default=0x61A8, type=int)

    argv = parser.parse_args(args)
    cli = SamLoader3CLI(
        timeout=argv.timeout,
        user_agent=argv.user_agent,
        model_name=argv.model,
        region=argv.region,
        imei=argv.imei,
    )
    while True:
        try:
            cli.cmdloop()
        except (SystemExit, KeyboardInterrupt):
            print()
        except CLIExit:
            break
        except Exception as e:
            _print_error(f"[bold]{e.__class__.__name__}[/]: {str(e)}")
            traceback.print_exc()
