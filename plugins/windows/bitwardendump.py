import logging
from typing import List
import re
import json

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, cmdline, vadinfo

import binary2strings

vollog = logging.getLogger(__name__)


class BitwardenDump(interfaces.plugins.PluginInterface):
    """Dumps credentials from an unlocked Bitwarden vault in Chrome/Firefox"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="cmdline", component=cmdline.CmdLine, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Manually specifies process IDs where the extension is running",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed DLLs",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def find_potential_processes(
            cls, context: interfaces.context.ContextInterface, kernel_table_name: str, layer_name: str
    ):
        """
        Finds browser processes where the Bitwarden extension could be running
        """
        procs = []
        for proc in pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=kernel_table_name
        ):
            try:
                proc_name = proc.ImageFileName.cast(
                    "string", max_length=proc.ImageFileName.vol.count, errors="replace"
                )
                if (
                    proc_name == "chrome.exe"
                    and
                    "--extension-process" in cmdline.CmdLine.get_cmdline(context,
                                                                         kernel_table_name,
                                                                         proc)
                ) or (
                    proc_name == "firefox.exe"
                    and
                    "tab" in cmdline.CmdLine.get_cmdline(context,
                                                         kernel_table_name,
                                                         proc)
                ):
                    procs.append(proc)
            except Exception as ex:
                vollog.debug(f"Error checking process info: {ex}")

        if not procs:
            vollog.error("No browser processes found")

        return procs

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        protect_values = vadinfo.VadInfo.protect_values(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name
        )

        seen_creds = set()

        for proc in procs:
            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as ex:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        proc_id, ex.invalid_address, ex.layer_name
                    )
                )
                continue

            proc_layer = self.context.layers[proc_layer_name]
            memory_dump = bytearray()

            for vad in sorted(list(vadinfo.VadInfo.list_vads(proc)), key=lambda x: x.get_start()):
                vad_start = vad.get_start()
                vad_size = vad.get_size()
                protection = vad.get_protection(
                    protect_values,
                    vadinfo.winnt_protections
                )
                private = int(vad.get_private_memory())
                if private and protection == 'PAGE_READWRITE' and vad_size < 64 * 1024 * 1024:
                    try:
                        chunk_size = 1024 * 1024 * 10
                        offset = vad_start
                        while offset < vad_start + vad_size:
                            to_read = min(chunk_size, vad_start + vad_size - offset)
                            data = proc_layer.read(offset, to_read, pad=True)
                            if not data:
                                break
                            memory_dump.extend(data)
                            offset += to_read
                    except Exception as ex:
                        vollog.debug(f"Error dumping VAD: {ex}")
                        continue

            strings = ''.join([
                x[0]
                for x in binary2strings.extract_all_strings(bytes(memory_dump), 128, only_interesting=True)
            ])

            for match in re.findall(r"\"login\":({\"username\":\".*?]}),\"", strings):
                try:
                    creds_json = json.loads(match)
                    creds = (
                        creds_json["uris"][0]['_uri'] if creds_json["uris"] else "",
                        creds_json["username"],
                        creds_json["password"]
                    )
                    if creds not in seen_creds:
                        seen_creds.add(creds)
                        yield (
                            0,
                            (
                                proc.UniqueProcessId,
                                *creds
                            )
                        )
                except Exception as ex:
                    vollog.debug(f"Failed to parse credential match: {ex}")

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]

        if not self.config.get("pid"):
            procs = self.find_potential_processes(self.context, kernel.symbol_table_name, kernel.layer_name)
        else:
            procs = pslist.PsList.list_processes(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
                filter_func=pslist.PsList.create_pid_filter(self.config.get("pid")),
            )

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("URL", str),
                ("Username", str),
                ("Password", str)
            ],
            self._generator(
                procs
            ),
        )
