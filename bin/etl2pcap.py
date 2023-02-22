#!/usr/bin/env python3
import argparse
import struct
from datetime import datetime

from etl.error import EtwVersionNotFound, EventIdNotFound, GuidNotFound
from etl.etl import IEtlFileObserver, build_from_stream
from etl.wintrace import WinTrace
from etl.event import Event
from etl.parsers.etw.Microsoft_Windows_NDIS_PacketCapture import Microsoft_Windows_NDIS_PacketCapture_1001_0
from etl.perf import PerfInfo
from etl.system import SystemTraceRecord
from etl.trace import Trace


class EtlFileLogger(IEtlFileObserver):
    """
    This a basic observer that log event
    """
    def __init__(self, file_stream):
        self.file_stream = file_stream

    def on_system_trace(self, obj: SystemTraceRecord):
        """ignore this kind of message"""

    def on_perfinfo_trace(self, obj: PerfInfo):
        """ignore this kind of message"""

    def on_trace_record(self, event: Trace):
        """ignore this kind of message"""

    def on_event_record(self, event: Event):
        try:
            etw = event.parse_etw()
            # we search for instance of Microsoft_Windows_NDIS_PacketCapture event id 1001 with version 0
            if not isinstance(etw, Microsoft_Windows_NDIS_PacketCapture_1001_0):
                return

            ft = datetime.utcfromtimestamp(event.source.event_header.timestamp / 10000000)
            t = (ft-datetime(1970, 1, 1)).total_seconds()

            self.file_stream.write(struct.pack("<IIII", int(t), ft.microsecond, etw.source.FragmentSize, etw.source.FragmentSize))
            self.file_stream.write(etw.source.Fragment)

        except (EtwVersionNotFound, EventIdNotFound, GuidNotFound):
            """ignore exception"""

    def on_win_trace(self, event: WinTrace):
        """ignore this kind of message"""


def main(input: str, output: str):
    """
    Main entry point
    :param input: input file path
    :param output: output path
    """

    with open(output, "wb") as output_file:
        output_file.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        with open(input, "rb") as input_file:
            etl_reader = build_from_stream(input_file.read())
            etl_reader.parse(EtlFileLogger(output_file))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    Convert your ETL Windows log files into PCAP files.
    Filter in ETW provider Microsoft-Windows-NDIS-PacketCapture {2ed6006e-4729-4609-b423-3ee7bcd678ef} on event ID 1001
    This is made with love by Airbus CERT Team.
    """)

    parser.add_argument("etlfile",
                        help="Path of input ETL file",
                        nargs=1,
                        type=str)
    parser.add_argument( "-o", "--output",
                        help="Path of output PCAP file",
                        type=str, default=None, required=False)

    args = parser.parse_args()
    etlfile = args.etlfile[0]
    if not os.path.isfile(etlfile):
        sys.exit("No ETL file specified or file does not exist.")

    pcapfile = args.output
    if not pcapfile:
        pcapfile = os.path.join(os.path.dirname(etlfile), os.path.basename(etlfile).replace(".etl", '') + ".pcap")
        print(f"Output file: {pcapfile}")
    main(etlfile, pcapfile)
