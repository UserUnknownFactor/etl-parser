#!/usr/bin/env python3
import argparse, os, sys

from xml.etree import ElementTree
from xml.etree.ElementTree import Element
from xml.dom.minidom import parseString

from construct import ListContainer, Struct, Container

from etl.error import GroupNotFound, VersionNotFound, EventTypeNotFound, EtwVersionNotFound, EventIdNotFound, \
    GuidNotFound, TlMetaDataNotFound, InvalidType
from etl.etl import IEtlFileObserver, build_from_stream
from etl.parsers.etw.core import Guid
from etl.wintrace import WinTrace
from etl.event import Event
from etl.parsers.kernel import FileIo_V2_Name, ImageLoad, DiskIo_TypeGroup1, \
    Process_V3_TypeGroup1, Process_V4_TypeGroup1, Process_Defunct_TypeGroup1, ImageLoadProcess
from etl.parsers.kernel.core import Mof
from etl.parsers.kernel.io import DiskIo_TypeGroup3
from etl.parsers.tracelogging import TraceLogging
from etl.perf import PerfInfo
from etl.system import SystemTraceRecord
from etl.trace import Trace


def add_attribute(parent: Element, name: str, value: str):
    attribute = ElementTree.SubElement(parent, "attribute")
    attribute.set("name", name)
    attribute.set("value", value)


def log_kernel_type(mof_object: Mof, xml: Element):
    """
    Log mof object into stdout
    :param mof_object: Mof object to log
    """

    if isinstance(mof_object, FileIo_V2_Name):
        type_name = {
            0: "Name",
            32: "FileCreate",
            35: "FileDelete",
            36: "FileRundown"
        }
        xml.set("type", type_name[mof_object.event_type])

    elif isinstance(mof_object, ImageLoad):
        type_name = {
            10: "Load",
            2: "Unload",
            3: "DCStart",
            4: "DCEnd"
        }
        xml.set("type", type_name[mof_object.event_type])

    elif isinstance(mof_object, DiskIo_TypeGroup1):
        type_name = {
            10: "Read",
            11: "Write",
            55: "OpticalRead",
            56: "OpticalWrite"
        }
        xml.set("type", type_name[mof_object.event_type])

    elif isinstance(mof_object, DiskIo_TypeGroup3):
        type_name = {
            14: "FlushBuffers",
            57: "OpticalFlushBuffers"
        }
        xml.set("type", type_name[mof_object.event_type])

    elif isinstance(mof_object, Process_V3_TypeGroup1):
        type_name = {
            1: "Start",
            2: "End",
            3: "DCStart",
            4: "DCEnd",
            39: "Defunct"
        }
        xml.set("type", type_name[mof_object.event_type])

    elif isinstance(mof_object, Process_V4_TypeGroup1):
        type_name = {
            1: "Start",
            2: "End",
            3: "DCStart",
            4: "DCEnd",
            39: "Defunct"
        }
        xml.set("type", type_name[mof_object.event_type])

    elif isinstance(mof_object, Process_Defunct_TypeGroup1):
        xml.set("type", "zombie")

    elif isinstance(mof_object, ImageLoadProcess):
        type_name = {
            10: "Load",
            2: "Unload",
            3: "DCStart",
            4: "DCEnd"
        }
        xml.set("type", type_name[mof_object.event_type])

    return xml


def log_construct_pattern(xml: Element, pattern: Struct, source: Container):
    """
    Log a Construct pattern
    :param xml: xml element
    :param pattern: Pattern use by construct
    :param source: Element parsed
    :return: XML Element
    """

    for field in pattern.subcons:
        # check for string
        if hasattr(source[field.name], "type"):
            if source[field.name].type == "WString":
                add_attribute(xml, field.name, bytearray(source[field.name].string[:-2]).decode("utf-16le"))
            elif source[field.name].type == "CString":
                add_attribute(xml, field.name, bytearray(source[field.name].string[:-1]).decode("ascii"))
            else:
                raise InvalidType()
        elif isinstance(source[field.name], ListContainer):
            add_attribute(xml, field.name, bytearray(source[field.name]).hex())
        elif isinstance(source[field.name],  bytes):
            add_attribute(xml, field.name, source[field.name].hex())
        elif isinstance(source[field.name], Container):
            continue
        else:
            add_attribute(xml, field.name, str(source[field.name]))


def log_tracelogging(obj: TraceLogging) -> Element:
    """
    Print a trace logging event
    :param obj: tracelogging object
    """
    xml = ElementTree.Element("tracelogging")
    xml.set("name", obj.get_name())
    for k, v in obj.items():
        if hasattr(v, "type") and v.type == "Guid":
            add_attribute(xml, k, str(Guid(v.inner.data1, v.inner.data2, v.inner.data3, v.inner.data4)))
        else:
            add_attribute(xml, k, str(v))
    return xml


class EtlFileLogger(IEtlFileObserver):
    """
    This a basic observer that log event
    """
    def __init__(self):
        self.xml_document = ElementTree.Element("etl")

    def on_system_trace(self, obj: SystemTraceRecord):
        try:
            mof = obj.get_mof()
            data = ElementTree.SubElement(self.xml_document, "event")
            data.set("type", "system")
            data.set("PID", str(obj.get_process_id()))
            data.set("TID", str(obj.get_thread_id()))
            xml = ElementTree.SubElement(data, "mof")
            xml.set("provider", mof.__class__.__name__)
            log_kernel_type(mof, xml)
            log_construct_pattern(xml, mof.pattern, mof.source)

        except (GroupNotFound, VersionNotFound, EventTypeNotFound) as e:
            print(e)

    def on_perfinfo_trace(self, obj: PerfInfo):
        try:
            mof = obj.get_mof()
            data = ElementTree.SubElement(self.xml_document, "event")
            data.set("type", "perfinfo")
            data.set("timestamp", obj.get_utc_timestamp())
            xml = ElementTree.SubElement(data, "mof")
            xml.set("provider", mof.__class__.__name__)
            log_kernel_type(mof, xml)
            log_construct_pattern(xml, mof.pattern, mof.source)
        except (GroupNotFound, VersionNotFound, EventTypeNotFound) as e:
            print(e)

    def on_trace_record(self, event: Trace):
        pass

    def on_event_record(self, event: Event):
        try:
            data = ElementTree.Element("event")
            data.set("type", "event")
            data.set("timestamp", event.get_utc_timestamp())
            data.set("PID", str(event.get_process_id()))
            data.set("TID", str(event.get_thread_id()))
            data.append(log_tracelogging(event.parse_tracelogging()))
            self.xml_document.append(data)
        except TlMetaDataNotFound as t:
            try:
                etw = event.parse_etw()
                data = ElementTree.SubElement(self.xml_document, "event")
                data.set("type", "event")
                data.set("timestamp", event.get_utc_timestamp())
                data.set("PID", str(event.get_process_id()))
                data.set("TID", str(event.get_thread_id()))
                xml = ElementTree.SubElement(data, "etw")
                xml.set("provider", etw.__class__.__name__)
                log_construct_pattern(xml, etw.pattern, etw.source)
            except (EtwVersionNotFound, EventIdNotFound, GuidNotFound) as e:
                print(e)

    def on_win_trace(self, event: WinTrace):
        try:
            etw = event.parse_etw()
            data = ElementTree.SubElement(self.xml_document, "event")
            data.set("type", "event")
            xml = ElementTree.SubElement(data, "etw")
            xml.set("provider", etw.__class__.__name__)
            log_construct_pattern(xml, etw.pattern, etw.source)
        except (EtwVersionNotFound, EventIdNotFound, GuidNotFound) as e:
            print(e)

def prettify(elem: ElementTree):
    """
    Return a pretty-printed XML string for the Element. 
    """
    return parseString(ElementTree.tostring(elem, 'utf-8')).toprettyxml(indent="\t")

def main(input: str, output: str):
    """
    Main entry point
    :param input: input file path
    :param output: output path
    """
    logger = EtlFileLogger()
    if logger is not None:
        with open(input, "rb") as input_file:
            etl_reader = build_from_stream(input_file.read())
            etl_reader.parse(logger)
    
        with open(output, "w", encoding='utf-8') as output_file:
            output_file.write(prettify(logger.xml_document))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""
    Convert your ETL Windows log files into XML files.
    This is made with love by Airbus CERT Team.
    """)

    parser.add_argument("etlfile",
                        help="Path of input ETL file",
                        nargs=1,
                        type=str)
    parser.add_argument( "-o", "--output",
                        help="Path of output XML file",
                        type=str, default=None, required=False)

    args = parser.parse_args()
    etlfile = args.etlfile[0]
    if not os.path.isfile(etlfile):
        sys.exit("No ETL file specified or file does not exist.")

    xmlfile = args.output
    if not xmlfile:
        xmlfile = os.path.join(os.path.dirname(etlfile), os.path.basename(etlfile).replace(".etl", '') + ".xml")
        print(f"Output file: {xmlfile}")
    main(etlfile, xmlfile)
