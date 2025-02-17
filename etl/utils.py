# -*- coding: utf-8 -*-

"""
Utils encompass a lot of well known structure definition
Which can be found in many other type definition
"""

from construct import Struct, Int32sl, Int16sl, Byte, Enum, Check, \
                      EnumInteger, Int16ul, Int32ul, RepeatUntil, \
                      Computed, Int64ul

"""
FILETIME and datetime conversion
"""
EPOCH_AS_FILETIME = 116444736000000000
HUNDREDS_OF_NANOSECONDS = 10000000

FileTime = Struct(
    "value" / Int64ul,
    "datetime" / Computed(lambda this: datetime.datetime.utcfromtimestamp(
        (this.FileTime - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
        if this.FileTime > EPOCH_AS_FILETIME else ''
    )
)

"""
Global Unique Identifier
"""
Guid = Struct(
    "type" / Computed("Guid"),
    "_inner" / Struct (
        "data1" / Int32ul,
        "data2" / Int16ul,
        "data3" / Int16ul,
        "data4" / Byte[8]
    ),
    "string" / Computed(lambda this:
        "{:08x}-{:04x}-{:04x}-{:s}-{:s}".format(
            this._inner.data1,
            this._inner.data2,
            this._inner.data3,
            ''.join("{:02x}".format(x) for x in this._inner.data4[0:2]),
            ''.join("{:02x}".format(x) for x in this._inner.data4[2:])
		)
	)
)

"""
System Time definition in Windows Internal
"""
SystemTime = Struct(
    "year" / Int16sl,
    "month" / Int16sl,
    "day_of_week" / Int16sl,
    "day" / Int16sl,
    "hour" / Int16sl,
    "minute" / Int16sl,
    "second" / Int16sl,
    "milliseconds" / Int16sl
)

"""
TimeZone Information definition in Windows Internal
"""
TimeZoneInformation = Struct(
    "bias" / Int32sl,
    "standard_name" / Byte[64],
    "standard_date" / SystemTime,
    "standard_bias" / Int32sl,
    "delight_name" / Byte[64],
    "delight_date" / SystemTime,
    "delight_bias" / Int32sl
)

PerfinfoGroupMask = Struct(
    "masks" / Int32ul[8]
)

"""
Wide string windows style
"""
WString = Struct(
    "type" / Computed("WString"),
    "string" / RepeatUntil(lambda x, lst, ctx: len(lst) % 2 == 0 and lst[-2:] == [0, 0], Byte)
)

"""
C string style
"""
CString = Struct(
    "type" / Computed("CString"),
    "string" / RepeatUntil(lambda x, lst, ctx: lst[-1:] == [0], Byte)
)


def check_enum(enum: Enum) -> Struct:
    """
    Enforce an enum value to be in enum range
    :param enum: source enum
    :return: Struct
    :raise: construct.core.CheckError
    """
    return Struct(
        "enum" / enum,
        Check(lambda this: not isinstance(this.enum, EnumInteger))
    )
