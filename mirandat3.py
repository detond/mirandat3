#!/usr/bin/env python

# DO WHAT THE FUCK YOU WANT TO BUT IT'S NOT MY FAULT PUBLIC LICENSE
# Version 1, October 2013
#
# Copyright (C) 2011 Kristoffer Gronlund <deceiver.g@gmail.com>
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
# DO WHAT THE FUCK YOU WANT TO BUT IT'S NOT MY FAULT PUBLIC LICENSE
# TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
# 0. You just DO WHAT THE FUCK YOU WANT TO.
#
# 1. Do not hold the author(s), creator(s), developer(s) or distributor(s)
# liable for anything that happens or goes wrong with your use of the work.


from struct import unpack
from datetime import datetime
from functools import reduce
from argparse import ArgumentParser
from enum import Enum


CONTACT_SIG = 0x43DECADE
MODULENAME_SIG = 0x4DDECADE
EVENT_SIG = 0x45DECADE

EventType_Message = 0
EventType_Url = 1
EventType_Contacts = 2
EventType_Added = 1000
EventType_AuthRequest = 1001
EventType_File = 1002

class ContactFields(Enum):
    FIRST_NAME = 'FirstName'
    LAST_NAME = 'LastName'
    NICK = 'Nick'
    UIN = 'UIN'

def deunicode(txt):
    try:
        return str(txt, encoding='utf-8')
    except:
        return repr(txt)

def deutf16(txt):
    try:
        return str(txt, encoding='utf-16')
    except:
        return repr(txt)

def delatin(txt):
    try:
        return str(txt, encoding='latin')
    except:
        return repr(txt)

def clipstr(txt, st=0, ln=0):
    i = st
    while (i < ln) and (txt[i:i+1] != b'\x00'):
        i = i+1
    return txt[st:i]

class DBEvent(object):
    DBEF_FIRST = 1
    DBEF_SENT = 2
    DBEF_READ = 4
    DBEF_RTL = 8
    DBEF_UTF = 16

    def __init__(self, contact, dat, offset):
        self.contact = contact
        bloboffs = offset+(7*4)+2
        evh = unpack("<IIIIIIHI", dat[offset:bloboffs])
        self.signature = evh[0]
        self.prev = evh[1]
        self.next = evh[2]
        self.moduleName = evh[3]
        self.timestamp = datetime.fromtimestamp(evh[4])
        self.flags = evh[5]
        self.type = evh[6]
        self.blobsize = evh[7]
        self.blob = dat[bloboffs:(bloboffs+self.blobsize-1)]

        if self.signature != EVENT_SIG:
            print(("Not a valid event:", self.signature))

    def name(self):
        return self.contact.name

    def typestr(self):
        m = { EventType_Message:"Message",
              EventType_Url:"Url",
              EventType_Contacts:"Contacts",
              EventType_Added:"Added",
              EventType_AuthRequest:"AuthRequest",
              EventType_File:"File"
              }
        if self.type in m:
            return m[self.type]
        return "Unknown"

    def parse_blob(self):
        ln = len(self.blob)
        st = 0
        if self.type == EventType_File:
            st = 4
        txt = clipstr(self.blob, st, ln)

        if self.flags & self.DBEF_UTF:
            return deunicode(txt)
        else:
            return delatin(txt)

    def dir(self):
        return ">" if (self.flags & self.DBEF_SENT) else "<"

    def __str__(self):
        txt = self.parse_blob()
        return "%s %s (%s) %s: " % (self.dir(), self.name(), self.timestamp, self.typestr()) + txt

class DBContactSettings(object):
    DBVT_DELETED = 0
    DBVT_BYTE = 1
    DBVT_WORD = 2
    DBVT_DWORD = 4
    DBVT_ASCIIZ = 255
    DBVT_BLOB = 254
    DBVT_UTF8 = 253
    DBVT_WCHAR = 252
    DBVTF_VARIABLELENGTH = 0x80
    DBVTF_DENYUNICODE = 0x10000

    def __init__(self, dat, offset):
        s = unpack("<IIII", dat[offset:(offset+(4*4))])
        self.signature = s[0]
        self.next = s[1]
        self.moduleName = s[2]
        self.blobsize = s[3]
        self.blob = dat[offset+(4*4):offset+(4*4)+self.blobsize]

        self.settings = dict(self._read_settings())

    def dataTypeName(self, dt):
        m = {
            self.DBVT_DELETED:'Deleted',
            self.DBVT_BYTE:'Byte',
            self.DBVT_WORD:'Word',
            self.DBVT_DWORD:'Dword',
            self.DBVT_ASCIIZ:'AsciiZ',
            self.DBVT_BLOB:'Blob',
            self.DBVT_UTF8:'Utf8',
            self.DBVT_WCHAR:'WChar'}
        if dt in m:
            return m[dt]
        return str(dt)

    def _read_settings(self):
        settings = []
        cur = self.blob
        cbName = unpack("<B", cur[0:1])[0]
        while cbName != 0:
            name = delatin(cur[1:(int(cbName)+1)])
            dataType = unpack("<B", cur[cbName+1:cbName+2])[0]
            typename = self.dataTypeName(dataType)
            parsed = self._parse_setting(dataType, cur[cbName+2:])
            settings.append([name, parsed[0]])
            if parsed[1] > 0:
                nbytes = parsed[1]
                cur = cur[(1+cbName+1+nbytes):]
                cbName = unpack("<B", cur[0:1])[0]
            else:
                break # todo
        return settings

    def _parse_setting(self, typ, data):
        if typ == self.DBVT_DELETED:
            return ("Deleted", 0)
        elif typ == self.DBVT_BYTE:
            return (unpack("<B", data[0:1])[0], 1)
        elif typ == self.DBVT_WORD:
            return (unpack("<H", data[0:2])[0], 2)
        elif typ == self.DBVT_DWORD:
            return (unpack("<I", data[0:4])[0], 4)
        elif typ == self.DBVT_ASCIIZ:
            ln = unpack("<H", data[0:2])[0]
            return (delatin(data[2:2+ln]), ln+2)
        elif typ == self.DBVT_BLOB:
            ln = unpack("<H", data[0:2])[0]
            return (repr(data[2:]), ln+2)
        elif typ == self.DBVT_UTF8:
            ln = unpack("<H", data[0:2])[0]
            return (deunicode(data[2:2+ln]), ln+2)
        elif typ == self.DBVT_WCHAR:
            ln = unpack("<H", data[0:2])[0]
            return (deutf16(data[2:(2+ln)]), ln+2)
        else:
            return (repr(data), len(data))

    def __repr__(self):
        return str(self.settings)

class DBContact(object):
    def __init__(self, dat, offset):
        sig = unpack("<IIIIIIII", dat[offset:(offset+(4*8))])
        self.signature = sig[0]
        self.next = sig[1]
        self.firstSettings = sig[2]
        self.eventCount = sig[3]
        self.firstEvent = sig[4]
        self.lastEvent = sig[5]
        self.firstUnreadEvent = sig[6]
        self.timestampFirstUnread = sig[7]

        if self.signature != CONTACT_SIG:
            print(("Not a valid contact:", self.signature))

        self.settings = self._read_settings(dat)

        if ContactFields.FIRST_NAME.value in self.settings:
            self.firstName = self.settings[ContactFields.FIRST_NAME.value]
        else:
            self.firstName = None
        if ContactFields.LAST_NAME.value in self.settings:
            self.lastName = self.settings[ContactFields.LAST_NAME.value]
        else:
            self.lastName = None
        if ContactFields.NICK.value in self.settings:
            self.nick = self.settings[ContactFields.NICK.value]
        else:
            self.nick = None
        if ContactFields.UIN.value in self.settings:
            self.uin = self.settings[ContactFields.UIN.value]
        else:
            self.uin = None

        if self.firstName and self.lastName and self.nick:
            self.name = "%s %s (%s)" % (self.firstName, self.lastName, self.nick)
        elif self.firstName and self.nick:
            self.name = "%s (%s)" % (self.firstName, self.nick)
        elif self.lastName and self.nick:
            self.name = "%s (%s)" % (self.lastName, self.nick)
        elif self.firstName and self.lastName:
            self.name = "%s %s" % (self.firstName, self.lastName)
        elif self.nick:
            self.name = self.nick
        elif self.uin:
            self.name = self.uin
        else:
            self.name = "?"

        self.events = self._read_events(dat)

        # find contact name/id etc!
    def _read_settings(self, dat):
        settings = []
        i = self.firstSettings
        while i != 0:
            s = DBContactSettings(dat, i)
            i = s.next
            settings.append(s.settings)

        settings = reduce(lambda x,y: dict(list(x.items()) + list(y.items())), settings)
        return settings

    def _read_events(self, dat):
        events = []
        i = self.firstEvent
        while i != 0:
            e = DBEvent(self, dat, i)
            i = e.next
            events.append(e)
        return events

    def __str__(self):
        s = "Contact:\n"
        s += "Event count: " + str(self.eventCount) + "\n"
        for k,v in list(self.settings.items()):
            s += ("%12s:\t%12s\n"%(str(k), str(v)))
        return s


class DBHeader(object):
    def __init__(self, dat):
        header_size = 20+(6*4)
        header = unpack("<16sHHIIIIII", dat[:header_size])
        self.signature = header[0]
        self.checkWord = header[1]
        self.cryptorUID = header[2]
        self.fileEnd = header[3]
        self.slackSpace = header[4]
        self.contactCount = header[5]
        self.firstContact = header[6]
        self.user = header[7]
        self.firstModuleName = header[8]

def sqlite3_export(header, dat):
    import sqlite3

    con = sqlite3.connect("export.db3")

    cur = con.cursor()

    cur.executescript("""
        create table contacts(
            id integer primary key autoincrement,
            name text
        );

        create table settings(
            id integer primary key autoincrement,
            owner integer,
            name text,
            value text
        );

        create table events(
            id integer primary key autoincrement,
            owner integer,
            timestamp integer,
            type text,
            data text
        );
        """)

    cur.execute("create table test(x)")
    #cur.executemany("insert into test(x) values (?)", [("a",), ("b",)])
    #cur.execute("select x from test order by x collate reverse")

    next_contact = header.firstContact
    while next_contact != 0:
        c = DBContact(dat, next_contact)
        cur.execute("insert into contacts(name) values (?)", (str(c.name).encode('utf-8'),))
        c_id = None
        for row in cur.execute('select last_insert_rowid()'):
            print(row)
            c_id = row[0]
        cur.executemany("insert into settings(owner, name, value) values (?, ?, ?)",
                        [(c_id, k.encode('utf-8'), str(v).encode('utf-8')) for k, v in list(c.settings.items())])
        cur.executemany("insert into events(owner, timestamp, type, data) values (?, ?, ?, ?)",
                        [(c_id, e.timestamp, e.typestr().encode('utf-8'), e.parse_blob().encode('utf-8')) for e in c.events])
        next_contact = c.next

    con.commit()
    cur.close()
    con.close()


def main():
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", dest="filename",
                        help="Miranda database file", metavar="FILE", required=True)
    subparsers = parser.add_subparsers(help='Commands', required=True, dest='command')
    parser_ls = subparsers.add_parser('list', help='Print out all events as text', aliases=['ls'])
    parser_e = subparsers.add_parser('export', help='Export all exents to an SQLite DB', aliases=['e'])
    parser_c = subparsers.add_parser('contacts', help='List contacts (detailed)', aliases=['c'])
    parser_cn = subparsers.add_parser('contact_names', help='List contacts (brief)', aliases=['cn'])
    parser_fc = subparsers.add_parser('find_contact', help='Find contact by a given field', aliases=['fc'])
    parser_fc.add_argument('by', choices=[element.value for element in ContactFields], help='Field name')
    parser_fc.add_argument('value', help='Field value')

    args = parser.parse_args()
    triggered_subparser = subparsers.choices[args.command]

    dat = None
    with open(args.filename, 'rb') as f:
        dat = f.read()
    header = DBHeader(dat)

    if triggered_subparser == parser_cn:
        next_contact = header.firstContact
        while next_contact != 0:
            c = DBContact(dat, next_contact)
            print("%12s\t%12s\t%12s\t%12s" % (c.uin, c.nick, c.firstName, c.lastName))
            next_contact = c.next
    elif triggered_subparser == parser_fc:
        by = args.by
        val = args.value
        next_contact = header.firstContact
        while next_contact != 0:
            c = DBContact(dat, next_contact)
            if str(c.settings.get(by)) == val:
                print(c)
            next_contact = c.next
    elif triggered_subparser == parser_c:
        next_contact = header.firstContact
        while next_contact != 0:
            c = DBContact(dat, next_contact)
            print(c)
            next_contact = c.next
    elif triggered_subparser == parser_ls:
        next_contact = header.firstContact
        while next_contact != 0:
            c = DBContact(dat, next_contact)
            for e in c.events:
                print(e)
            next_contact = c.next
    elif triggered_subparser == parser_e:
        sqlite3_export(header, dat)
    else:
        print("Unknown command")

if __name__=="__main__":
    main()
