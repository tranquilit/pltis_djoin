# Tranquil IT DJoin

*A DJoin blob (de)serialization library in modern Object Pascal*

(c) 2023-2023 Tranquil IT https://www.tranquil.it


## Presentation

This repository provide a lazarus package allowing to create and edit a DJoin blob.

It only require [mORMot 2](https://github.com/synopse/mORMot2/) framework as a dependency.

### Sub-Folders

The repository content is organized into the following sub-folders:

- [`src`](src) is the main source code folder, where you should find the actual library.
- [`pack`](pack) contains lazrus package file.
- [`examples`](examples) contains various samples.

Feel free to explore the source, and the inlined documentation.

### DJoin blob

The microsoft [DJoin.exe](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/ff793312(v=ws.11)) produce a base64 file encoded in Utf-16 LE with BOM.
The base64 represent a [ODJ_PROVISION_DATA](https://learn.microsoft.com/en-us/windows/win32/netmgmt/odj-odj_provision_data) structure serialized following NDR (Network Data Representation) protocol. 

Usefull links for the protocol:
- [Offline Domain Join IDL Definitions](https://learn.microsoft.com/en-us/windows/win32/netmgmt/odj-idl)
- [NDR Common Type Header](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/6d75d40e-e2d2-4420-b9e9-8508a726a9ae)
- [NDR Custom Type Header](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/63949ba8-bc88-4c0c-9377-23f14b197827)
- [NDR Strings encoding](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ed96db0d-830e-42ed-a36b-af589a1c33fd)
- [DCE 1.1: Remote Procedure Call (PDF)](https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf)

### MPL/GPL/LGPL Three-License

The project is licensed under a disjunctive three-license giving you the choice of one of the three following sets of free software/open source licensing terms:
- Mozilla Public License, version 1.1 or later;
- GNU General Public License, version 2.0 or later;
- GNU Lesser General Public License, version 2.1 or later.

This allows the use of our code in as wide a variety of software projects as possible, while still maintaining copy-left on code we wrote.
See [the full licensing terms](LICENCE.md).