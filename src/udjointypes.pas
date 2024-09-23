/// This unit is a part of the Open Source Tranquil IT DJoin,
// licensed under a MPL/GPL/LGPL three license - see LICENSE.md

unit uDJoinTypes;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.base,
  mormot.core.os,
  mormot.core.os.security,
  uNDRContext;

const
  GUID_JOIN_PROVIDER : TGUID = '{631c7621-5289-4321-bc9e-80f843f868c3}';
  GUID_JOIN_PROVIDER2 : TGUID = '{57BFC56B-52F9-480C-ADCB-91B3F8A82317}';
  GUID_JOIN_PROVIDER3 : TGUID = '{FC0CCF25-7FFA-474A-8611-69FFE269645F}';
  GUID_CERT_PROVIDER : TGUID = '{9c0971e9-832f-4873-8e87-ef1419d4781e}';
  GUID_POLICY_PROVIDER : TGUID = '{68fb602a-0c09-48ce-b75f-07b7bd58f7ec}';

  DS_PDC_FLAG : UInt32 = $00000001; // DC is PDC of Domain
  DS_GC_FLAG : UInt32 = $00000004; // DC is a GC of forest
  DS_LDAP_FLAG : UInt32 = $00000008; // Server supports an LDAP server
  DS_DS_FLAG : UInt32 = $00000010; // DC supports a DS and is a Domain Controller
  DS_KDC_FLAG : UInt32 = $00000020; // DC is running KDC service
  DS_TIMESERV_FLAG : UInt32 = $00000040; // DC is running time service
  DS_CLOSEST_FLAG : UInt32 = $00000080; // DC is in closest site to client
  DS_WRITABLE_FLAG : UInt32 = $00000100; // DC has a writable DS
  DS_GOOD_TIMESERV_FLAG : UInt32 = $00000200; // DC is running time service (and has clock hardware)
  DS_NDNC_FLAG : UInt32 = $00000400; // DomainName is non-domain NC serviced by the LDAP server
  DS_SELECT_SECRET_DOMAIN_6_FLAG : UInt32 = $00000800; // DC has some secrets
  DS_FULL_SECRET_DOMAIN_6_FLAG : UInt32 = $00001000; // DC has all secrets
  DS_WS_FLAG : UInt32 = $00002000; // DC is running web service
  DS_PING_FLAGS : UInt32 = $000FFFFF;    // Flags returned on ping
  DS_DNS_CONTROLLER_FLAG : UInt32 = $20000000; // DomainControllerName is a DNS name
  DS_DNS_DOMAIN_FLAG : UInt32 = $40000000; // DomainName is a DNS name
  DS_DNS_FOREST_FLAG : UInt32 = $80000000; // DnsForestName is a DNS name


  // Registry value types: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
  REG_NONE = 0;
  REG_SZ = 1;
  REG_EXPAND_SZ = 2;
  REG_BINARY = 3;
  REG_DWORD = 4;
  REG_DWORD_LITTLE_ENDIAN = 4;
  REG_DWORD_BIG_ENDIAN = 5;
  REG_LINK = 6;
  REG_MULTI_SZ = 7;
  REG_RESOURCE_LIST = 8;
  REG_FULL_RESOURCE_DESCRIPTOR = 9;
  REG_RESOURCE_REQUIREMENTS_LIST = 10;
  REG_QWORD = 11;
  REG_QWORD_LITTLE_ENDIAN = 11;


type
  {$A-} // every record (or object) is packed from now on


  // Types related to GPO
  TRegistryValue = object
    Key: RawUtf8;
    ValueName: RawUtf8;
    ValueType: UInt32;
    ValueSize: UInt32;
    Value: RawByteString;
  end;
  TRegistryValues = array of TRegistryValue;

  TGroupPolicy = object
    Name: RawUtf8;
    Values: TRegistryValues;
  end;
  TGroupPolicies = array of TGroupPolicy;

  TDS_FLAGS = UInt32;
  TDS_AddressType = (DS_INET_ADDRESS = 1, DS_NETBIOS_ADDRESS = 2);

  TODJ_Format = (ODJ_WIN7BLOB = 1, OP_PACKAGE = 2);

  { TODJ_UNICODE_STRING }

  TODJ_UNICODE_STRING = object
    Length: UInt16;
    MaximumLength: UInt16;
    Buffer: WideString;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  PODJ_UNICODE_STRING = ^TODJ_UNICODE_STRING;

  { TOP_BLOB }

  TOP_BLOB = object
    cbBlob: UInt32;
    pBlob: PByte;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_BLOB = ^TOP_BLOB;

  TOP_POLICY_ELEMENT = object
    pKeyPath: WideString;
    pValueName: WideString;
    ulValueType: UInt32;
    cbValueData: UInt32;
    pValueData: PByte;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_POLICY_ELEMENT = ^TOP_POLICY_ELEMENT;

  TOP_POLICY_ELEMENT_LIST = object
    pSource: WideString;
    ulRootKeyId: UInt32;
    cElements: UInt32;
    pElements: POP_POLICY_ELEMENT;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_POLICY_ELEMENT_LIST = ^TOP_POLICY_ELEMENT_LIST;

  TOP_POLICY_PART = object
    cElementLists: UInt32;
    pElementsLists: POP_POLICY_ELEMENT_LIST;
    Extension: TOP_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_POLICY_PART = ^TOP_POLICY_PART;
  TOP_POLICY_PART_ctr = specialize TNDRPointer<TOP_POLICY_PART>;
  TOP_POLICY_PART_serialized_ptr = specialize TNDRCustomType<TOP_POLICY_PART_ctr>;

  { TODJ_POLICY_DNS_DOMAIN_INFO }

  TODJ_POLICY_DNS_DOMAIN_INFO = object
    Name: TODJ_UNICODE_STRING;
    DnsDomainName: TODJ_UNICODE_STRING;
    DnsForestName: TODJ_UNICODE_STRING;
    DomainGuid: TGuid;
    Sid: PSid;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  PODJ_POLICY_DNS_DOMAIN_INFO = ^TODJ_POLICY_DNS_DOMAIN_INFO;

  { TDOMAIN_CONTROLLER_INFO }

  TDOMAIN_CONTROLLER_INFO = object
    dc_unc: WideString;
    dc_address: WideString;
    dc_address_type: TDS_AddressType;
    domain_guid: TGuid;
    domain_name: WideString;
    forest_name: WideString;
    dc_flags: TDS_FLAGS;
    dc_site_name: WideString;
    client_site_name: WideString;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  PDOMAIN_CONTROLLER_INFO = ^TDOMAIN_CONTROLLER_INFO;

  { TODJ_WIN7BLOB }

  TODJ_WIN7BLOB = object
    lpDomain: WideString;
    lpMachineName: WideString;
    lpMachinePassword: WideString;
    Padding: UInt32; // Not in official struct but present in binary serialized
    DnsDomainInfo: TODJ_POLICY_DNS_DOMAIN_INFO;
    DcInfo: TDOMAIN_CONTROLLER_INFO;
    Options: UInt32;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  PODJ_WIN7BLOB = ^TODJ_WIN7BLOB;
  TODJ_WIN7BLOB_serialized = specialize TNDRCustomType<TODJ_WIN7BLOB>;

  { TOP_JOINPROV3_PART }

  TOP_JOINPROV3_PART = object
    Rid: UInt32;
    lpSid: WideString;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_JOINPROV3_PART = ^TOP_JOINPROV3_PART;
  TOP_JOINPROV3_PART_ctr = specialize TNDRPointer<TOP_JOINPROV3_PART>;
  TOP_JOINPROV3_PART_serialized_ptr = specialize TNDRCustomType<TOP_JOINPROV3_PART_ctr>;

  TOP_PACKAGE_PART_u = record
    case UInt32 of
      1: (Win7Blob: PODJ_WIN7BLOB);
      2: (JoinProv3: TOP_JOINPROV3_PART_ctr);
      3: (PolicyProvider: TOP_POLICY_PART_ctr);
      4: (RawBytes: PByte);
  end;

  { TOP_PACKAGE_PART }

  TOP_PACKAGE_PART = object
    PartType: TGUID;
    ulFlags: UInt32;
    PartLen: UInt32;
    Part: TOP_PACKAGE_PART_u;
    Extension: TOP_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
    function NDRSize_PartBlob: SizeUInt;
  end;
  POP_PACKAGE_PART = ^TOP_PACKAGE_PART;

  { TOP_PACKAGE_PART_COLLECTION }

  TOP_PACKAGE_PART_COLLECTION = object
    cParts: UInt32;
    pParts: POP_PACKAGE_PART;
    Extension: TOP_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_PACKAGE_PART_COLLECTION = ^TOP_PACKAGE_PART_COLLECTION;
  TOP_PACKAGE_PART_COLLECTION_ctr = specialize TNDRPointer<TOP_PACKAGE_PART_COLLECTION>;
  TOP_PACKAGE_PART_COLLECTION_serialized_ptr = specialize TNDRCustomType<TOP_PACKAGE_PART_COLLECTION_ctr>;

  { TOP_PACKAGE_PART_COLLECTION_blob }

  TOP_PACKAGE_PART_COLLECTION_blob = object
    cbBlob: UInt32;
    pPackagePartCollection: TOP_PACKAGE_PART_COLLECTION_ctr;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
    function NDRSize_blob: SizeUInt;
  end;
  POP_PACKAGE_PART_COLLECTION_blob = ^TOP_PACKAGE_PART_COLLECTION_blob;

  { TOP_PACKAGE }

  TOP_PACKAGE = object
    EncryptionType: TGUID;
    EncryptionContext: TOP_BLOB;
    WrappedPartCollection: TOP_PACKAGE_PART_COLLECTION_blob;
    cbDecryptedPartCollection: UInt32;
    Extension: TOP_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_PACKAGE = ^TOP_PACKAGE;
  TOP_PACKAGE_ctr = specialize TNDRPointer<TOP_PACKAGE>;
  TOP_PACKAGE_serialized_ptr = specialize TNDRCustomType<TOP_PACKAGE_ctr>;

  TODJ_BLOB_buffer_u = record
    case UInt32 of
      1: (Win7Blob: PODJ_WIN7BLOB);
      2: (OPPackage: TOP_PACKAGE_ctr);
      3: (RawBytes: PByte);
  end;
  PODJ_BLOB_buffer_u = ^TODJ_BLOB_buffer_u;

  { TODJ_BLOB }

  TODJ_BLOB = object
    ulODJFormat: TODJ_Format;
    cbBlob: UInt32;
    pBlob: TODJ_BLOB_buffer_u;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
    function NDRSize_pBlob: SizeUInt;
  end;
  PODJ_BLOB = ^TODJ_BLOB;

  { TODJ_PROVISION_DATA }

  TODJ_PROVISION_DATA = object
    Version: UInt32;
    ulcBlobs: UInt32;
    pBlobs: PODJ_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  PODJ_PROVISION_DATA = ^TODJ_PROVISION_DATA;
  TODJ_PROVISION_DATA_ctr = specialize TNDRPointer<TODJ_PROVISION_DATA>;
  TODJ_PROVISION_DATA_serialized_ptr = specialize TNDRCustomType<TODJ_PROVISION_DATA_ctr>;

procedure DumpDS_Flags(flags: TDS_FLAGS);
function RegistryTypeToString(RegType: UInt32): RawUtf8;

implementation

uses
  mormot.core.buffers,
  mormot.core.unicode;

procedure DumpDS_Flags(flags: TDS_FLAGS);
begin
  WriteLn(Format('Flag: 0x%x', [flags]));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_PDC_FLAG', DS_PDC_FLAG, BoolToStr((Flags and DS_PDC_FLAG) > 0, 'True', 'False'), 'DC is PDC of Domain']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_GC_FLAG', DS_GC_FLAG, BoolToStr((Flags and DS_GC_FLAG) > 0, 'True', 'False'), 'DC is a GC of forest']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_LDAP_FLAG', DS_LDAP_FLAG, BoolToStr((Flags and DS_LDAP_FLAG) > 0, 'True', 'False'), 'Server supports an LDAP server']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_DS_FLAG', DS_DS_FLAG, BoolToStr((Flags and DS_DS_FLAG) > 0, 'True', 'False'), 'DC supports a DS and is a Domain Controller']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_KDC_FLAG', DS_KDC_FLAG, BoolToStr((Flags and DS_KDC_FLAG) > 0, 'True', 'False'), 'DC is running KDC service']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_TIMESERV_FLAG', DS_TIMESERV_FLAG, BoolToStr((Flags and DS_TIMESERV_FLAG) > 0, 'True', 'False'), 'DC is running time service']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_CLOSEST_FLAG', DS_CLOSEST_FLAG, BoolToStr((Flags and DS_CLOSEST_FLAG) > 0, 'True', 'False'), 'DC is in closest site to client']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_WRITABLE_FLAG', DS_WRITABLE_FLAG, BoolToStr((Flags and DS_WRITABLE_FLAG) > 0, 'True', 'False'), 'DC has a writable DS']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_GOOD_TIMESERV_FLAG', DS_GOOD_TIMESERV_FLAG, BoolToStr((Flags and DS_GOOD_TIMESERV_FLAG) > 0, 'True', 'False'), 'DC is running time service (and has clock hardware)']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_NDNC_FLAG', DS_NDNC_FLAG, BoolToStr((Flags and DS_NDNC_FLAG) > 0, 'True', 'False'), 'DomainName is non-domain NC serviced by the LDAP server']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_SELECT_SECRET_DOMAIN_6_FLAG', DS_SELECT_SECRET_DOMAIN_6_FLAG, BoolToStr((Flags and DS_SELECT_SECRET_DOMAIN_6_FLAG) > 0, 'True', 'False'), 'DC has some secrets']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_FULL_SECRET_DOMAIN_6_FLAG', DS_FULL_SECRET_DOMAIN_6_FLAG, BoolToStr((Flags and DS_FULL_SECRET_DOMAIN_6_FLAG) > 0, 'True', 'False'), 'DC has all secrets']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_WS_FLAG', DS_WS_FLAG, BoolToStr((Flags and DS_WS_FLAG) > 0, 'True', 'False'), 'DC is running web service']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_DNS_CONTROLLER_FLAG', DS_DNS_CONTROLLER_FLAG, BoolToStr((Flags and DS_DNS_CONTROLLER_FLAG) > 0, 'True', 'False'), 'DomainControllerName is a DNS name']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_DNS_DOMAIN_FLAG', DS_DNS_DOMAIN_FLAG, BoolToStr((Flags and DS_DNS_DOMAIN_FLAG) > 0, 'True', 'False'), 'DomainName is a DNS name']));
  WriteLn(Format('%-32s  0x%.8x : %-5s # %s', ['DS_DNS_FOREST_FLAG', DS_DNS_FOREST_FLAG, BoolToStr((Flags and DS_DNS_FOREST_FLAG) > 0, 'True', 'False'), 'DnsForestName is a DNS name']));
end;

function RegistryTypeToString(RegType: UInt32): RawUtf8;
begin
  case RegType of
    REG_NONE: Result := 'REG_NONE';
    REG_SZ: Result := 'REG_SZ';
    REG_EXPAND_SZ: Result := 'REG_EXPAND_SZ';
    REG_BINARY: Result := 'REG_BINARY';
    REG_DWORD: Result := 'REG_DWORD';
    REG_DWORD_BIG_ENDIAN: Result := 'REG_DWORD_BIG_ENDIAN';
    REG_LINK: Result := 'REG_LINK';
    REG_MULTI_SZ: Result := 'REG_MULTI_SZ';
    REG_RESOURCE_LIST: Result := 'REG_RESOURCE_LIST';
    REG_FULL_RESOURCE_DESCRIPTOR: Result := 'REG_FULL_RESOURCE_DESCRIPTOR';
    REG_RESOURCE_REQUIREMENTS_LIST: Result := 'REG_RESOURCE_REQUIREMENTS_LIST';
    REG_QWORD: Result := 'REG_QWORD';
  else
    Result := 'REG_UNKNOWN';
  end;
  Result := Result + ' (' + IntToStr(RegType) + ')';
end;

{ TOP_POLICY_ELEMENT }

procedure TOP_POLICY_ELEMENT.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  dataSize: UInt32;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    // pKeyPath
    Ctx.UnpackPtr;
    // pValueName
    Ctx.UnpackPtr;
    ulValueType := Ctx.UnpackUInt32;
    cbValueData := Ctx.UnpackUInt32;
    // pValueData
    Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    pKeyPath := Ctx.UnpackWideStr;
    pValueName := Ctx.UnpackWideStr;
    dataSize := Ctx.UnpackUInt32;
    if dataSize <> cbValueData then
      raise Exception.CreateFmt('Expected GPO data size and actual size differs: %d - %d', [cbValueData, dataSize]);
    pValueData := Ctx.MemoryContext^.GetMem(dataSize);
    Move(PByte(Ctx.Unpack(dataSize))^, pValueData[0], dataSize);
  end;
end;

procedure TOP_POLICY_ELEMENT.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackPtr(Pointer(pKeyPath));
    Ctx.PackPtr(Pointer(pValueName));
    Ctx.PackUInt32(ulValueType);
    Ctx.PackUInt32(cbValueData);
    Ctx.PackPtr(pValueData);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Ctx.PackWideStr(pKeyPath);
    Ctx.PackWideStr(pValueName);
    Ctx.PackUInt32(cbValueData);
    Ctx.Pack(@pValueData[0], cbValueData);
  end;
end;

function TOP_POLICY_ELEMENT.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(pKeyPath));
    Inc(Result, SizeOf(pValueName));
    Inc(Result, SizeOf(ulValueType));
    Inc(Result, SizeOf(cbValueData));
    Inc(Result, SizeOf(pValueData));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, NDRWideStrSize(pKeyPath));
    Inc(Result, NDRWideStrSize(pValueName));
    Inc(Result, SizeOf(cbValueData));
    Inc(Result, cbValueData);
  end;
end;

{ TOP_POLICY_ELEMENT_LIST }

procedure TOP_POLICY_ELEMENT_LIST.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  NbElements: UInt32;
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    // pSource
    Ctx.UnpackPtr;
    ulRootKeyId := Ctx.UnpackUInt32;
    cElements := Ctx.UnpackUInt32;
    pElements := Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    pSource := Ctx.UnpackWideStr;
    if Assigned(pElements) then
    begin
      NbElements := Ctx.UnpackUInt32;
      pElements := Ctx.MemoryContext^.GetZeroedMem(NbElements, SizeOf(pElements^));
      for i := 0 to NbElements - 1 do
        pElements[i].NDRUnpack(Ctx, NDR_Scalar);
      for i := 0 to NbElements - 1 do
        pElements[i].NDRUnpack(Ctx, NDR_Buffer);
    end;
  end;
end;

procedure TOP_POLICY_ELEMENT_LIST.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
var
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackPtr(Pointer(pSource));
    Ctx.PackUInt32(ulRootKeyId);
    Ctx.PackUInt32(cElements);
    Ctx.PackPtr(pElements);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Ctx.PackWideStr(pSource);
    if Assigned(pElements) then
    begin
      Ctx.PackUInt32(cElements);
      for i := 0 to cElements - 1 do
        pElements[i].NDRPack(Ctx, NDR_Scalar);
      for i := 0 to cElements - 1 do
        pElements[i].NDRPack(Ctx, NDR_Buffer);
    end;
  end;
end;

function TOP_POLICY_ELEMENT_LIST.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  i: Integer;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(pSource));
    Inc(Result, SizeOf(ulRootKeyId));
    Inc(Result, SizeOf(cElements));
    Inc(Result, SizeOf(pElements));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, NDRWideStrSize(pSource));
    Inc(Result, SizeOf(cElements));

    for i := 0 to cElements - 1 do
      Inc(Result, pElements[i].NDRSize(NDR_Scalar));
    for i := 0 to cElements - 1 do
      Inc(Result, pElements[i].NDRSize(NDR_Buffer));
  end;
end;

{ TOP_POLICY_PART }

procedure TOP_POLICY_PART.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  NbElementLists: UInt32;
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    cElementLists := Ctx.UnpackUInt32;
    pElementsLists := Ctx.UnpackPtr;
    Extension.NDRUnpack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(pElementsLists) then
    begin
      NbElementLists := Ctx.UnpackUInt32;
      pElementsLists := Ctx.MemoryContext^.GetZeroedMem(NbElementLists, SizeOf(pElementsLists^));
      for i := 0 to NbElementLists - 1 do
        pElementsLists[i].NDRUnpack(Ctx, NDR_Scalar);
      for i := 0 to NbElementLists - 1 do
        pElementsLists[i].NDRUnpack(Ctx, NDR_Buffer);
    end;
  end;
end;

procedure TOP_POLICY_PART.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
var
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(cElementLists);
    Ctx.PackPtr(pElementsLists);
    Extension.NDRPack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(pElementsLists) then
    begin
      Ctx.PackUInt32(cElementLists);
      for i := 0 to cElementLists - 1 do
        pElementsLists[i].NDRPack(Ctx, NDR_Scalar);
      for i := 0 to cElementLists - 1 do
        pElementsLists[i].NDRPack(Ctx, NDR_Buffer);
    end;
    Extension.NDRPack(Ctx, NDR_Buffer);
  end;
end;

function TOP_POLICY_PART.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  i: Integer;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(cElementLists));
    Inc(Result, SizeOf(pElementsLists));
    Inc(Result, Extension.NDRSize(NDR_Scalar));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, SizeOf(cElementLists));

    for i := 0 to cElementLists - 1 do
      Inc(Result, pElementsLists[i].NDRSize(NDR_Scalar));
    for i := 0 to cElementLists - 1 do
      Inc(Result, pElementsLists[i].NDRSize(NDR_Buffer));
    Inc(Result, Extension.NDRSize(NDR_Buffer));
  end;
end;

{ TOP_JOINPROV3_PART }

procedure TOP_JOINPROV3_PART.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Rid := Ctx.UnpackUInt32;
    // lpSid
    Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    lpSid := Ctx.UnpackWideStr;
end;

procedure TOP_JOINPROV3_PART.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(Rid);
    Ctx.PackPtr(Pointer(lpSid));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    Ctx.PackWideStr(lpSid);
end;

function TOP_JOINPROV3_PART.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(Rid));
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    Inc(Result, NDRWideStrSize(lpSid));
end;

{ TOP_PACKAGE_PART }

procedure TOP_PACKAGE_PART.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  Size: UInt32;
  PreviousOffset: SizeInt;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    PartType := Ctx.UnpackGuid;
    ulFlags := Ctx.UnpackUInt32;
    PartLen := Ctx.UnpackUInt32;
    Part.RawBytes := Ctx.UnpackPtr;
    Extension.NDRUnpack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(Part.RawBytes) then
    begin
      Size := Ctx.UnpackUInt32;
      PreviousOffset := Ctx.Current;
      if Size <> PartLen then
        raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [PartLen, Size]);
      Part.RawBytes := Ctx.MemoryContext^.GetZeroedMem(Size);

      if IsEqualGuid(PartType, GUID_JOIN_PROVIDER) then
        TODJ_WIN7BLOB_serialized.NDRUnpack(Ctx, Part.Win7Blob^)
      else if IsEqualGuid(PartType, GUID_JOIN_PROVIDER3) then
        TOP_JOINPROV3_PART_serialized_ptr.NDRUnpack(Ctx, Part.JoinProv3)
      else if IsEqualGuid(PartType, GUID_POLICY_PROVIDER) then
        TOP_POLICY_PART_serialized_ptr.NDRUnpack(Ctx, Part.PolicyProvider);
      Ctx.Current := PreviousOffset + Size;
    end;
  end;
end;

procedure TOP_PACKAGE_PART.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackGuid(PartType);
    Ctx.PackUInt32(ulFlags);
    Ctx.PackUInt32(NDRSize_PartBlob);
    Ctx.PackPtr(Part.RawBytes);
    Extension.NDRPack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(Part.RawBytes) then
    begin
      Ctx.PackUInt32(NDRSize_PartBlob);

      if IsEqualGuid(PartType, GUID_JOIN_PROVIDER) then
        TODJ_WIN7BLOB_serialized.NDRPack(Ctx, Part.Win7Blob^)
      else if IsEqualGuid(PartType, GUID_JOIN_PROVIDER3) then
        TOP_JOINPROV3_PART_serialized_ptr.NDRPack(Ctx, Part.JoinProv3)
      else if IsEqualGuid(PartType, GUID_POLICY_PROVIDER) then
        TOP_POLICY_PART_serialized_ptr.NDRPack(Ctx, Part.PolicyProvider);
    end;
  end;
end;

function TOP_PACKAGE_PART.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(PartType));
    Inc(Result, SizeOf(ulFlags));
    Inc(Result, SizeOf(PartLen));
    Inc(Result, NDR_PointerSize);
    Inc(Result, Extension.NDRSize(NDR_Scalar));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(Part.RawBytes) then
    begin
      Inc(Result, SizeOf(PartLen));
      Inc(Result, NDRSize_PartBlob);
    end;
  end;
end;

function TOP_PACKAGE_PART.NDRSize_PartBlob: SizeUInt;
begin
  Result := 0;

  if IsEqualGuid(PartType, GUID_JOIN_PROVIDER) then
    Inc(Result, TODJ_WIN7BLOB_serialized.NDRSize(Part.Win7Blob^))
  else if IsEqualGuid(PartType, GUID_JOIN_PROVIDER3) then
    Inc(Result, TOP_JOINPROV3_PART_serialized_ptr.NDRSize(part.JoinProv3))
  else if IsEqualGuid(PartType, GUID_POLICY_PROVIDER) then
    Inc(Result, TOP_POLICY_PART_serialized_ptr.NDRSize(part.PolicyProvider));
end;

{ TOP_PACKAGE_PART_COLLECTION }

procedure TOP_PACKAGE_PART_COLLECTION.NDRUnpack(Ctx: TNDRUnpackContext;
  NDRFormat: UInt32);
var
  NbParts: UInt32;
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    cParts := Ctx.UnpackUInt32;
    pParts := Ctx.UnpackPtr;
    Extension.NDRUnpack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(pParts) then
    begin
      NbParts := Ctx.UnpackUInt32;
      pParts := Ctx.MemoryContext^.GetMem(NbParts, SizeOf(pParts^));
      for i := 0 to NbParts - 1 do
        pParts[i].NDRUnpack(Ctx, NDR_Scalar);
      for i := 0 to NbParts - 1 do
        pParts[i].NDRUnpack(Ctx, NDR_Buffer);
    end;
  end;
end;

procedure TOP_PACKAGE_PART_COLLECTION.NDRPack(Ctx: TNDRPackContext;
  NDRFormat: UInt32);
var
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(cParts);
    Ctx.PackPtr(pParts);
    Extension.NDRPack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(pParts) then
    begin
      Ctx.PackUInt32(cParts);
      for i := 0 to cParts - 1 do
        pParts[i].NDRPack(Ctx, NDR_Scalar);
      for i := 0 to cParts - 1 do
        pParts[i].NDRPack(Ctx, NDR_Buffer);
    end;
    //Extension.NDRUnpack(Ctx, NDR_Buffer);
  end;
end;

function TOP_PACKAGE_PART_COLLECTION.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  i: Integer;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(cParts));
    Inc(Result, NDR_PointerSize);
    Inc(Result, Extension.NDRSize(NDR_Scalar));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, SizeOf(cParts));

    for i := 0 to cParts - 1 do
      Inc(Result, pParts[i].NDRSize(NDR_Scalar));
    for i := 0 to cParts - 1 do
      Inc(Result, pParts[i].NDRSize(NDR_Buffer));
    //Extension.NDRUnpack(Ctx, NDR_Buffer);
  end;
end;

{ TOP_PACKAGE_PART_COLLECTION_blob }

procedure TOP_PACKAGE_PART_COLLECTION_blob.NDRUnpack(Ctx: TNDRUnpackContext;
  NDRFormat: UInt32);
var
  Size: UInt32;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    cbBlob := Ctx.UnpackUInt32;
    pPackagePartCollection.p := Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pPackagePartCollection.p) then
    begin
      Size := Ctx.UnpackUInt32;
      if Size <> cbBlob then
        raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [cbBlob, Size]);
      TOP_PACKAGE_PART_COLLECTION_serialized_ptr.NDRUnpack(Ctx, pPackagePartCollection);
    end;
end;

procedure TOP_PACKAGE_PART_COLLECTION_blob.NDRPack(Ctx: TNDRPackContext;
  NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(NDRSize_blob);
    Ctx.PackPtr(pPackagePartCollection.p);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pPackagePartCollection.p) then
    begin
      Ctx.PackUInt32(NDRSize_blob);
      TOP_PACKAGE_PART_COLLECTION_serialized_ptr.NDRPack(Ctx, pPackagePartCollection);
    end;
end;

function TOP_PACKAGE_PART_COLLECTION_blob.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(cbBlob));
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pPackagePartCollection.p) then
    begin
      Inc(Result, SizeOf(cbBlob));
      Inc(Result, NDRSize_blob);
    end;
end;

function TOP_PACKAGE_PART_COLLECTION_blob.NDRSize_blob: SizeUInt;
begin
  Result := TOP_PACKAGE_PART_COLLECTION_serialized_ptr.NDRSize(pPackagePartCollection);
end;

{ TOP_BLOB }

procedure TOP_BLOB.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  Size: UInt32;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    cbBlob := Ctx.UnpackUInt32;
    pBlob := Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob) then
    begin
      Size := Ctx.UnpackUInt32;
      if Size <> cbBlob then
        raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [cbBlob, Size]);
      pBlob := Ctx.MemoryContext^.GetMem(Size);
      Move(PByte(Ctx.Unpack(Size))^, pBlob[0], Size);
    end;
end;

procedure TOP_BLOB.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(cbBlob);
    Ctx.PackPtr(pBlob);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob) then
    begin
      Ctx.PackUInt32(cbBlob);
      Ctx.Pack(@pBlob[0], cbBlob);
    end;
end;

function TOP_BLOB.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(cbBlob));
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob) then
    begin
      Inc(Result, SizeOf(cbBlob));
      Inc(Result, cbBlob);
    end;
end;

{ TOP_PACKAGE }

procedure TOP_PACKAGE.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    EncryptionType := Ctx.UnpackGuid;
    EncryptionContext.NDRUnpack(Ctx, NDR_Scalar);
    // Package part collection blob
    WrappedPartCollection.NDRUnpack(Ctx, NDR_Scalar);
    cbDecryptedPartCollection := Ctx.UnpackUInt32;
    Extension.NDRUnpack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    EncryptionContext.NDRUnpack(Ctx, NDR_Buffer);
    WrappedPartCollection.NDRUnpack(Ctx, NDR_Buffer);
    Extension.NDRUnpack(Ctx, NDR_Buffer);
  end;
end;

procedure TOP_PACKAGE.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackGuid(EncryptionType);
    EncryptionContext.NDRPack(Ctx, NDR_Scalar);
    // Package part collection blob
    WrappedPartCollection.NDRPack(Ctx, NDR_Scalar);
    Ctx.PackUInt32(cbDecryptedPartCollection);
    Extension.NDRPack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    EncryptionContext.NDRPack(Ctx, NDR_Buffer);
    WrappedPartCollection.NDRPack(Ctx, NDR_Buffer);
    Extension.NDRPack(Ctx, NDR_Buffer);
  end;
end;

function TOP_PACKAGE.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(EncryptionType));
    Inc(Result, EncryptionContext.NDRSize(NDR_Scalar));
    // Package part collection blob
    Inc(Result, WrappedPartCollection.NDRSize(NDR_Scalar));
    Inc(Result, SizeOf(cbDecryptedPartCollection));
    Inc(Result, Extension.NDRSize(NDR_Scalar));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin

    Inc(Result, EncryptionContext.NDRSize(NDR_Buffer));
    Inc(Result, WrappedPartCollection.NDRSize(NDR_Buffer));
    Inc(Result, Extension.NDRSize(NDR_Buffer));
  end;
end;

{ TDOMAIN_CONTROLLER_INFO }

procedure TDOMAIN_CONTROLLER_INFO.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32
  );
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    // dc_unc
    Ctx.UnpackPtr;
    // dc_address
    Ctx.UnpackPtr;
    dc_address_type := TDS_AddressType(Ctx.UnpackUInt32);
    domain_guid := Ctx.UnpackGuid;
    // domain_name
    Ctx.UnpackPtr;
    // forest_name
    Ctx.UnpackPtr;
    dc_flags := Ctx.UnpackUInt32;
    // dc_site_name
    Ctx.UnpackPtr;
    // client_site_name
    Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    dc_unc := Ctx.UnpackWideStr;
    dc_address := Ctx.UnpackWideStr;
    domain_name := Ctx.UnpackWideStr;
    forest_name := Ctx.UnpackWideStr;
    dc_site_name := Ctx.UnpackWideStr;
    client_site_name := Ctx.UnpackWideStr;
  end;
end;

procedure TDOMAIN_CONTROLLER_INFO.NDRPack(Ctx: TNDRPackContext;
  NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackPtr(Pointer(dc_unc));
    Ctx.PackPtr(Pointer(dc_address));
    Ctx.PackUInt32(UInt32(dc_address_type));
    Ctx.PackGuid(domain_guid);
    Ctx.PackPtr(Pointer(domain_name));
    Ctx.PackPtr(Pointer(forest_name));
    Ctx.PackUInt32(dc_flags);
    Ctx.PackPtr(Pointer(dc_site_name));
    Ctx.PackPtr(Pointer(client_site_name));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Ctx.PackWideStr(dc_unc);
    Ctx.PackWideStr(dc_address);
    Ctx.PackWideStr(domain_name);
    Ctx.PackWideStr(forest_name);
    Ctx.PackWideStr(dc_site_name);
    Ctx.PackWideStr(client_site_name);
  end;
end;

function TDOMAIN_CONTROLLER_INFO.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, NDR_PointerSize);
    Inc(Result, NDR_PointerSize);
    Inc(Result, SizeOf(dc_address_type));
    Inc(Result, SizeOf(domain_guid));
    Inc(Result, NDR_PointerSize);
    Inc(Result, NDR_PointerSize);
    Inc(Result, SizeOf(dc_flags));
    Inc(Result, NDR_PointerSize);
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, NDRWideStrSize(dc_unc));
    Inc(Result, NDRWideStrSize(dc_address));
    Inc(Result, NDRWideStrSize(domain_name));
    Inc(Result, NDRWideStrSize(forest_name));
    Inc(Result, NDRWideStrSize(dc_site_name));
    Inc(Result, NDRWideStrSize(client_site_name));
  end;
end;

{ TODJ_UNICODE_STRING }

function TODJ_UNICODE_STRING.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  Len: PtrInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(Length));
    Inc(Result, SizeOf(MaximumLength));
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, SizeOf(UInt32) * 3);
    Len := StrLenW(PWideChar(@Buffer[1]));
    Inc(Result, (Len + Len mod 2) * 2);
  end;
end;

procedure TODJ_UNICODE_STRING.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  Len: UInt32;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Length := Ctx.UnpackUInt16;
    MaximumLength := Ctx.UnpackUInt16;
    // Buffer
    Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    // MaxLength
    Ctx.UnpackUInt32;
    // Always 0
    Ctx.UnpackUInt32;
    // Length
    Len := Ctx.UnpackUInt32;
    Len := Len + (Len mod 2);

    SetLength(Buffer, Len);
    Move(PWideChar(Ctx.Unpack(Len * 2))^, Buffer[1], Len * 2);
  end;
end;

procedure TODJ_UNICODE_STRING.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
var
  NbChars: PtrInt;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    NbChars := StrLenW(PWideChar(@Buffer[1]));
    Ctx.PackUInt16(NbChars * 2);
    Ctx.PackUInt16((NbChars + 1) * 2);
    Ctx.PackPtr(Pointer(Buffer));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    NbChars := StrLenW(PWideChar(@Buffer[1]));
    Ctx.PackUInt32(NbChars + 1);
    Ctx.PackUInt32(0);
    Ctx.PackUInt32(NbChars);
    Ctx.Pack(@Buffer[1], (NbChars + NbChars mod 2) * 2);
  end;
end;

{ TODJ_POLICY_DNS_DOMAIN_INFO }

procedure TODJ_POLICY_DNS_DOMAIN_INFO.NDRUnpack(Ctx: TNDRUnpackContext;
  NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Name.NDRUnpack(Ctx, NDR_Scalar);
    DnsDomainName.NDRUnpack(Ctx, NDR_Scalar);
    DnsForestName.NDRUnpack(Ctx, NDR_Scalar);
    DomainGuid := Ctx.UnpackGuid;
    Sid := Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Name.NDRUnpack(Ctx, NDR_Buffer);
    DnsDomainName.NDRUnpack(Ctx, NDR_Buffer);
    DnsForestName.NDRUnpack(Ctx, NDR_Buffer);
    if Assigned(Sid) then
      Sid := Ctx.UnpackSidPtr
  end;
end;

procedure TODJ_POLICY_DNS_DOMAIN_INFO.NDRPack(Ctx: TNDRPackContext;
  NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Name.NDRPack(Ctx, NDR_Scalar);
    DnsDomainName.NDRPack(Ctx, NDR_Scalar);
    DnsForestName.NDRPack(Ctx, NDR_Scalar);
    Ctx.PackGuid(DomainGuid);
    Ctx.PackPtr(Sid);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Name.NDRPack(Ctx, NDR_Buffer);
    DnsDomainName.NDRPack(Ctx, NDR_Buffer);
    DnsForestName.NDRPack(Ctx, NDR_Buffer);
    if Assigned(Sid) then
      Ctx.PackSidPtr(Sid);
  end;
end;

function TODJ_POLICY_DNS_DOMAIN_INFO.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, Name.NDRSize(NDR_Scalar));
    Inc(Result, DnsDomainName.NDRSize(NDR_Scalar));
    Inc(Result, DnsForestName.NDRSize(NDR_Scalar));
    Inc(Result, SizeOf(DomainGuid));
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, Name.NDRSize(NDR_Buffer));
    Inc(Result, DnsDomainName.NDRSize(NDR_Buffer));
    Inc(Result, DnsForestName.NDRSize(NDR_Buffer));
    if Assigned(Sid) then
    begin
      // SubAuth count
      Inc(Result, SizeOf(UInt32));
      Inc(Result, NDRSidPtrSize(Sid))
    end;
  end;
end;

{ TODJ_WIN7BLOB }

procedure TODJ_WIN7BLOB.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    // lpDomain
    Ctx.UnpackPtr;
    //lpMachineName
    Ctx.UnpackPtr;
    // lpMachinePassword
    Ctx.UnpackPtr;
    /// Padding
    Ctx.UnpackUInt32;
    DnsDomainInfo.NDRUnpack(Ctx, NDR_Scalar);
    DcInfo.NDRUnpack(Ctx, NDR_Scalar);
    Options := Ctx.UnpackUInt32;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    lpDomain := Ctx.UnpackWideStr;
    lpMachineName := Ctx.UnpackWideStr;
    lpMachinePassword := Ctx.UnpackWideStr;
    DnsDomainInfo.NDRUnpack(Ctx, NDR_Buffer);
    DcInfo.NDRUnpack(Ctx, NDR_Buffer);
  end;
end;

procedure TODJ_WIN7BLOB.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackPtr(Pointer(lpDomain));
    Ctx.PackPtr(Pointer(lpMachineName));
    Ctx.PackPtr(Pointer(lpMachinePassword));
    /// Padding
    Ctx.PackUInt32(-1);
    DnsDomainInfo.NDRPack(Ctx, NDR_Scalar);
    DcInfo.NDRPack(Ctx, NDR_Scalar);
    Ctx.PackUInt32(Options);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Ctx.PackWideStr(lpDomain);
    Ctx.PackWideStr(lpMachineName);
    Ctx.PackWideStr(lpMachinePassword);
    DnsDomainInfo.NDRPack(Ctx, NDR_Buffer);
    DcInfo.NDRPack(Ctx, NDR_Buffer);
  end;
end;

function TODJ_WIN7BLOB.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, NDR_PointerSize);
    Inc(Result, NDR_PointerSize);
    Inc(Result, NDR_PointerSize);
    Inc(Result, SizeOf(Padding));
    Inc(Result, DnsDomainInfo.NDRSize(NDR_Scalar));
    Inc(Result, DcInfo.NDRSize(NDR_Scalar));
    Inc(Result, SizeOf(Options));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, NDRWideStrSize(lpDomain));
    Inc(Result, NDRWideStrSize(lpMachineName));
    Inc(Result, NDRWideStrSize(lpMachinePassword));
    Inc(Result, DnsDomainInfo.NDRSize(NDR_Buffer));
    Inc(Result, DcInfo.NDRSize(NDR_Buffer));
  end;
end;

{ TODJ_BLOB }

procedure TODJ_BLOB.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  Size: UInt32;
  PreviousOffset: SizeInt;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    ulODJFormat := TODJ_Format(Ctx.UnpackUInt32);
    cbBlob := Ctx.UnpackUInt32;
    pBlob.RawBytes := Pointer(Ctx.UnpackPtr);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob.RawBytes) then
    begin
      Size := Ctx.UnpackUInt32;
      PreviousOffset := Ctx.Current;
      if Size <> cbBlob then
        raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [cbBlob, Size]);
      pBlob.RawBytes := Ctx.MemoryContext^.GetZeroedMem(Size);

      case ulODJFormat of
        ODJ_WIN7BLOB:
          TODJ_WIN7BLOB_serialized.NDRUnpack(Ctx, pBlob.Win7Blob^);
        OP_PACKAGE:
            TOP_PACKAGE_serialized_ptr.NDRUnpack(Ctx, pBlob.OPPackage);
      end;
      Ctx.Current := PreviousOffset + Size;
    end;
end;

procedure TODJ_BLOB.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(UInt32(ulODJFormat));
    cbBlob := NDRSize_pBlob;
    Ctx.PackUInt32(NDRSize_pBlob);
    Ctx.PackPtr(pBlob.RawBytes);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob.RawBytes) then
    begin
      Ctx.PackUInt32(NDRSize_pBlob);
      case ulODJFormat of
        ODJ_WIN7BLOB:
          TODJ_WIN7BLOB_serialized.NDRPack(Ctx, pBlob.Win7Blob^);
        OP_PACKAGE:
            TOP_PACKAGE_serialized_ptr.NDRPack(Ctx, pBlob.OPPackage);
      end;
    end;
end;

function TODJ_BLOB.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(ulODJFormat));
    Inc(Result, SizeOf(cbBlob));
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob.RawBytes) then
    begin
      Inc(Result, SizeOf(cbBlob));
      Inc(Result, NDRSize_pBlob);
    end;
end;

function TODJ_BLOB.NDRSize_pBlob: SizeUInt;
begin
  Result := 0;
  case ulODJFormat of
    ODJ_WIN7BLOB:
      Inc(Result, TODJ_WIN7BLOB_serialized.NDRSize(pBlob.Win7Blob^));
    OP_PACKAGE:
      Inc(Result, TOP_PACKAGE_serialized_ptr.NDRSize(pBlob.OPPackage));
  end;
end;

{ TODJ_PROVISION_DATA }

procedure TODJ_PROVISION_DATA.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  i: Integer;
  NbBlobs: UInt32;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Version := Ctx.UnpackUInt32;
    ulcBlobs := Ctx.UnpackUInt32;
    pBlobs := Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(pBlobs) then
    begin
      NbBlobs := Ctx.UnpackUInt32;
      pBlobs := Ctx.MemoryContext^.GetMem(NbBlobs, SizeOf(pBlobs^));

      // Scalar Part
      for i := 0 to NbBlobs - 1 do
        pBlobs[i].NDRUnpack(Ctx, NDR_Scalar);

      // Buffer Part
      for i := 0 to NbBlobs - 1 do
        pBlobs[i].NDRUnpack(Ctx, NDR_Buffer);
    end;
  end;
end;

procedure TODJ_PROVISION_DATA.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
var
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(Version);
    Ctx.PackUInt32(ulcBlobs);
    Ctx.PackPtr(pBlobs);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Ctx.PackUInt32(ulcBlobs);

    // Scalar Part
    for i := 0 to ulcBlobs - 1 do
      pBlobs[i].NDRPack(Ctx, NDR_Scalar);

    // Buffer Part
    for i := 0 to ulcBlobs - 1 do
      pBlobs[i].NDRPack(Ctx, NDR_Buffer);
  end;
end;

function TODJ_PROVISION_DATA.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  i: Integer;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(Version));
    Inc(Result, SizeOf(ulcBlobs));
    Inc(Result, NDR_PointerSize);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, SizeOf(ulcBlobs));

    // Scalar Part
    for i := 0 to ulcBlobs - 1 do
      Inc(Result, pBlobs[i].NDRSize(NDR_Scalar));

    // Buffer Part
    for i := 0 to ulcBlobs - 1 do
      Inc(Result, pBlobs[i].NDRSize(NDR_Buffer));
  end;
end;

end.

