unit uDJoin;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.os,
  mormot.core.buffers,
  mormot.core.unicode, mormot.core.base;

const
  MAX_SID_ELEMENTS = 10;

type
  {$A-} // every record (or object) is packed from now on

  TRDN_Ptr = UInt32;
  TODJ_Format = (ODJ_WIN7BLOB, OP_PACKAGE);

  TCommonTypeHeader = record
    case bool of
      False: (Version: Byte;
             Endianness: Byte;
             Length: UInt16;
             Filler: UInt32;);
      True: (Header: UInt64);
  end;
  PCommonTypeHeader = ^TCommonTypeHeader;

  TPrivateTypeHeader = record
    ObjectBufferLength: UInt32;
    Filler: UInt32;
  end;
  PPrivateTypeHeader = ^TPrivateTypeHeader;

  TRDNPrivateHeader = record
    CommonHeader: TCommonTypeHeader;
    PrivateHeader: TPrivateTypeHeader;
  end;
  PRDNPrivateHeader = ^TRDNPrivateHeader;

  TODJ_UNICODE_STRING = record
    Length: UInt16;
    MaximumLength: UInt16;
    Buffer: TRDN_Ptr;
  end;
  PODJ_UNICODE_STRING = ^TODJ_UNICODE_STRING;

  TOP_BLOB = record
    cbBlob: UInt32;
    pBlobl: TRDN_Ptr;
  end;
  POP_BLOB = ^TOP_BLOB;

  TODJ_OPLICY_DNS_DOMAIN_INFO = record
    Name: TODJ_UNICODE_STRING;
    DnsDomainName: TODJ_UNICODE_STRING;
    DnsForestName: TODJ_UNICODE_STRING;
    DomainGuid: TGuid;
    Sid: TRDN_Ptr;
  end;
  PODJ_OPLICY_DNS_DOMAIN_INFO = ^TODJ_OPLICY_DNS_DOMAIN_INFO;

  TDOMAIN_CONTROLLER_INFO = record
    dc_unc: WideString;
    dc_address: WideString;
    dc_address_type: UInt32;
    domain_guid: TGuid;
    domain_name: WideString;
    forest_name: WideString;
    dc_flags: UInt32;
    dc_site_name: WideString;
    client_site_name: WideString;
  end;
  PDOMAIN_CONTROLLER_INFO = ^TDOMAIN_CONTROLLER_INFO;

  TODJ_WIN7BLOB = record
    lpDomain: WideString;
    lpMachineName: WideString;
    lpMachinePassword: WideString;
    DnsDomainInfo: TODJ_OPLICY_DNS_DOMAIN_INFO;
    DcInfo: TDOMAIN_CONTROLLER_INFO;
    Options: UInt32;
  end;
  PODJ_WIN7BLOB = ^TODJ_WIN7BLOB;

  TOP_PACKAGE_PART = record
    PartType: TGUID;
    ulFlags: UInt32;
    Part: TOP_BLOB;
    Extension: TOP_BLOB;
  end;
  POP_PACKAGE_PART = ^TOP_PACKAGE_PART;

  TOP_PACKAGE_PART_COLLECTION = record
    cParts: UInt32;
    pParts: POP_PACKAGE_PART;
    Extension: TOP_BLOB;
  end;
  POP_PACKAGE_PART_COLLECTION = ^TOP_PACKAGE_PART_COLLECTION;

  TOP_PACKAGE = record
    EncryptionType: TGUID;
    EncryptionContext: TOP_BLOB;
    WrappedPartCollection: TOP_BLOB;
    cbDecryptedPartCollection: UInt32;
    Extension: TOP_BLOB;
  end;
  POP_PACKAGE = ^TOP_PACKAGE;

  TODJ_BLOB_buffer_u = record
    case UInt32 of
      1: (Win7Blob: PODJ_WIN7BLOB);
      2: (OPPackage: POP_PACKAGE);
  end;
  PODJ_BLOB_buffer_u = ^TODJ_BLOB_buffer_u;

  TODJ_BLOB = record
    ulODJFormat: TODJ_Format;
    cbBlob: UInt32;
    pBlob: TODJ_BLOB_buffer_u;
  end;
  PODJ_BLOB = ^TODJ_BLOB;

  TODJ_PROVISION_DATA = record
    Version: UInt32;
    ulcBlobs: UInt32;
    pBlobs: PODJ_BLOB;
  end;
  PODJ_PROVISION_DATA = ^TODJ_PROVISION_DATA;

  TDJoinString = record
    BuffSize: UInt32;
    BuffOffset: UInt32;
    BuffLen: UInt32;
    Buffer: Char;
  end;
  PDJoinString = ^TDJoinString;

  { TDJoin }

  TDJoin = class
  private
    fOptions: PInt32;

    fBufferLength: SizeInt;
    fBinaryContent: RawByteString;

    function GetODJ_PROVISION_DATA_header: PRDNPrivateHeader;
    procedure NextString(var Str: PDJoinString);

    function ConvertString(Str: PDJoinString): RawUtf8;
    function Parse: Boolean;

    function CheckODJ_PROVISION_DATA: Boolean;
  public
    constructor Create;

    /// Load a DJoin file in memory
    // - Return true if the file has been successfully loaded
    function LoadFromFile(const Filename: TFileName): boolean;

    /// Unload the current file in memory
    // - Can be called even if no file is loaded
    procedure Unload;

    function StartAddress: Pointer;

    property ODJ_PROVISION_DATA_header: PRDNPrivateHeader read GetODJ_PROVISION_DATA_header;
    property Options: PInt32 read fOptions;
    property BufferLength: SizeInt read fBufferLength;
  end;



implementation

const
  EXPECTED_COMMON_HEADER : UInt64 = $cccccccc00081001;
  PRIVATE_HEADER_FILLER: UInt32 = 0;
  OPTIONS_OFFSET = $40;
  GLOBAL_DOMAIN_OFFSET = $b4;
  DNS_POLICY_GUID_OFFSET = $78;

{ TDJoin }

procedure TDJoin.NextString(var Str: PDJoinString);
begin
  Str := Pointer(Str) + 12 + (Str^.BuffLen + (Str^.BuffLen mod 2)) * 2;
end;

function TDJoin.GetODJ_PROVISION_DATA_header: PRDNPrivateHeader;
begin
  Result := StartAddress;
end;

function TDJoin.ConvertString(Str: PDJoinString): RawUtf8;
begin
  // Corrupted
  if (@str^.Buffer > StartAddress + BufferLength) or (@str^.Buffer + str^.BuffLen > StartAddress + BufferLength) then
    Exit;

  Result := RawUnicodeToUtf8(@Str^.Buffer, Str^.BuffLen);
end;

function TDJoin.Parse: Boolean;
var
  CurrentStr: PDJoinString;
  Sid: PSid;
  guidStr: RawUtf8;
  guid: PGuid;
  temp: TRawSmbiosInfo;
begin
  // Header length and actual length differs
  if not CheckODJ_PROVISION_DATA then
    Exit(False);

  // File too short to contains the options
  if OPTIONS_OFFSET + sizeof(fOptions^) > BufferLength then
    Exit(False);
  fOptions := StartAddress + OPTIONS_OFFSET;

  // File too short to contains the policy guid
  if DNS_POLICY_GUID_OFFSET + sizeof(guid^) > BufferLength then
    Exit(False);
  guid := StartAddress + DNS_POLICY_GUID_OFFSET;

  // File too short to contains the domain name
  if GLOBAL_DOMAIN_OFFSET + sizeof(TDJoinString) > BufferLength then
    Exit(False);
  CurrentStr := StartAddress + GLOBAL_DOMAIN_OFFSET + 12; /// Not sure about the +12
  WriteLn('Machine Information:');
  WriteLn(' - Domain: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - Computer name: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - Computer password: ', ConvertString(CurrentStr));

  WriteLn(CRLF,'Domain Policy Information:');
  NextString(CurrentStr);
  WriteLn(' - Domain Name: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - DNS Name: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - Forest Name: ', ConvertString(CurrentStr));

  DecodeSmbiosUuid(guid, guidStr, temp);
  WriteLn(' - Domain GUID: ', guidStr);

  NextString(CurrentStr);
  Sid := Pointer(CurrentStr) + 4;

  // File too short to contains the SID informations
  if (Pointer(Sid) > StartAddress + BufferLength) or (@sid^.SubAuthority[sid^.SubAuthorityCount] > StartAddress + BufferLength) then
    Exit(False);
  WriteLn(' - SID: ', SidToText(sid));

  // Too many SID elements
  //if Sid^.Size > MAX_SID_ELEMENTS then
  //  Exit(False);

  Result := True;
end;

function TDJoin.CheckODJ_PROVISION_DATA: Boolean;
var
  h: PRDNPrivateHeader;
begin
  h := ODJ_PROVISION_DATA_header;
  Result :=  (h^.CommonHeader.Header = EXPECTED_COMMON_HEADER) and
             (h^.PrivateHeader.ObjectBufferLength = BufferLength - sizeof(h^)) and
             (h^.PrivateHeader.Filler = PRIVATE_HEADER_FILLER);
end;

constructor TDJoin.Create;
begin

end;

function TDJoin.LoadFromFile(const Filename: TFileName): boolean;
var
  Base64Utf16: RawByteString;
  Base64, Binary: RawUtf8;
begin
  Unload;

  Base64Utf16 := StringFromFile(Filename);
  Base64 := RawUnicodeToUtf8(pointer(Base64Utf16), Length(WideString(Base64Utf16)) div 2 - 1);
  Binary := Base64toBin(Base64);

  // Not base64 encoded
  if Binary = '' then
    Exit(False);

  fBinaryContent := Binary;
  fBufferLength := Length(fBinaryContent);
  Result := Parse;
  if not Result then
    Unload;
end;

procedure TDJoin.Unload;
begin
  fBinaryContent := '';
  fBufferLength := 0;
  fOptions := nil;
end;

function TDJoin.StartAddress: Pointer;
begin
  if fBinaryContent = '' then
    Result := nil
  else
    Result := @fBinaryContent[1];
end;

end.

