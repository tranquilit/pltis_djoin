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
  NDR_Scalar = $1;
  NDR_Buffer = $2;
  NDR_ScalarBuffer = $3;

type
  {$A-} // every record (or object) is packed from now on

  TNDR_Ptr = UInt32;
  TODJ_Format = (ODJ_WIN7BLOB = 1, OP_PACKAGE = 2);

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

  TNDRPrivateHeader = record
    CommonHeader: TCommonTypeHeader;
    PrivateHeader: TPrivateTypeHeader;
  end;
  PNDRPrivateHeader = ^TNDRPrivateHeader;

  TODJ_UNICODE_STRING = record
    Length: UInt16;
    MaximumLength: UInt16;
    Buffer: WideString;
  end;
  PODJ_UNICODE_STRING = ^TODJ_UNICODE_STRING;

  TOP_BLOB = record
    cbBlob: UInt32;
    pBlobl: TNDR_Ptr;
  end;
  POP_BLOB = ^TOP_BLOB;

  TODJ_POLICY_DNS_DOMAIN_INFO = record
    Name: TODJ_UNICODE_STRING;
    DnsDomainName: TODJ_UNICODE_STRING;
    DnsForestName: TODJ_UNICODE_STRING;
    DomainGuid: TGuid;
    Sid: PSid;
  end;
  PODJ_POLICY_DNS_DOMAIN_INFO = ^TODJ_POLICY_DNS_DOMAIN_INFO;

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
    Padding: UInt32; // Not in official struct but present in binary serialized
    DnsDomainInfo: TODJ_POLICY_DNS_DOMAIN_INFO;
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
      3: (RawBytes: PByte);
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
    pBlobs: array of TODJ_BLOB;
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
    // ODJ_WIN7BLOB
    fMachineDomainName: RawUtf8;
    fMachineName: RawUtf8;
    fMachinePassword: SpiUtf8;
    fOptions: UInt32;
    // Policy DNS Domain
    fPolicyDomainName: RawUtf8;
    fDnsDomainName: RawUtf8;
    fDnsForestName: RawUtf8;
    fDomainGUID: TGuid;
    fDomainSID: TSid;
    // Domain Informations
    fDCName: RawUtf8;
    fDCAddress: RawUtf8;
    fDCAddressType: UInt32;
    fDCDomainName: RawUtf8;
    fDCFlags: UInt32;
    fDCSiteName: RawUtf8;
    fDCClientSiteName: RawUtf8;
  public
    constructor Create;

    /// Load a DJoin file in memory
    // - Return true if the file has been successfully loaded
    function LoadFromFile(const Filename: TFileName): boolean;

    // Machine Informations
    property MachineDomainName: RawUtf8 read fMachineDomainName write fMachineDomainName;
    property MachineName: RawUtf8 read fMachineName write fMachineName;
    property MachinePassword: SpiUtf8 read fMachinePassword write fMachinePassword;
    property Options: UInt32 read fOptions write fOptions;
    // Policy DNS Domain
    property PolicyDomainName: RawUtf8 read fPolicyDomainName write fPolicyDomainName;
    property DnsDomainName: RawUtf8 read fDnsDomainName write fDnsDomainName;
    property DnsForestName: RawUtf8 read fDnsForestName write fDnsForestName;
    property DomainGUID: TGuid read fDomainGUID write fDomainGUID;
    property DomainSID: TSid read fDomainSID write fDomainSID;
    // Domain Informations
    property DCName: RawUtf8 read fDCName write fDCName;
    property DCAddress: RawUtf8 read fDCAddress write fDCAddress;
    property DCAddressType: UInt32 read fDCAddressType write fDCAddressType;
    property DCDomainName: RawUtf8 read fDCDomainName write fDCDomainName;
    property DCFlags: UInt32 read fDCFlags write fDCFlags;
    property DCSiteName: RawUtf8 read fDCSiteName write fDCSiteName;
    property DCClientSiteName: RawUtf8 read fDCClientSiteName write fDCClientSiteName;
  end;
  PDJoin = ^TDJoin;

  { TDJoinParser }



  TDJoinParser = class
  private
    fBufferLength: SizeInt;
    fBinaryContent: RawByteString;
    fDJoin: PDJoin;

    fProvisionData: TODJ_PROVISION_DATA;

    constructor Create(DJoin: PDJoin);
    function Parse(FileContent: RawByteString): Boolean;
    function ParseBinary(Binary: RawByteString): Boolean;

    function ParseProvisionData(At: Pointer; var ProvisionData: TODJ_PROVISION_DATA; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseBlob(At: Pointer; var Blob: TODJ_BLOB; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseWin7Blob(At: Pointer; var Win7Blob: TODJ_WIN7BLOB; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParsePolicyDnsDomainInfo(At: Pointer; var PolicyDnsDomainInfo: TODJ_POLICY_DNS_DOMAIN_INFO; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseDomainControllerInfo(At: Pointer; var DomainControllerInfo: TDOMAIN_CONTROLLER_INFO; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseSidPtr(At: Pointer; var Sid: PSid; NDRFormat: UInt32): Pointer;

    function ParseUnicodeString(At: Pointer; var UnicodeStr: TODJ_UNICODE_STRING; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseUnicodeBuffer(At: Pointer; var Buffer: WideString): Pointer;


    function GetODJ_PROVISION_DATA_header: PNDRPrivateHeader;
    procedure NextString(var Str: PDJoinString);
    function ConvertString(Str: PDJoinString): RawUtf8;
    function VerifyHeader(Header: PNDRPrivateHeader): Boolean;

    function StartAddress: Pointer;
    property ODJ_PROVISION_DATA_header: PNDRPrivateHeader read GetODJ_PROVISION_DATA_header;

    property BufferLength: SizeInt read fBufferLength;
  public
    class function ParseFile(FileName: TFileName; out DJoin: TDJoin): Boolean;
  end;



implementation

const
  EXPECTED_COMMON_HEADER : UInt64 = $cccccccc00081001;
  PRIVATE_HEADER_FILLER: UInt32 = 0;
  OPTIONS_OFFSET = $40;
  GLOBAL_DOMAIN_OFFSET = $b4;
  DNS_POLICY_GUID_OFFSET = $78;



{ TDJoin }

constructor TDJoin.Create;
begin

end;

function TDJoin.LoadFromFile(const Filename: TFileName): boolean;
begin
  Result := TDJoinParser.ParseFile(Filename, Self);
end;

{ TDJoinParser }

constructor TDJoinParser.Create(DJoin: PDJoin);
begin
  fDJoin := DJoin;
end;

function TDJoinParser.Parse(FileContent: RawByteString): Boolean;
var
  Base64: RawUtf8;
  Binary: RawByteString;
begin
  Base64 := RawUnicodeToUtf8(pointer(FileContent), Length(WideString(FileContent)) div 2 - 1);
  Binary := Base64toBin(Base64);

  // Not base64 encoded
  if Binary = '' then
    Exit(False);

  Result := ParseBinary(Binary);
end;

function TDJoinParser.ParseBinary(Binary: RawByteString): Boolean;
var
  CurrentStr: PDJoinString;
  Sid: PSid;
  guidStr: RawUtf8;
  guid: PGuid;
  temp: TRawSmbiosInfo;

  ProvisionData: TODJ_PROVISION_DATA;
begin
  fBinaryContent := Binary;
  fBufferLength := Length(fBinaryContent);

  // Header length and actual length differs
  if not VerifyHeader(StartAddress) then
    Exit(False);

  ParseProvisionData(StartAddress + sizeof(TNDRPrivateHeader) + sizeof(TNDR_Ptr), fProvisionData);

  // File too short to contains the options
  //if OPTIONS_OFFSET + sizeof(Options) > BufferLength then
  //  Exit(False);
  //fOptions := StartAddress + OPTIONS_OFFSET;

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

function TDJoinParser.ParseProvisionData(At: Pointer;
  var ProvisionData: TODJ_PROVISION_DATA; NDRFormat: UInt32): Pointer;
var
  i: Integer;
  Data: PODJ_PROVISION_DATA;
begin

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Data := PODJ_PROVISION_DATA(At);
    ProvisionData.Version := Data^.Version;
    ProvisionData.ulcBlobs := Data^.ulcBlobs;
    SetLength(ProvisionData.pBlobs, ProvisionData.ulcBlobs);
    Result := At + Sizeof(ProvisionData) + sizeof(TNDR_Ptr);


    // Scalar Part
    for i := 0 to ProvisionData.ulcBlobs - 1 do
      Result := ParseBlob(Result, ProvisionData.pBlobs[i], NDR_Scalar);

    // Buffer Part
    for i := 0 to ProvisionData.ulcBlobs - 1 do
      Result := ParseBlob(Result, ProvisionData.pBlobs[i], NDR_Buffer);
  end;
  Result := Result;
end;

function TDJoinParser.ParseBlob(At: Pointer; var Blob: TODJ_BLOB;
  NDRFormat: UInt32): Pointer;
var
  Size: DWord;
begin
  Result := At;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Blob := PODJ_BLOB(At)^;
    if (Blob.ulODJFormat <> ODJ_WIN7BLOB) and (Blob.ulODJFormat <> OP_PACKAGE) then
      raise Exception.CreateFmt('Unknown blob ulODJFormat: %d', [Blob.ulODJFormat]);
    /// TO FREE
    Blob.pBlob.RawBytes := GetMem(Blob.cbBlob);
    FillZero(blob.pBlob.RawBytes^, blob.cbBlob);
    Result := Result + sizeof(Blob);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Size := PUInt32(At)^;
    if Size <> Blob.cbBlob then
      raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [Blob.cbBlob, Size]);

    case blob.ulODJFormat of
      ODJ_WIN7BLOB:
        ParseWin7Blob(Result + sizeof(Size), blob.pBlob.Win7Blob^);
    end;

    Result := Result + Size;
  end;
end;

function TDJoinParser.ParseWin7Blob(At: Pointer; var Win7Blob: TODJ_WIN7BLOB;
  NDRFormat: UInt32): Pointer;
var
  Data: PODJ_WIN7BLOB;
begin
  Result := At;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    if not VerifyHeader(At) then
      raise Exception.CreateFmt('Invalid NDR Header at %x', [At - StartAddress]);

    Data := PODJ_WIN7BLOB(At + sizeof(TNDRPrivateHeader));
    ParsePolicyDnsDomainInfo(@Data^.DnsDomainInfo, Win7Blob.DnsDomainInfo, NDR_Scalar);
    ParseDomainControllerInfo(@Data^.DcInfo, Win7Blob.DcInfo, NDR_Scalar);
    Win7Blob.Options := Data^.Options;

    Result := Result + sizeof(Win7Blob) + sizeof(TNDRPrivateHeader);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Result := ParseUnicodeBuffer(Result, Win7Blob.lpDomain);
    Result := ParseUnicodeBuffer(Result, Win7Blob.lpMachineName);
    Result := ParseUnicodeBuffer(Result, Win7Blob.lpMachinePassword);

    Result := ParsePolicyDnsDomainInfo(Result, Win7Blob.DnsDomainInfo, NDR_Buffer);
    Result := ParseDomainControllerInfo(Result, Win7Blob.DcInfo, NDR_Buffer);
  end;
end;

function TDJoinParser.ParsePolicyDnsDomainInfo(At: Pointer;
  var PolicyDnsDomainInfo: TODJ_POLICY_DNS_DOMAIN_INFO; NDRFormat: UInt32
  ): Pointer;
begin
  Result := At;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Result := ParseUnicodeString(Result, PolicyDnsDomainInfo.Name, NDR_Scalar);
    Result := ParseUnicodeString(Result, PolicyDnsDomainInfo.DnsDomainName, NDR_Scalar);
    Result := ParseUnicodeString(Result, PolicyDnsDomainInfo.DnsForestName, NDR_Scalar);
    PolicyDnsDomainInfo.DomainGuid := PGuid(Result)^;
    Result := Result + sizeof(PolicyDnsDomainInfo.DomainGuid) + sizeof(PolicyDnsDomainInfo.Sid);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Result := ParseUnicodeString(Result, PolicyDnsDomainInfo.Name, NDR_Buffer);
    Result := ParseUnicodeString(Result, PolicyDnsDomainInfo.DnsDomainName, NDR_Buffer);
    Result := ParseUnicodeString(Result, PolicyDnsDomainInfo.DnsForestName, NDR_Buffer);
    Result := ParseSidPtr(Result, PolicyDnsDomainInfo.Sid, NDR_Buffer);
  end;
end;

function TDJoinParser.ParseDomainControllerInfo(At: Pointer;
  var DomainControllerInfo: TDOMAIN_CONTROLLER_INFO; NDRFormat: UInt32
  ): Pointer;
begin
  Result := At;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Result := Result + sizeof(TNDR_Ptr) * 2;
    DomainControllerInfo.dc_address_type := PUInt32(Result)^;
    DomainControllerInfo.domain_guid := PGuid(Result + Sizeof(UInt32))^;
    Result := Result + Sizeof(UInt32) + SizeOf(TGuid) + SizeOf(TNDR_Ptr) * 2;
    DomainControllerInfo.dc_flags := PUInt32(Result)^;
    Result := Result + sizeof(UInt32) * 3;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Result := ParseUnicodeBuffer(Result, DomainControllerInfo.dc_unc);
    Result := ParseUnicodeBuffer(Result, DomainControllerInfo.dc_address);
    Result := ParseUnicodeBuffer(Result, DomainControllerInfo.domain_name);
    Result := ParseUnicodeBuffer(Result, DomainControllerInfo.forest_name);
    Result := ParseUnicodeBuffer(Result, DomainControllerInfo.dc_site_name);
    Result := ParseUnicodeBuffer(Result, DomainControllerInfo.client_site_name);
  end;

end;

function TDJoinParser.ParseSidPtr(At: Pointer; var Sid: PSid; NDRFormat: UInt32
  ): Pointer;
var
  NbAuth, Len: UInt32;
begin
  Result := At;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    NbAuth := PUInt32(At)^;
    Result := Result + Sizeof(UInt32);

    Len := 8 + Sizeof(UInt32) * NbAuth;
    /// TO FREE
    Sid := GetMem(Len);
    Move(PSid(Result)^, Sid^, Len);
    Result := Result + Len;
  end;
end;

function TDJoinParser.ParseUnicodeString(At: Pointer;
  var UnicodeStr: TODJ_UNICODE_STRING; NDRFormat: UInt32): Pointer;
begin
  Result := At;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    // Retrieve the length informations
    Move(PODJ_UNICODE_STRING(At)^, UnicodeStr, sizeof(UInt16) * 2);
    Result := Result + sizeof(UnicodeStr);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    Result := ParseUnicodeBuffer(Result, UnicodeStr.Buffer);
end;

function TDJoinParser.ParseUnicodeBuffer(At: Pointer; var Buffer: WideString
  ): Pointer;
var
  Len: DWord;
begin
  Len := PUInt32(PUInt32(At) + 2)^;
  Len := Len + (Len mod 2);
  SetLength(Buffer, Len);
  Move(PWideChar(At + sizeof(UInt32) * 3)^, Buffer[1], Len * 2);
  Result := At + sizeof(UInt32) * 3 + Len * 2;
end;

class function TDJoinParser.ParseFile(FileName: TFileName; out DJoin: TDJoin
  ): Boolean;
begin
  with TDJoinParser.Create(@DJoin) do
  try
    Result := Parse(StringFromFile(Filename));
  finally
    Free;
  end;
end;

procedure TDJoinParser.NextString(var Str: PDJoinString);
begin
  Str := Pointer(Str) + 12 + (Str^.BuffLen + (Str^.BuffLen mod 2)) * 2;
end;

function TDJoinParser.GetODJ_PROVISION_DATA_header: PNDRPrivateHeader;
begin
  Result := StartAddress;
end;

function TDJoinParser.ConvertString(Str: PDJoinString): RawUtf8;
begin
  // Corrupted
  if (@str^.Buffer > StartAddress + BufferLength) or (@str^.Buffer + str^.BuffLen > StartAddress + BufferLength) then
    Exit;

  Result := RawUnicodeToUtf8(@Str^.Buffer, Str^.BuffLen);
end;


function TDJoinParser.VerifyHeader(Header: PNDRPrivateHeader): Boolean;
begin
  Result :=  (Header^.CommonHeader.Header = EXPECTED_COMMON_HEADER) and
             (Header^.PrivateHeader.ObjectBufferLength <= BufferLength - sizeof(Header^)) and
             (Header^.PrivateHeader.Filler = PRIVATE_HEADER_FILLER);
end;

function TDJoinParser.StartAddress: Pointer;
begin
  if fBinaryContent = '' then
    Result := nil
  else
    Result := @fBinaryContent[1];
end;

end.

