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
    pBlob: PByte;
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

  TOP_JOINPROV3_PART = record
    Rid: UInt32;
    lpSid: WideString;
  end;
  POP_JOINPROV3_PART = ^TOP_JOINPROV3_PART;

  TOP_PACKAGE_PART = record
    PartType: TGUID;
    ulFlags: UInt32;
    Part: TOP_BLOB;
    Extension: TOP_BLOB;
  end;
  POP_PACKAGE_PART = ^TOP_PACKAGE_PART;

  TOP_PACKAGE_PART_COLLECTION = record
    cParts: UInt32;
    pParts: array of TOP_PACKAGE_PART;
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

    // OP_PACKAGE
    fMachineSid: TSid;
  public
    constructor Create;

    /// Load a DJoin file in memory
    // - Return true if the file has been successfully loaded
    function LoadFromFile(const Filename: TFileName): boolean;

    function LoadFromProvisionData(const ProvisionData: TODJ_PROVISION_DATA): Boolean;

    procedure Dump;

    // Machine Informations
    property MachineDomainName: RawUtf8 read fMachineDomainName write fMachineDomainName;
    property MachineName: RawUtf8 read fMachineName write fMachineName;
    property MachinePassword: SpiUtf8 read fMachinePassword write fMachinePassword;
    property MachineSid: TSid read fMachineSid write fMachineSid;
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

    function ParseOpPackage(At: Pointer; var OpPackage: TOP_PACKAGE; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseOpBlob(At: Pointer; var OpBlob: TOP_BLOB; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseOpPackagePartCollection(At: Pointer; var OpPackagePartCollection: TOP_PACKAGE_PART_COLLECTION; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParsePackagePart(At: Pointer; var OpPackagePart: TOP_PACKAGE_PART; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseOpJoinProv3Part(At: Pointer; var OpJoinProv3Part: TOP_JOINPROV3_PART; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;

    function ParseUnicodeString(At: Pointer; var UnicodeStr: TODJ_UNICODE_STRING; NDRFormat: UInt32 = NDR_ScalarBuffer): Pointer;
    function ParseUnicodeBuffer(At: Pointer; var Buffer: WideString): Pointer;
    function ParseGUID(At: Pointer; var Guid: TGuid): Pointer;
    function ParseUint32(At: Pointer; var value: UInt32): Pointer;

    function VerifyHeader(Header: PNDRPrivateHeader): Boolean;

    function StartAddress: Pointer;
    property BufferLength: SizeInt read fBufferLength;
  public
    class function ParseFile(FileName: TFileName; out DJoin: TDJoin): Boolean;
  end;



implementation

const
  EXPECTED_COMMON_HEADER : UInt64 = $cccccccc00081001;
  PRIVATE_HEADER_FILLER: UInt32 = 0;

  GUID_JOIN_PROVIDER : TGUID = '{631c7621-5289-4321-bc9e-80f843f868c3}';
  GUID_JOIN_PROVIDER2 : TGUID = '{57BFC56B-52F9-480C-ADCB-91B3F8A82317}';
  GUID_JOIN_PROVIDER3 : TGUID = '{FC0CCF25-7FFA-474A-8611-69FFE269645F}';
  GUID_CERT_PROVIDER : TGUID = '{9c0971e9-832f-4873-8e87-ef1419d4781e}';
  GUID_POLICY_PROVIDER : TGUID = '{68fb602a-0c09-48ce-b75f-07b7bd58f7ec}';


{ TDJoin }

constructor TDJoin.Create;
begin

end;

function TDJoin.LoadFromFile(const Filename: TFileName): boolean;
begin
  Result := TDJoinParser.ParseFile(Filename, Self);
end;

function TDJoin.LoadFromProvisionData(const ProvisionData: TODJ_PROVISION_DATA
  ): Boolean;
var
  BlobId, PartId: Integer;
  Blob: TODJ_BLOB;
  Win7: PODJ_WIN7BLOB;
  OpPackage: POP_PACKAGE;
  PackageParts: POP_PACKAGE_PART_COLLECTION;
  Part: TOP_PACKAGE_PART;
  TempSidStr: RawUtf8;
begin
  for BlobId := 0 to ProvisionData.ulcBlobs - 1 do
  begin
    Blob := ProvisionData.pBlobs[BlobId];
    case Blob.ulODJFormat of
      ODJ_WIN7BLOB:
      begin
        Win7 := Blob.pBlob.Win7Blob;
        /// ODJ_WIN7BLOB
        MachineDomainName := WideStringToUtf8(Win7^.lpDomain);
        MachineName := WideStringToUtf8(Win7^.lpMachineName);
        MachinePassword := WideStringToUtf8(Win7^.lpMachinePassword);
        Options := Win7^.Options;
        /// Policy DNS Domain
        PolicyDomainName := WideStringToUtf8(Win7^.DnsDomainInfo.Name.Buffer);
        DnsDomainName := WideStringToUtf8(Win7^.DnsDomainInfo.DnsDomainName.Buffer);
        DnsForestName := WideStringToUtf8(Win7^.DnsDomainInfo.DnsForestName.Buffer);
        DomainGUID := Win7^.DnsDomainInfo.DomainGuid;
        Move(Win7^.DnsDomainInfo.Sid^, fDomainSID, 8 + SizeOf(UInt32) * Win7^.DnsDomainInfo.Sid^.SubAuthorityCount);
        /// Domain Informations
        DCName := WideStringToUtf8(Win7^.DcInfo.dc_unc);
        DCAddress := WideStringToUtf8(Win7^.DcInfo.dc_address);
        DCAddressType := Win7^.DcInfo.dc_address_type;
        DCFlags := Win7^.DcInfo.dc_flags;
        DCSiteName := WideStringToUtf8(Win7^.DcInfo.dc_site_name);
        DCClientSiteName := WideStringToUtf8(Win7^.DcInfo.client_site_name);
      end;
      OP_PACKAGE:
      begin
        OpPackage := Blob.pBlob.OPPackage;
        PackageParts := POP_PACKAGE_PART_COLLECTION(OpPackage^.WrappedPartCollection.pBlob);
        for PartId := 0 to PackageParts^.cParts - 1 do
        begin
          Part := PackageParts^.pParts[PartId];

          if IsEqualGuid(Part.PartType, GUID_JOIN_PROVIDER3) then
          begin
            TempSidStr := WideStringToUtf8(POP_JOINPROV3_PART(Part.Part.pBlob)^.lpSid);
            TextToSid(PChar(@TempSidStr[1]), fMachineSid);
          end;
        end;
      end;
    end;
  end;
end;

procedure TDJoin.Dump;
var
  DomainGuidStr: RawUtf8;
  temp: TRawSmbiosInfo;
begin
  DecodeSmbiosUuid(@DomainGUID, DomainGuidStr, temp);

  WriteLn('Machine Information:');
  WriteLn(' - Domain: ', MachineDomainName);
  WriteLn(' - Name: ', MachineName);
  WriteLn(' - Password: ', MachinePassword);
  WriteLn(' - Sid: ', SidToText(@MachineSid));
  WriteLn(' - Site Name: ', DCClientSiteName);

  WriteLn(CRLF+'Domain Policy Information:');
  WriteLn(' - Domain Name: ', PolicyDomainName);
  WriteLn(' - DNS Domain Name: ', DnsDomainName);
  WriteLn(' - DNS Forest Name: ', DnsForestName);
  WriteLn(' - Domain GUID: ', DomainGuidStr);
  WriteLn(' - Domain SID: ', SidToText(@DomainSID));

  WriteLn(CRLF+'Domain Controller Information:');
  WriteLn(' - Name: ', DCName);
  WriteLn(' - Address: ', DCAddress);
  WriteLn(Format(' - Address Type: 0x%x', [DCAddressType]));
  WriteLn(Format(' - Flags: 0x%x', [DCFlags]));
  WriteLn(' - Site Name: ', DCSiteName);
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
begin
  fBinaryContent := Binary;
  fBufferLength := Length(fBinaryContent);

  // Header length and actual length differs
  if not VerifyHeader(StartAddress) then
    Exit(False);

  ParseProvisionData(StartAddress + sizeof(TNDRPrivateHeader) + sizeof(TNDR_Ptr), fProvisionData);
  Result := fDJoin^.LoadFromProvisionData(fProvisionData);
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
    Result := Result + sizeof(Size);
    if Size <> Blob.cbBlob then
      raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [Blob.cbBlob, Size]);

    case blob.ulODJFormat of
      ODJ_WIN7BLOB:
        ParseWin7Blob(Result, blob.pBlob.Win7Blob^);
      OP_PACKAGE:
        ParseOpPackage(Result, blob.pBlob.OPPackage^);
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
      raise Exception.CreateFmt('Invalid PODJ_WIN7BLOB NDR Header at %x', [At - StartAddress]);

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
    Result := ParseGUID(Result, PolicyDnsDomainInfo.DomainGuid);
    Result := Result + sizeof(PolicyDnsDomainInfo.Sid);
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
    Result := ParseUint32(Result, DomainControllerInfo.dc_address_type);
    Result := ParseGUID(Result, DomainControllerInfo.domain_guid);
    Result := Result + SizeOf(TNDR_Ptr) * 2;
    Result := ParseUint32(Result, DomainControllerInfo.dc_flags);
    Result := Result + sizeof(UInt32) * 2;
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

function TDJoinParser.ParseOpPackage(At: Pointer; var OpPackage: TOP_PACKAGE;
  NDRFormat: UInt32): Pointer;
begin
  Result := At;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    if not VerifyHeader(At) then
      raise Exception.CreateFmt('Invalid POP_PACKAGE NDR Header at %x', [At - StartAddress]);

    // OP_PACKAGE is serialized as a pointer
    Result := Result + sizeof(TNDRPrivateHeader) + sizeof(TNDR_Ptr);
    Result := ParseGUID(Result, OpPackage.EncryptionType);
    Result := ParseOpBlob(Result, OpPackage.EncryptionContext, NDR_Scalar);
    Result := ParseOpBlob(Result, OpPackage.WrappedPartCollection, NDR_Scalar);
    Result := ParseUint32(Result, OpPackage.cbDecryptedPartCollection);
    Result := ParseOpBlob(Result, OpPackage.Extension, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Result := ParseOpPackagePartCollection(Result, POP_PACKAGE_PART_COLLECTION(OpPackage.WrappedPartCollection.pBlob)^);
  end;
end;

function TDJoinParser.ParseOpBlob(At: Pointer; var OpBlob: TOP_BLOB;
  NDRFormat: UInt32): Pointer;
begin
  Result := At;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Result := ParseUint32(Result, OpBlob.cbBlob);
    Result := Result + Sizeof(UInt32);
    /// TO FREE
    OpBlob.pBlob := GetMem(OpBlob.cbBlob);
    FillZero(OpBlob.pBlob^, OpBlob.cbBlob);
  end;
end;

function TDJoinParser.ParseOpPackagePartCollection(At: Pointer;
  var OpPackagePartCollection: TOP_PACKAGE_PART_COLLECTION; NDRFormat: UInt32
  ): Pointer;
var
  NbParts: UInt32;
  i: Integer;
begin
  Result := At;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    // Size of blob
    Result := Result + SizeOf(UInt32);
    if not VerifyHeader(Result) then
      raise Exception.CreateFmt('Invalid POP_PACKAGE_PART_COLLECTION NDR Header at %x', [Result - StartAddress]);
    Result := Result + Sizeof(TNDRPrivateHeader) + SizeOf(TNDR_Ptr);

    Result := ParseUint32(Result, OpPackagePartCollection.cParts);
    Result := Result + SizeOf(UInt32);
    Result := ParseOpBlob(Result, OpPackagePartCollection.Extension, NDR_Scalar);
    SetLength(OpPackagePartCollection.pParts, OpPackagePartCollection.cParts);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Result := ParseUint32(Result, NbParts);
    for i := 0 to NbParts - 1 do
      Result := ParsePackagePart(Result, OpPackagePartCollection.pParts[i], NDR_Scalar);
    for i := 0 to NbParts - 1 do
      Result := ParsePackagePart(Result, OpPackagePartCollection.pParts[i], NDR_Buffer);

    Result := Result + SizeOf(OpPackagePartCollection.Extension);
  end;
end;

function TDJoinParser.ParsePackagePart(At: Pointer;
  var OpPackagePart: TOP_PACKAGE_PART; NDRFormat: UInt32): Pointer;
begin
  Result := At;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Result := ParseGUID(Result, OpPackagePart.PartType);
    Result := ParseUint32(Result, OpPackagePart.ulFlags);
    Result := ParseOpBlob(Result, OpPackagePart.Part, NDR_Scalar);
    Result := ParseOpBlob(Result, OpPackagePart.Extension, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if IsEqualGuid(OpPackagePart.PartType, GUID_JOIN_PROVIDER) then
      Result := ParseWin7Blob(Result + SizeOf(UInt32), PODJ_WIN7BLOB(OpPackagePart.Part.pBlob)^)
    else if IsEqualGuid(OpPackagePart.PartType, GUID_JOIN_PROVIDER3) then
      Result := ParseOpJoinProv3Part(Result + SizeOf(UInt32), POP_JOINPROV3_PART(OpPackagePart.Part.pBlob)^);
  end;
end;

function TDJoinParser.ParseOpJoinProv3Part(At: Pointer;
  var OpJoinProv3Part: TOP_JOINPROV3_PART; NDRFormat: UInt32): Pointer;
begin
  Result := At;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    if not VerifyHeader(Result) then
      raise Exception.CreateFmt('Invalid POP_JOINPROV3_PART NDR Header at %x', [Result - StartAddress]);
    Result := Result + SizeOf(TNDRPrivateHeader) + SizeOf(TNDR_Ptr);
    Result := ParseUint32(Result, OpJoinProv3Part.Rid);
    Result := Result + SizeOf(TNDR_Ptr);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    Result := ParseUnicodeBuffer(Result, OpJoinProv3Part.lpSid);
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

function TDJoinParser.ParseGUID(At: Pointer; var Guid: TGuid): Pointer;
begin
  Guid := PGuid(At)^;
  Result := At + SizeOf(Guid);
end;

function TDJoinParser.ParseUint32(At: Pointer; var value: UInt32): Pointer;
begin
  value := PUInt32(At)^;
  Result := At + SizeOf(value);
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

