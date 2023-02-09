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

  { TNDRContext }

  TNDRContext = class
  protected
    Buffer: RawByteString;
    BufferLength: SizeInt;
    Current: SizeInt;
  public
    constructor Create(Buf: RawByteString; BufLen: SizeInt);

    function StartPtr: Pointer;
    function CurrentPtr: Pointer;
  end;

  { TNDRUnpackContext }

  TNDRUnpackContext = class(TNDRContext)
  public
    constructor Create(Buf: RawByteString; BufLen: SizeInt);

    function Unpack(Size: SizeInt): Pointer;
    procedure UnpackAlign(Size: SizeInt);
    function UnpackHeader: TNDRPrivateHeader;
    function UnpackUInt32: UInt32;
    function UnpackUInt16: UInt16;
    function UnpackPtr: Pointer;
    function UnpackGuid: TGuid;
    function UnpackSidPtr: PSid;
    function UnpackWideStr: WideString;
  end;
  PNDR_Context = ^TNDRUnpackContext;

  { TNDRPackContext }

  TNDRPackContext = class(TNDRContext)
  private
    PointerCount: SizeInt;
  public
    constructor Create;

    procedure Pack(Content: Pointer; Len: SizeInt);
    procedure PackHeader(Size: SizeInt);
    procedure PackByte(Value: Byte);
    procedure PackUInt32(Value: UInt32);
    procedure PackPtr(Value: Pointer);
  end;

  { TNDRCustomType }

  generic TNDRCustomType<NDRType> = class
    class procedure NDRUnpack(Ctx: TNDRUnpackContext; var Data: NDRType; NDRFormat: UInt32 = NDR_ScalarBuffer);
    class procedure NDRPack(Ctx: TNDRPackContext; var Data: NDRType; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;

  { TNDRPointer }

  generic TNDRPointer<NDRType> = object
    p: NDRType;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;

  { TODJ_UNICODE_STRING }

  TODJ_UNICODE_STRING = object
    Length: UInt16;
    MaximumLength: UInt16;
    Buffer: WideString;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  PODJ_UNICODE_STRING = ^TODJ_UNICODE_STRING;

  { TOP_BLOB }

  TOP_BLOB = object
    cbBlob: UInt32;
    pBlob: PByte;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  POP_BLOB = ^TOP_BLOB;

  { TODJ_POLICY_DNS_DOMAIN_INFO }

  TODJ_POLICY_DNS_DOMAIN_INFO = object
    Name: TODJ_UNICODE_STRING;
    DnsDomainName: TODJ_UNICODE_STRING;
    DnsForestName: TODJ_UNICODE_STRING;
    DomainGuid: TGuid;
    Sid: PSid;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  PODJ_POLICY_DNS_DOMAIN_INFO = ^TODJ_POLICY_DNS_DOMAIN_INFO;

  { TDOMAIN_CONTROLLER_INFO }

  TDOMAIN_CONTROLLER_INFO = object
    dc_unc: WideString;
    dc_address: WideString;
    dc_address_type: UInt32;
    domain_guid: TGuid;
    domain_name: WideString;
    forest_name: WideString;
    dc_flags: UInt32;
    dc_site_name: WideString;
    client_site_name: WideString;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
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
  end;
  PODJ_WIN7BLOB = ^TODJ_WIN7BLOB;
  TODJ_WIN7BLOB_serialized = specialize TNDRCustomType<TODJ_WIN7BLOB>;

  { TOP_JOINPROV3_PART }

  TOP_JOINPROV3_PART = object
    Rid: UInt32;
    lpSid: WideString;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  POP_JOINPROV3_PART = ^TOP_JOINPROV3_PART;
  TOP_JOINPROV3_PART_ctr = specialize TNDRPointer<TOP_JOINPROV3_PART>;
  TOP_JOINPROV3_PART_serialized_ptr = specialize TNDRCustomType<TOP_JOINPROV3_PART_ctr>;


  { TOP_PACKAGE_PART }

  TOP_PACKAGE_PART = object
    PartType: TGUID;
    ulFlags: UInt32;
    Part: TOP_BLOB;
    Extension: TOP_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  POP_PACKAGE_PART = ^TOP_PACKAGE_PART;

  { TOP_PACKAGE_PART_COLLECTION }

  TOP_PACKAGE_PART_COLLECTION = object
    cParts: UInt32;
    pParts: array of TOP_PACKAGE_PART;
    Extension: TOP_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  POP_PACKAGE_PART_COLLECTION = ^TOP_PACKAGE_PART_COLLECTION;
  TOP_PACKAGE_PART_COLLECTION_ctr = specialize TNDRPointer<TOP_PACKAGE_PART_COLLECTION>;
  TOP_PACKAGE_PART_COLLECTION_serialized_ptr = specialize TNDRCustomType<TOP_PACKAGE_PART_COLLECTION_ctr>;

  { TOP_PACKAGE_PART_COLLECTION_blob }

  TOP_PACKAGE_PART_COLLECTION_blob = object
    cbBlob: UInt32;
    pPackagePartCollection: POP_PACKAGE_PART_COLLECTION;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
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
  end;
  POP_PACKAGE = ^TOP_PACKAGE;
  TOP_PACKAGE_ctr = specialize TNDRPointer<TOP_PACKAGE>;
  TOP_PACKAGE_serialized_ptr = specialize TNDRCustomType<TOP_PACKAGE_ctr>;

  TODJ_BLOB_buffer_u = record
    case UInt32 of
      1: (Win7Blob: PODJ_WIN7BLOB);
      2: (OPPackage: POP_PACKAGE);
      3: (RawBytes: PByte);
  end;
  PODJ_BLOB_buffer_u = ^TODJ_BLOB_buffer_u;

  { TODJ_BLOB }

  TODJ_BLOB = object
    ulODJFormat: TODJ_Format;
    cbBlob: UInt32;
    pBlob: TODJ_BLOB_buffer_u;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  PODJ_BLOB = ^TODJ_BLOB;

  { TODJ_PROVISION_DATA }

  TODJ_PROVISION_DATA = object
    Version: UInt32;
    ulcBlobs: UInt32;
    pBlobs: array of TODJ_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;
  PODJ_PROVISION_DATA = ^TODJ_PROVISION_DATA;
  TODJ_PROVISION_DATA_ctr = specialize TNDRPointer<TODJ_PROVISION_DATA>;
  TODJ_PROVISION_DATA_serialized_ptr = specialize TNDRCustomType<TODJ_PROVISION_DATA_ctr>;

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
  public

    class function ParseFile(FileName: TFileName; out DJoin: TDJoin): Boolean;
    class function ParseFileContent(FileContent: RawByteString; out DJoin: TDJoin): Boolean;
    class function ParseBinary(Binary: RawByteString; out DJoin: TDJoin): Boolean;
  end;



implementation

const
  EXPECTED_COMMON_HEADER : UInt64 = $cccccccc00081001;
  COMMON_HEADER_FILLER : UInt32 = $CCCCCCCC;
  PRIVATE_HEADER_FILLER: UInt32 = 0;

  GUID_JOIN_PROVIDER : TGUID = '{631c7621-5289-4321-bc9e-80f843f868c3}';
  GUID_JOIN_PROVIDER2 : TGUID = '{57BFC56B-52F9-480C-ADCB-91B3F8A82317}';
  GUID_JOIN_PROVIDER3 : TGUID = '{FC0CCF25-7FFA-474A-8611-69FFE269645F}';
  GUID_CERT_PROVIDER : TGUID = '{9c0971e9-832f-4873-8e87-ef1419d4781e}';
  GUID_POLICY_PROVIDER : TGUID = '{68fb602a-0c09-48ce-b75f-07b7bd58f7ec}';

{ TNDRContext }

constructor TNDRContext.Create(Buf: RawByteString; BufLen: SizeInt);
begin
  Buffer := Buf;
  BufferLength := BufLen;
  Current := 0;
end;

function TNDRContext.StartPtr: Pointer;
begin
  Result := @Buffer[1];
end;

function TNDRContext.CurrentPtr: Pointer;
begin
  Result := StartPtr + Current;
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

end;

{ TOP_PACKAGE_PART }

procedure TOP_PACKAGE_PART.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  Size: UInt32;
  JoinProv: TOP_JOINPROV3_PART_ctr;
  PreviousOffset: SizeInt;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    PartType := Ctx.UnpackGuid;
    ulFlags := Ctx.UnpackUInt32;
    Part.NDRUnpack(Ctx, NDR_Scalar);
    Extension.NDRUnpack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(Part.pBlob) then
    begin
      Size := Ctx.UnpackUInt32;
      PreviousOffset := Ctx.Current;
      if Size <> Part.cbBlob then
        raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [Part.cbBlob, Size]);
      // Allocate Memory -> TO FREE
      part.pBlob := GetMem(Size);
      FillZero(part.pBlob^, Size);

      if IsEqualGuid(PartType, GUID_JOIN_PROVIDER) then
        TODJ_WIN7BLOB_serialized.NDRUnpack(Ctx, PODJ_WIN7BLOB(Part.pBlob)^)
      else if IsEqualGuid(PartType, GUID_JOIN_PROVIDER3) then
      begin
        TOP_JOINPROV3_PART_serialized_ptr.NDRUnpack(Ctx, JoinProv);
        POP_JOINPROV3_PART(Part.pBlob)^ := JoinProv.p;
      end;
      Ctx.Current := PreviousOffset + Size;
    end;
  end;
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
    //pParts
    Ctx.UnpackPtr;
    Extension.NDRUnpack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    NbParts := Ctx.UnpackUInt32;
    SetLength(pParts, NbParts);
    for i := 0 to NbParts - 1 do
      pParts[i].NDRUnpack(Ctx, NDR_Scalar);
    for i := 0 to NbParts - 1 do
      pParts[i].NDRUnpack(Ctx, NDR_Buffer);
    // Extension
    Ctx.Unpack(8);
  end;
end;

procedure TOP_PACKAGE_PART_COLLECTION.NDRPack(Ctx: TNDRPackContext;
  NDRFormat: UInt32);
begin

end;

{ TOP_PACKAGE_PART_COLLECTION_blob }

procedure TOP_PACKAGE_PART_COLLECTION_blob.NDRUnpack(Ctx: TNDRUnpackContext;
  NDRFormat: UInt32);
var
  OpPackagePart: TOP_PACKAGE_PART_COLLECTION_ctr;
  Size: UInt32;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    cbBlob := Ctx.UnpackUInt32;
    pPackagePartCollection := Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pPackagePartCollection) then
    begin
      Size := Ctx.UnpackUInt32;
      if Size <> cbBlob then
        raise Exception.CreateFmt('Expected blob size and actual size differs: %d - %d', [cbBlob, Size]);
      // Allocate Memory -> TO FREE
      pPackagePartCollection := GetMem(SizeOf(TOP_PACKAGE_PART_COLLECTION));
      FillZero(pPackagePartCollection^, SizeOf(TOP_PACKAGE_PART_COLLECTION));

      TOP_PACKAGE_PART_COLLECTION_serialized_ptr.NDRUnpack(Ctx, OpPackagePart);
      pPackagePartCollection^ := OpPackagePart.p;
    end;
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
      // Allocate Memory -> TO FREE
      pBlob := GetMem(Size);
      FillZero(pBlob^, Size);
      Move(PByte(Ctx.Unpack(Size))^, pBlob, Size);
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
    dc_address_type := Ctx.UnpackUInt32;
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

{ TODJ_UNICODE_STRING }

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

{ TNDRPointer }

procedure TNDRPointer.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    if Assigned(Ctx.UnpackPtr) then
      p.NDRUnpack(Ctx, NDR_ScalarBuffer);
  end;
end;

procedure TNDRPointer.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackPtr(@p);
    p.NDRPack(Ctx, NDR_ScalarBuffer);
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

end;

{ TODJ_BLOB }

procedure TODJ_BLOB.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
var
  Size: UInt32;
  TempOpPackage: TOP_PACKAGE_ctr;
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
      // Allocate Memory -> TO FREE
      pBlob.RawBytes := GetMem(Size);
      FillZero(pBlob.RawBytes^, Size);

      case ulODJFormat of
        ODJ_WIN7BLOB:
          TODJ_WIN7BLOB_serialized.NDRUnpack(Ctx, pBlob.Win7Blob^);
        OP_PACKAGE:
          begin
            TOP_PACKAGE_serialized_ptr.NDRUnpack(Ctx, TempOpPackage);
            pBlob.OPPackage^ := TempOpPackage.p;
          end;
      end;
      Ctx.Current := PreviousOffset + Size;
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
    // Do nothing with this
    Ctx.UnpackPtr;
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    NbBlobs := Ctx.UnpackUInt32;
    SetLength(pBlobs, NbBlobs);

    // Scalar Part
    for i := 0 to NbBlobs - 1 do
      pBlobs[i].NDRUnpack(Ctx, NDR_Scalar);

    // Buffer Part
    for i := 0 to NbBlobs - 1 do
      pBlobs[i].NDRUnpack(Ctx, NDR_Buffer);
  end;
end;

procedure TODJ_PROVISION_DATA.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(Version);
    Ctx.PackUInt32(ulcBlobs);
    Ctx.PackPtr(Pointer(Length(pBlobs)));
  end;
end;

{ TNDRUnpackContext }

constructor TNDRUnpackContext.Create(Buf: RawByteString; BufLen: SizeInt);
begin
  inherited Create(Buf, BufLen);
end;

function TNDRUnpackContext.UnpackHeader: TNDRPrivateHeader;
var
  Header: PNDRPrivateHeader;
  Valid: Boolean;
begin
  Result := PNDRPrivateHeader(Unpack(SizeOf(Result)))^;
  if not  ((Result.CommonHeader.Header = EXPECTED_COMMON_HEADER) and
           (Result.PrivateHeader.ObjectBufferLength <= BufferLength - sizeof(Result)) and
           (Result.PrivateHeader.Filler = PRIVATE_HEADER_FILLER)) then
    raise Exception.CreateFmt('Invalid Custom NDR Header at 0x%x', [Current - SizeOf(Result)]);
end;

function TNDRUnpackContext.Unpack(Size: SizeInt): Pointer;
begin
  Result := CurrentPtr;
  Inc(Current, Size);
  if Current > BufferLength then
    raise Exception.Create('NDR context out of bounds');
end;

constructor TNDRPackContext.Create;
begin
  inherited Create('', 0);
end;

procedure TNDRPackContext.Pack(Content: Pointer; Len: SizeInt);
begin
  AppendBufferToRawByteString(Buffer, Content^, Len);
  Inc(BufferLength, Len);
end;

procedure TNDRPackContext.PackHeader(Size: SizeInt);
var
  Header: TNDRPrivateHeader;
begin
  Header.CommonHeader.Version := 1;
  Header.CommonHeader.Endianness := $10;
  Header.CommonHeader.Length := 8;
  Header.CommonHeader.Filler := COMMON_HEADER_FILLER;

  Header.PrivateHeader.ObjectBufferLength := Size;
  Header.PrivateHeader.Filler := PRIVATE_HEADER_FILLER;
  Pack(@Header, SizeOf(Header));
end;

procedure TNDRPackContext.PackByte(Value: Byte);
begin
  Pack(@Value, SizeOf(Value));
end;

procedure TNDRUnpackContext.UnpackAlign(Size: SizeInt);
begin
  Current := (Current + Size - 1) and (not (Size - 1));
end;

function TNDRUnpackContext.UnpackUInt32: UInt32;
begin
  Result := PUInt32(Unpack(SizeOf(UInt32)))^;
end;

function TNDRUnpackContext.UnpackUInt16: UInt16;
begin
 Result := PUInt16(Unpack(SizeOf(UInt16)))^;
end;

function TNDRUnpackContext.UnpackPtr: Pointer;
begin
  Result := Pointer(UnpackUInt32);
end;

function TNDRUnpackContext.UnpackGuid: TGuid;
begin
  Result := PGuid(Unpack(SizeOf(TGuid)))^;
end;

function TNDRUnpackContext.UnpackSidPtr: PSid;
var
  NbAuth, Len: UInt32;
begin
  NbAuth := UnpackUInt32;
  Len := 8 + Sizeof(UInt32) * NbAuth;
  /// TO FREE
  Result := GetMem(Len);
  Move(PSid(Unpack(Len))^, Result^, Len);
end;

function TNDRUnpackContext.UnpackWideStr: WideString;
var
  Len: UInt32;
begin
  // Length
  UnpackUInt32;
  // Always 0
  UnpackUInt32;
  // MaxLength
  Len := UnpackUInt32;
  Len := Len + (Len mod 2);

  SetLength(Result, Len);
  Move(PWideChar(Unpack(Len * 2))^, Result[1], Len * 2);
end;

procedure TNDRPackContext.PackUInt32(Value: UInt32);
begin
  Pack(@Value, SizeOf(Value));
end;

procedure TNDRPackContext.PackPtr(Value: Pointer);
var
  PtrVal: UInt32;
begin
  PtrVal := 0;
  if Assigned(Value) then
  begin
    PtrVal := (PointerCount * 4) or $00020000;
    Inc(PointerCount);
  end;
  PackUInt32(PtrVal);
end;

{ TNDRCustomType }

class procedure TNDRCustomType.NDRUnpack(Ctx: TNDRUnpackContext;
  var Data: NDRType; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.UnpackHeader;
    // Object pointer
    Data.NDRUnpack(Ctx, NDR_ScalarBuffer);
  end;
end;

class procedure TNDRCustomType.NDRPack(Ctx: TNDRPackContext; var Data: NDRType;
  NDRFormat: UInt32);
var
  PreviousOffset: SizeInt;
  SubCtx: TNDRPackContext;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    PreviousOffset := Ctx.Current;
    SubCtx := TNDRPackContext.Create;
    try
      Data.NDRPack(SubCtx, NDR_ScalarBuffer);
      Ctx.PackHeader(SubCtx.BufferLength);
      Ctx.Pack(SubCtx.StartPtr, SubCtx.BufferLength);
    finally
      SubCtx.Free;
    end;
  end;
end;


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
        PackageParts := OpPackage^.WrappedPartCollection.pPackagePartCollection;
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

class function TDJoinParser.ParseBinary(Binary: RawByteString; out DJoin: TDJoin
  ): Boolean;
var
  NdrCtx: TNDRUnpackContext;
  OutCtx: TNDRPackContext;
  ProvData: TODJ_PROVISION_DATA_ctr;
begin
  NdrCtx := TNDRUnpackContext.Create(Binary, Length(Binary));
  TODJ_PROVISION_DATA_serialized_ptr.NDRUnpack(NdrCtx, ProvData);

  OutCtx :=  TNDRPackContext.Create;
  TODJ_PROVISION_DATA_serialized_ptr.NDRPack(OutCtx, ProvData);
  FileFromString(OutCtx.Buffer, 'C:\temp\out.bin');

  Result := DJoin.LoadFromProvisionData(ProvData.p);
end;

class function TDJoinParser.ParseFile(FileName: TFileName; out DJoin: TDJoin
  ): Boolean;
begin
  Result := ParseFileContent(StringFromFile(Filename), DJoin);
end;

class function TDJoinParser.ParseFileContent(FileContent: RawByteString; out
  DJoin: TDJoin): Boolean;
var
  Base64: RawUtf8;
  Binary: RawByteString;
begin
  Base64 := RawUnicodeToUtf8(pointer(FileContent), Length(WideString(FileContent)) div 2 - 1);
  Binary := Base64toBin(Base64);

  // Not base64 encoded
  if Binary = '' then
    Exit(False);

  Result := ParseBinary(Binary, DJoin);
end;

end.

