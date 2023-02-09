unit uDJoinTypes;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.os,
  uNDRContext;

const
  GUID_JOIN_PROVIDER : TGUID = '{631c7621-5289-4321-bc9e-80f843f868c3}';
  GUID_JOIN_PROVIDER2 : TGUID = '{57BFC56B-52F9-480C-ADCB-91B3F8A82317}';
  GUID_JOIN_PROVIDER3 : TGUID = '{FC0CCF25-7FFA-474A-8611-69FFE269645F}';
  GUID_CERT_PROVIDER : TGUID = '{9c0971e9-832f-4873-8e87-ef1419d4781e}';
  GUID_POLICY_PROVIDER : TGUID = '{68fb602a-0c09-48ce-b75f-07b7bd58f7ec}';

type
  {$A-} // every record (or object) is packed from now on

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
    dc_address_type: UInt32;
    domain_guid: TGuid;
    domain_name: WideString;
    forest_name: WideString;
    dc_flags: UInt32;
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


  { TOP_PACKAGE_PART }

  TOP_PACKAGE_PART = object
    PartType: TGUID;
    ulFlags: UInt32;
    Part: TOP_BLOB;
    Extension: TOP_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  POP_PACKAGE_PART = ^TOP_PACKAGE_PART;

  { TOP_PACKAGE_PART_COLLECTION }

  TOP_PACKAGE_PART_COLLECTION = object
    cParts: UInt32;
    pParts: array of TOP_PACKAGE_PART;
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
    pPackagePartCollection: POP_PACKAGE_PART_COLLECTION;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
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
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  PODJ_BLOB = ^TODJ_BLOB;

  { TODJ_PROVISION_DATA }

  TODJ_PROVISION_DATA = object
    Version: UInt32;
    ulcBlobs: UInt32;
    pBlobs: array of TODJ_BLOB;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;
  PODJ_PROVISION_DATA = ^TODJ_PROVISION_DATA;
  TODJ_PROVISION_DATA_ctr = specialize TNDRPointer<TODJ_PROVISION_DATA>;
  TODJ_PROVISION_DATA_serialized_ptr = specialize TNDRCustomType<TODJ_PROVISION_DATA_ctr>;


implementation

uses
  mormot.core.buffers,
  mormot.core.unicode,
  mormot.core.base;

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
  begin
    Ctx.PackWideStr(lpSid);
    Ctx.PackUInt32(0);
  end;
end;

function TOP_JOINPROV3_PART.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(Rid));
    Inc(Result, SizeOf(lpSid));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, NDRWideStrSize(lpSid));
    // Padding ?
    Inc(Result, SizeOf(UInt32));
  end;
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

procedure TOP_PACKAGE_PART.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
var
  JoinProv: TOP_JOINPROV3_PART_ctr;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackGuid(PartType);
    Ctx.PackUInt32(ulFlags);
    Part.NDRPack(Ctx, NDR_Scalar);
    Extension.NDRPack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(Part.pBlob) then
    begin
      Ctx.PackUInt32(Part.cbBlob);

      if IsEqualGuid(PartType, GUID_JOIN_PROVIDER) then
        TODJ_WIN7BLOB_serialized.NDRPack(Ctx, PODJ_WIN7BLOB(Part.pBlob)^)
      else if IsEqualGuid(PartType, GUID_JOIN_PROVIDER3) then
      begin
        JoinProv.p := POP_JOINPROV3_PART(Part.pBlob)^;
        TOP_JOINPROV3_PART_serialized_ptr.NDRPack(Ctx, JoinProv);
      end;
    end;
  end;
end;

function TOP_PACKAGE_PART.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  JoinProv: TOP_JOINPROV3_PART_ctr;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(PartType));
    Inc(Result, SizeOf(ulFlags));
    Inc(Result, Part.NDRSize(NDR_Scalar));
    Inc(Result, Extension.NDRSize(NDR_Scalar));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(Part.pBlob) then
    begin
      Inc(Result, SizeOf(Part.cbBlob));

      if IsEqualGuid(PartType, GUID_JOIN_PROVIDER) then
        Inc(Result, TODJ_WIN7BLOB_serialized.NDRSize(PODJ_WIN7BLOB(Part.pBlob)^))
      else if IsEqualGuid(PartType, GUID_JOIN_PROVIDER3) then
      begin
        JoinProv.p := POP_JOINPROV3_PART(Part.pBlob)^;
        Inc(Result, TOP_JOINPROV3_PART_serialized_ptr.NDRSize(JoinProv));
      end;
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
var
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(cParts);
    Ctx.PackPtr(Pointer(Length(pParts)));
    Extension.NDRPack(Ctx, NDR_Scalar);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Ctx.PackUInt32(cParts);
    for i := 0 to cParts - 1 do
      pParts[i].NDRPack(Ctx, NDR_Scalar);
    for i := 0 to cParts - 1 do
      pParts[i].NDRPack(Ctx, NDR_Buffer);
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
    Inc(Result, SizeOf(Pointer));
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

procedure TOP_PACKAGE_PART_COLLECTION_blob.NDRPack(Ctx: TNDRPackContext;
  NDRFormat: UInt32);
var
  OpPackagePart: TOP_PACKAGE_PART_COLLECTION_ctr;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(cbBlob);
    Ctx.PackPtr(pPackagePartCollection);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pPackagePartCollection) then
    begin
      Ctx.PackUInt32(cbBlob);
      OpPackagePart.p := pPackagePartCollection^;
      TOP_PACKAGE_PART_COLLECTION_serialized_ptr.NDRPack(Ctx, OpPackagePart);
    end;
end;

function TOP_PACKAGE_PART_COLLECTION_blob.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  OpPackagePart: TOP_PACKAGE_PART_COLLECTION_ctr;
begin
  Result := 0;
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(cbBlob));
    Inc(Result, SizeOf(pPackagePartCollection));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pPackagePartCollection) then
    begin
      Inc(Result, SizeOf(cbBlob));
      OpPackagePart.p := pPackagePartCollection^;
      Inc(Result, TOP_PACKAGE_PART_COLLECTION_serialized_ptr.NDRSize(OpPackagePart));
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
      Ctx.Pack(pBlob, cbBlob);
    end;
end;

function TOP_BLOB.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(cbBlob));
    Inc(Result, SizeOf(pBlob));
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
    Ctx.PackUInt32(0);
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
    // ??
    Inc(Result, SizeOf(UInt32));
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

procedure TDOMAIN_CONTROLLER_INFO.NDRPack(Ctx: TNDRPackContext;
  NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackPtr(Pointer(dc_unc));
    Ctx.PackPtr(Pointer(dc_address));
    Ctx.PackUInt32(dc_address_type);
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
    Inc(Result, SizeOf(dc_unc));
    Inc(Result, SizeOf(dc_address));
    Inc(Result, SizeOf(dc_address_type));
    Inc(Result, SizeOf(domain_guid));
    Inc(Result, SizeOf(domain_name));
    Inc(Result, SizeOf(forest_name));
    Inc(Result, SizeOf(dc_flags));
    Inc(Result, SizeOf(dc_site_name));
    Inc(Result, SizeOf(client_site_name));
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
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(Length));
    Inc(Result, SizeOf(MaximumLength));
    Inc(Result, SizeOf(Buffer));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, SizeOf(UInt32) * 3);
    Inc(Result, (StrLenW(PWideChar(@Buffer[1])) + 1) * 2);
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
    Ctx.Pack(@Buffer[1], (NbChars + 1) * 2);
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
    Inc(Result, SizeOf(Sid));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    Inc(Result, Name.NDRSize(NDR_Buffer));
    Inc(Result, DnsDomainName.NDRSize(NDR_Buffer));
    Inc(Result, DnsForestName.NDRSize(NDR_Buffer));
    if Assigned(Sid) then
      Inc(Result, NDRSidPtrSize(Sid))
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
    // Padding but don't know why
    Ctx.PackUInt32(0);
  end;
end;

function TODJ_WIN7BLOB.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(lpDomain));
    Inc(Result, SizeOf(lpMachineName));
    Inc(Result, SizeOf(lpMachinePassword));
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
    // Padding but don't know why
    Inc(Result, SizeOf(UInt32));
  end;
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

procedure TODJ_BLOB.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
var
  TempOpPackage: TOP_PACKAGE_ctr;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(UInt32(ulODJFormat));
    Ctx.PackUInt32(cbBlob);   /// TO COMPUTE
    Ctx.PackPtr(pBlob.RawBytes);
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob.RawBytes) then
    begin
      Ctx.PackUInt32(cbBlob);  /// TO COMPUTE
      case ulODJFormat of
        ODJ_WIN7BLOB:
          TODJ_WIN7BLOB_serialized.NDRPack(Ctx, pBlob.Win7Blob^);
        OP_PACKAGE:
          begin
            TempOpPackage.p := pBlob.OPPackage^;
            TOP_PACKAGE_serialized_ptr.NDRPack(Ctx, TempOpPackage);
          end;
      end;
    end;
end;

function TODJ_BLOB.NDRSize(NDRFormat: UInt32): SizeUInt;
var
  TempOpPackage: TOP_PACKAGE_ctr;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(ulODJFormat));
    Inc(Result, SizeOf(cbBlob));
    Inc(Result, SizeOf(pBlob.RawBytes));
  end;

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(pBlob.RawBytes) then
    begin
      Inc(Result, SizeOf(cbBlob));

      case ulODJFormat of
        ODJ_WIN7BLOB:
          Inc(Result, TODJ_WIN7BLOB_serialized.NDRSize(pBlob.Win7Blob^));
        OP_PACKAGE:
          begin
            TempOpPackage.p := pBlob.OPPackage^;
            Inc(Result, TOP_PACKAGE_serialized_ptr.NDRSize(TempOpPackage));
          end;
      end;
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
var
  i: Integer;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackUInt32(Version);
    Ctx.PackUInt32(ulcBlobs);
    Ctx.PackPtr(Pointer(Length(pBlobs)));
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
    Ctx.PackUInt32(0);
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
    Inc(Result, SizeOf(pBlobs));
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
    // Padding ?
    Inc(Result, SizeOf(UInt32));
  end;
end;

end.

