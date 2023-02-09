unit uDJoin;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.os,
  mormot.core.base,
  uDJoinTypes,
  uNDRContext;

type

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
    fMachineRid: UInt32;


    procedure FillProvision(var ProvisionData: TODJ_PROVISION_DATA);
    procedure FillWin7blob(var Win7Blob: TODJ_WIN7BLOB);
    procedure FillDnsPolicy(var DnsPolicy: TODJ_POLICY_DNS_DOMAIN_INFO);
    procedure FillDCInfo(var DCInfo: TDOMAIN_CONTROLLER_INFO);
    procedure FillOpPackagePartCollection(var OpPackagePartCollection: TOP_PACKAGE_PART_COLLECTION);
  public
    constructor Create;

    /// Load a DJoin file in memory
    // - Return true if the file has been successfully loaded
    function LoadFromFile(const Filename: TFileName): boolean;

    function LoadFromProvisionData(const ProvisionData: TODJ_PROVISION_DATA): Boolean;
    procedure SaveToFile(Filename: TFileName);

    procedure Dump;

    // Machine Informations
    property MachineDomainName: RawUtf8 read fMachineDomainName write fMachineDomainName;
    property MachineName: RawUtf8 read fMachineName write fMachineName;
    property MachinePassword: SpiUtf8 read fMachinePassword write fMachinePassword;
    property MachineRid: UInt32 read fMachineRid write fMachineRid;
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

uses
  mormot.core.buffers,
  mormot.core.unicode;

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
            MachineRid := POP_JOINPROV3_PART(Part.Part.pBlob)^.Rid;
        end;
      end;
    end;
  end;
end;

procedure TDJoin.FillProvision(var ProvisionData: TODJ_PROVISION_DATA);
begin
  ProvisionData.Version := 1;
  ProvisionData.ulcBlobs := 2;
  SetLength(ProvisionData.pBlobs, 2);

  // Win7
  ProvisionData.pBlobs[0].ulODJFormat := ODJ_WIN7BLOB;
  New(ProvisionData.pBlobs[0].pBlob.Win7Blob);
  FillWin7blob(ProvisionData.pBlobs[0].pBlob.Win7Blob^);

  // Win8
  ProvisionData.pBlobs[1].ulODJFormat := OP_PACKAGE;
  New(ProvisionData.pBlobs[1].pBlob.OPPackage);
  FillZero(ProvisionData.pBlobs[1].pBlob.OPPackage^, SizeOf(TOP_PACKAGE));
  New(ProvisionData.pBlobs[1].pBlob.OPPackage^.WrappedPartCollection.pPackagePartCollection);
  FillOpPackagePartCollection(ProvisionData.pBlobs[1].pBlob.OPPackage^.WrappedPartCollection.pPackagePartCollection^);
end;

procedure TDJoin.FillWin7blob(var Win7Blob: TODJ_WIN7BLOB);
begin
  Win7Blob.lpDomain := Utf8ToWideString(MachineDomainName);
  Win7Blob.lpMachineName := Utf8ToWideString(MachineName);
  Win7Blob.lpMachinePassword := Utf8ToWideString(MachinePassword);
  FillDnsPolicy(Win7Blob.DnsDomainInfo);
  FillDCInfo(Win7Blob.DcInfo);
  Win7Blob.Options := Options;
end;

procedure TDJoin.FillDnsPolicy(var DnsPolicy: TODJ_POLICY_DNS_DOMAIN_INFO);
begin
  DnsPolicy.Name.Buffer := Utf8ToWideString(PolicyDomainName);
  DnsPolicy.DnsDomainName.Buffer := Utf8ToWideString(DnsDomainName);
  DnsPolicy.DnsForestName.Buffer := Utf8ToWideString(DnsForestName);
  DnsPolicy.DomainGuid := DomainGUID;
  DnsPolicy.Sid := @DomainSID;
end;

procedure TDJoin.FillDCInfo(var DCInfo: TDOMAIN_CONTROLLER_INFO);
begin
  DCInfo.dc_unc := Utf8ToWideString(DCName);
  DCInfo.dc_address := Utf8ToWideString(DCAddress);
  DCInfo.dc_address_type := DCAddressType;
  DCInfo.domain_guid := DomainGUID;
  DCInfo.domain_name := Utf8ToWideString(DnsDomainName);
  DCInfo.forest_name := Utf8ToWideString(DnsForestName);
  DCInfo.dc_flags := DCFlags;
  DCInfo.dc_site_name := Utf8ToWideString(DCSiteName);
  DCInfo.client_site_name := Utf8ToWideString(DCClientSiteName);
end;

procedure TDJoin.FillOpPackagePartCollection(
  var OpPackagePartCollection: TOP_PACKAGE_PART_COLLECTION);
var
  JoinPart: POP_JOINPROV3_PART;
begin
  OpPackagePartCollection.cParts := 2;
  SetLength(OpPackagePartCollection.pParts, 2);

  OpPackagePartCollection.pParts[0].PartType := GUID_JOIN_PROVIDER;
  OpPackagePartCollection.pParts[0].ulFlags := 1; // ?
  New(PODJ_WIN7BLOB(OpPackagePartCollection.pParts[0].Part.pBlob));
  FillWin7blob(PODJ_WIN7BLOB(OpPackagePartCollection.pParts[0].Part.pBlob)^);

  OpPackagePartCollection.pParts[1].PartType := GUID_JOIN_PROVIDER3;
  OpPackagePartCollection.pParts[1].ulFlags := 0; // ?
  New(POP_JOINPROV3_PART(OpPackagePartCollection.pParts[1].Part.pBlob));
  JoinPart := POP_JOINPROV3_PART(OpPackagePartCollection.pParts[1].Part.pBlob);
  JoinPart^.Rid := MachineRid;
  JoinPart^.lpSid := Utf8ToWideString(SidToText(@DomainSID) + '-' + IntToStr(MachineRid));
end;

procedure TDJoin.SaveToFile(Filename: TFileName);
var
  Provision: TODJ_PROVISION_DATA_ctr;
  Ctx: TNDRPackContext;
begin
  FillProvision(Provision.p);

  Ctx := TNDRPackContext.Create;
  TODJ_PROVISION_DATA_serialized_ptr.NDRPack(Ctx, Provision);
  FileFromString(Ctx.Buffer, Filename);
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
  WriteLn(' - Rid: ', MachineRid);
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
  FileFromString(Binary, 'C:\temp\in.bin');
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

