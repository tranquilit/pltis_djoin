/// This unit is a part of the Open Source Tranquil IT DJoin,
// licensed under a MPL/GPL/LGPL three license - see LICENSE.md

unit uDJoin;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.os,
  mormot.core.base,
  mormot.net.ldap,
  uDJoinTypes,
  uNDRContext,
  uLdapUtils;

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
    fNetbiosDomainName: RawUtf8;
    fDnsDomainName: RawUtf8;
    fDnsForestName: RawUtf8;
    fDomainGUID: TGuid;
    fDomainSID: TSid;
    // Domain Informations
    fDCName: RawUtf8;
    fDCAddress: RawUtf8;
    fDCAddressType: TDS_AddressType;
    fDCFlags: UInt32;
    fDCSiteName: RawUtf8;
    fDCClientSiteName: RawUtf8;

    // OP_PACKAGE
    fMachineRid: UInt32;

    // OP_POLICY_PART
    fGroupPolicies: TGroupPolicies;

    procedure FillProvision(MemCtx: PMemoryContext; var ProvisionData: TODJ_PROVISION_DATA);
    procedure FillWin7blob(var Win7Blob: TODJ_WIN7BLOB);
    procedure FillDnsPolicy(var DnsPolicy: TODJ_POLICY_DNS_DOMAIN_INFO);
    procedure FillDCInfo(var DCInfo: TDOMAIN_CONTROLLER_INFO);
    procedure FillOpPackagePartCollection(MemCtx: PMemoryContext; var OpPackagePartCollection: TOP_PACKAGE_PART_COLLECTION);
    procedure FillPolicyPart(MemCtx: PMemoryContext; var PolicyPart: TOP_POLICY_PART);
    procedure LoadPolicyProvider(Provider: POP_POLICY_PART);
  public
    constructor Create;

    /// Load a DJoin file in memory
    // - Return true if the file has been successfully loaded
    function LoadFromFile(const Filename: TFileName; Unicode: Boolean = True): boolean;
    function LoadFromFileContent(const FileContent: RawByteString; Unicode: Boolean = True): Boolean;
    function LoadFromBinary(const content: RawByteString): Boolean;
    function LoadFromLDAP(ldap: TLdapClient; ComputerName, DN: RawUtf8; Password: SpiUtf8; DomainController: RawUtf8 = ''; Address: RawUtf8 = '';
      HostActionIfExists: TActionIfExists = aieFail): Boolean;

    // Group policies
    function AddGroupPolicyFromGPT(Name: RawUtf8; GPT: RawUtf8): Integer;
    function AddGroupPolicyFromRegistryFile(Name: RawUtf8; const content: RawByteString): Integer;
    function AddGroupPoliciesFromLdap(Ldap: TLdapClient; DisplayName: RawUtf8 = ''; Guid: RawUtf8 = ''): Integer;

    function LoadFromProvisionData(const ProvisionData: TODJ_PROVISION_DATA): Boolean;
    procedure SaveToFile(Filename: TFileName; EncodeUtf16: Boolean = True);
    function GetBlob(EncodeUtf16: Boolean = True): RawByteString;


    function Dump(DumpGpoRegistryValues: Boolean = False): RawUtf8;
    procedure DumpToConsole;

    // Machine Informations
    property MachineDomainName: RawUtf8 read fMachineDomainName write fMachineDomainName;
    property MachineName: RawUtf8 read fMachineName write fMachineName;
    property MachinePassword: SpiUtf8 read fMachinePassword write fMachinePassword;
    property MachineRid: UInt32 read fMachineRid write fMachineRid;
    property Options: UInt32 read fOptions write fOptions;
    // Policy DNS Domain
    property NetbiosDomainName: RawUtf8 read fNetbiosDomainName write fNetbiosDomainName;
    property DnsDomainName: RawUtf8 read fDnsDomainName write fDnsDomainName;
    property DnsForestName: RawUtf8 read fDnsForestName write fDnsForestName;
    property DomainGUID: TGuid read fDomainGUID write fDomainGUID;
    property DomainSID: TSid read fDomainSID write fDomainSID;
    // Domain Informations
    property DCName: RawUtf8 read fDCName write fDCName;
    property DCAddress: RawUtf8 read fDCAddress write fDCAddress;
    property DCAddressType: TDS_AddressType read fDCAddressType write fDCAddressType;
    property DCFlags: UInt32 read fDCFlags write fDCFlags;
    property DCSiteName: RawUtf8 read fDCSiteName write fDCSiteName;
    property DCClientSiteName: RawUtf8 read fDCClientSiteName write fDCClientSiteName;
    // Group policies embedded
    property GroupPolicies: TGroupPolicies read fGroupPolicies write fGroupPolicies;
  end;
  PDJoin = ^TDJoin;

  { TDJoinParser }

  TDJoinParser = class
  public
    class function ParseFile(FileName: TFileName; var DJoin: TDJoin; Unicode: Boolean = True): Boolean;
    class function ParseFileContent(FileContent: RawByteString; var DJoin: TDJoin; Unicode: Boolean = True): Boolean;
    class function ParseBinary(Binary: RawByteString; var DJoin: TDJoin): Boolean;
  end;

implementation

uses
  mormot.core.buffers,
  mormot.core.unicode,
  mormot.core.text,
  mormot.net.dns;

{ TDJoin }

constructor TDJoin.Create;
begin

end;

function TDJoin.LoadFromFile(const Filename: TFileName; Unicode: Boolean
  ): boolean;
begin
  Result := TDJoinParser.ParseFile(Filename, Self, Unicode);
end;

function TDJoin.LoadFromFileContent(const FileContent: RawByteString;
  Unicode: Boolean): Boolean;
begin
  Result := TDJoinParser.ParseFileContent(FileContent, Self , Unicode);
end;

function TDJoin.LoadFromBinary(const content: RawByteString): Boolean;
begin
  Result := TDJoinParser.ParseBinary(content, Self);
end;

function TDJoin.LoadFromLDAP(ldap: TLdapClient; ComputerName,
  DN: RawUtf8; Password: SpiUtf8; DomainController: RawUtf8; Address: RawUtf8;
  HostActionIfExists: TActionIfExists): Boolean;
var
  ComputerDN, Addr, DC, Netbios, DCReference, SiteName, SidStr,
    DomainCN, ForestCN, ErrMsg: RawUtf8;
  ComputerObject, DCObject, DNObject: TLdapResult;
  Sid: TSid;
  Rid: Cardinal;
  DomGuid: TGuid;
begin
  if DN = '' then
    DN := Ldap.WellKnownObjects^.Computers;
  ComputerDN := FormatUtf8('CN=%,%', [ComputerName, DN]);

  DomainCN := DNToCN(ldap.DefaultDN);
  ForestCN := DNToCN(ldap.RootDN); // Only works with two levels of subdomains
  Netbios := ldap.NetbiosDN;
  if Address = '' then
    Addr := FormatUtf8('\\%', [DnsLookup(ldap.Settings.TargetHost)])
  else
    Addr := FormatUtf8('\\%', [Address]);

  if PrepareComputerEntry(ldap, ComputerName, DN, ErrMsg, Password, HostActionIfExists) <> ccrSuccess then
    raise Exception.Create('Unable to prepare computer entry in the ldap server');

  // Computer Object
  ComputerObject := ldap.SearchFirst(ComputerDN, '', []);
  if not (Assigned(ComputerObject) and ComputerObject.CopyObjectSid(SidStr) and TextToSid(PUtf8Char(@SidStr[1]), Sid)) then
    raise Exception.Create('Unable to retreive computer SID');
    // Create computer if not existing
  Rid := sid.SubAuthority[sid.SubAuthorityCount - 1];
  Dec(sid.SubAuthorityCount);

  // DC Object (take first DC if none supplied)
  if DomainController = '' then
    DCObject := ldap.SearchFirst(ldap.DefaultDN, '(primaryGroupID=516)', [])
  else
    DCObject := ldap.SearchFirst(ldap.WellKnownObjects()^.DomainControllers, FormatUtf8('(dNSHostName=%)', [DomainController]), ['dNSHostName', 'serverReferenceBL']);
  if not Assigned(DCObject) then
     raise Exception.Create('Unable to retreive Domain Controller object');
  DC := FormatUtf8('\\%', [DCObject.Attributes.Find('dNSHostName').GetReadable]);
  DCReference := DCObject.Attributes.Find('serverReferenceBL').GetReadable;
  SiteName := String(DNToCN(DCReference)).Split('/')[3];

  // Base Dn Object
  DNObject := ldap.SearchFirst(ldap.DefaultDN, FormatUtf8('(distinguishedName=%)', [ldap.DefaultDN]), []);
  if not Assigned(DNObject) or not DNObject.CopyObjectGUID(DomGuid) then
     raise Exception.Create('Unable to retreive Domain object');


  // Assign values
  MachineDomainName := DomainCN;
  MachineName := ComputerName;
  MachinePassword := Password;
  MachineRid := Rid;
  Options := 0;

  NetbiosDomainName := Netbios;
  DnsDomainName := DomainCN;
  DnsForestName := ForestCN;
  DomainGUID := DomGUID;
  DomainSID := sid;

  DCName := DC;
  DCAddress := Addr;
  DCAddressType := DS_INET_ADDRESS;
  DCFlags := $E00013FD; // Should be computed
  DCSiteName := SiteName;
  DCClientSiteName := SiteName;
  Result := True;
end;

function TDJoin.AddGroupPoliciesFromLdap(Ldap: TLdapClient; DisplayName: RawUtf8; Guid: RawUtf8): Integer;
var
  Filter: RawUtf8;
  Policy: TLdapResult;
begin
  Result := -1;
  if not ldap.Connected then
    Exit;
  Filter := '';// '(objectClass=groupPolicyContainer)';
  if (DisplayName <> '*') and (DisplayName <> '') then
     Filter := Format('(displayName=%s)', [DisplayName]);
  // TODO: Check if GUID is valid
  if (Guid <> '*') and (Guid <> '') then
     Filter := Format('%s(cn=%s)', [Filter, Guid]);
  if Filter <> '' then
     Filter := Format('(&(objectClass=groupPolicyContainer)%s)', [Filter])
  else
     Filter := '(objectClass=groupPolicyContainer)';

  if not ldap.Search(ldap.DefaultDN, False, Filter, ['displayName', 'cn', 'gPCFileSysPath']) then
    Exit;
  Result := 0;
  for Policy in ldap.SearchResult.Items  do
    if AddGroupPolicyFromGPT(Policy.Attributes.Find('displayName').GetReadable, Policy.Attributes.Find('gPCFileSysPath').GetReadable) <> -1 then
      Inc(Result);
end;

function TDJoin.AddGroupPolicyFromGPT(Name: RawUtf8; GPT: RawUtf8): Integer;
var
  RegistryFile: TFileName;
begin
  Result := -1;
  RegistryFile := MakePath([GPT, 'Machine', 'Registry.pol']);
  if Executable.Command.Option(['v', 'verbose']) then
    WriteLn('Add GPO "', Name, '" from GPT "', GPT, '"');
  if not FileExists(RegistryFile) then
  begin
    WriteLn('Cannot access registry file "', RegistryFile, '", GPO skipped');
    Exit;
  end;
  Result := AddGroupPolicyFromRegistryFile(Name, StringFromFile(RegistryFile));
end;

function TDJoin.AddGroupPolicyFromRegistryFile(Name: RawUtf8; const content: RawByteString): Integer;
const
  REGFILE_SIGNATURE = 'PReg'#1#0#0#0;
var
  Policy: TGroupPolicy;
  RegValue: TRegistryValue;
  Idx: Integer;

  function _PrepareRead(Delimiter: RawUtf8 = ';'#0): Integer;
  begin
    Result := -1;
    if (content[Idx] = ';') or (content[Idx] = '[') then
      Inc(Idx, 2);
    if content[Idx] = ']' then
      Exit;
    Result := Pos(Delimiter, content, Idx);
  end;

  function ReadWideString(Delimiter: RawUtf8 = ';'#0): RawUtf8;
  var
    EndOfPart: SizeInt;
  begin
    Result := '';
    EndOfPart := _PrepareRead(Delimiter);
    if EndOfPart = -1 then
      Exit;
    Result := RawUnicodeToUtf8(@content[Idx], (EndOfPart - Idx) div 2);
    Idx := EndOfPart;
  end;

  function ReadBuffer(BufferSize: SizeInt; var Buffer; Delimiter: RawUtf8 = ';'#0): Boolean;
  var
    EndOfPart: SizeInt;
  begin
    Result := False;
    EndOfPart := _PrepareRead(Delimiter);
    if (EndOfPart = -1) or (EndOfPart - Idx <> BufferSize) then
      Exit;
    Move(content[Idx], Buffer, BufferSize);
    Result := True;
    Idx := EndOfPart;
  end;

begin
  Result := -1;
  if content = '' then
    Exit;
  if (Length(content) < Length(REGFILE_SIGNATURE)) or
     (not CompareMem(@content[1], @REGFILE_SIGNATURE[1], Length(REGFILE_SIGNATURE))) then
    Exit;
  Idx := 1 + Length(REGFILE_SIGNATURE);
  while Idx < Length(content) do
  begin
    // Format  [key;value;type;size;data] in utf16
    if content[Idx] <> '[' then
    begin
      WriteLn('Expected opening [ at ', Idx);
      Exit;
    end;
    // Key
    RegValue.Key := ReadWideString;
    RegValue.ValueName := ReadWideString;

    if not (ReadBuffer(SizeOf(RegValue.ValueType), RegValue.ValueType) and
      ReadBuffer(SizeOf(RegValue.ValueSize), RegValue.ValueSize)) then
      continue;
    begin
      SetLength(RegValue.Value, RegValue.ValueSize);
      ReadBuffer(RegValue.ValueSize, RegValue.Value[1], ']'#0);
    end;

    if content[Idx] <> ']' then
    begin
      WriteLn('Expected closing ] at ', Idx);
      Exit;
    end;
    Inc(Idx, 2);

    SetLength(Policy.Values, Length(Policy.Values) + 1);
    Policy.Values[Length(Policy.Values) - 1] := RegValue;
  end;
  Result := Length(GroupPolicies);
  SetLength(fGroupPolicies, Result + 1);
  Policy.Name := Name;
  GroupPolicies[Result] := Policy;
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
        NetbiosDomainName := WideStringToUtf8(Win7^.DnsDomainInfo.Name.Buffer);
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
        OpPackage := Blob.pBlob.OPPackage.p;
        PackageParts := OpPackage^.WrappedPartCollection.pPackagePartCollection.p;
        for PartId := 0 to PackageParts^.cParts - 1 do
        begin
          Part := PackageParts^.pParts[PartId];

          if IsEqualGuid(Part.PartType, GUID_JOIN_PROVIDER3) then
            MachineRid := Part.Part.JoinProv3.p^.Rid
          else if IsEqualGUID(Part.PartType, GUID_POLICY_PROVIDER) then
            LoadPolicyProvider(Part.Part.PolicyProvider.p);
        end;
      end;
    end;
  end;
end;

procedure TDJoin.FillProvision(MemCtx: PMemoryContext;
  var ProvisionData: TODJ_PROVISION_DATA);
begin
  ProvisionData.Version := 1;
  ProvisionData.ulcBlobs := 2;
  ProvisionData.pBlobs := MemCtx^.GetMem(2, SizeOf(ProvisionData.pBlobs^));

  // Win7
  ProvisionData.pBlobs[0].ulODJFormat := ODJ_WIN7BLOB;
  ProvisionData.pBlobs[0].pBlob.Win7Blob := MemCtx^.GetZeroedMem(SizeOf(ProvisionData.pBlobs[0].pBlob.Win7Blob^));
  FillWin7blob(ProvisionData.pBlobs[0].pBlob.Win7Blob^);

  // Win8
  ProvisionData.pBlobs[1].ulODJFormat := OP_PACKAGE;
  ProvisionData.pBlobs[1].pBlob.OPPackage.p := MemCtx^.GetZeroedMem(SizeOf(ProvisionData.pBlobs[1].pBlob.OPPackage.p^));
  ProvisionData.pBlobs[1].pBlob.OPPackage.p^.WrappedPartCollection.pPackagePartCollection.p := MemCtx^.GetZeroedMem(SizeOf(ProvisionData.pBlobs[1].pBlob.OPPackage.p^.WrappedPartCollection.pPackagePartCollection.p^));
  FillOpPackagePartCollection(MemCtx, ProvisionData.pBlobs[1].pBlob.OPPackage.p^.WrappedPartCollection.pPackagePartCollection.p^);
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
  DnsPolicy.Name.Buffer := Utf8ToWideString(NetbiosDomainName);
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

procedure TDJoin.FillOpPackagePartCollection(MemCtx: PMemoryContext;
  var OpPackagePartCollection: TOP_PACKAGE_PART_COLLECTION);
var
  JoinPart: POP_JOINPROV3_PART;
  Part: POP_PACKAGE_PART;
  PolicyPart: POP_POLICY_PART;
begin
  OpPackagePartCollection.cParts := 2;
  // We need a part to embed group policies
  if Length(GroupPolicies) > 0 then
    Inc(OpPackagePartCollection.cParts);
  OpPackagePartCollection.pParts := MemCtx^.GetMem(OpPackagePartCollection.cParts, SizeOf(OpPackagePartCollection.pParts^));

  // WIN7BLOB
  Part := @OpPackagePartCollection.pParts[0];
  Part^.PartType := GUID_JOIN_PROVIDER;
  Part^.ulFlags := 1; // Part is essential
  FillZero(Part^.Extension, SizeOf(Part^.Extension));
  Part^.Part.RawBytes := MemCtx^.GetZeroedMem(SizeOf(TODJ_WIN7BLOB));
  FillWin7blob(Part^.Part.Win7Blob^);

  // OP_JOINPROV3_PART (machine rid and sid)
  Part := @OpPackagePartCollection.pParts[1];
  Part^.PartType := GUID_JOIN_PROVIDER3;
  Part^.ulFlags := 0; // Part may fail
  FillZero(Part^.Extension, SizeOf(Part^.Extension));
  Part^.Part.JoinProv3.p := MemCtx^.GetZeroedMem(SizeOf(TOP_JOINPROV3_PART));
  JoinPart := Part^.Part.JoinProv3.p;
  JoinPart^.Rid := MachineRid;
  JoinPart^.lpSid := Utf8ToWideString(SidToText(@DomainSID) + '-' + IntToStr(MachineRid));

  /// OP_POLICY_PART (group policies)
  if Length(GroupPolicies) = 0 then
    Exit;
  Part := @OpPackagePartCollection.pParts[2];
  Part^.PartType := GUID_POLICY_PROVIDER;
  Part^.ulFlags := 0; // Part may fail
  FillZero(Part^.Extension, SizeOf(Part^.Extension));
  Part^.Part.PolicyProvider.p := MemCtx^.GetZeroedMem(SizeOf(TOP_POLICY_PART));
  FillPolicyPart(MemCtx, Part^.Part.PolicyProvider.p^);
end;

procedure TDJoin.FillPolicyPart(MemCtx: PMemoryContext; var PolicyPart: TOP_POLICY_PART);
var
  i, j: Integer;
  GP: TGroupPolicy;
  RegVal: TRegistryValue;
  ElementList: TOP_POLICY_ELEMENT_LIST;
  Element: TOP_POLICY_ELEMENT;
begin
  FillZero(PolicyPart.Extension, SizeOf(PolicyPart.Extension));
  PolicyPart.cElementLists := Length(GroupPolicies);
  PolicyPart.pElementsLists := MemCtx^.GetZeroedMem(PolicyPart.cElementLists, SizeOf(PolicyPart.pElementsLists^));

  for i := 0 to PolicyPart.cElementLists - 1 do
  begin
    GP := GroupPolicies[i];
    ElementList := PolicyPart.pElementsLists[i];
    ElementList.pSource := GP.Name;
    ElementList.ulRootKeyId := $80000002; // HKEY_LOCAL_MACHINE
    ElementList.cElements := Length(GP.Values);
    ElementList.pElements := MemCtx^.GetZeroedMem(ElementList.cElements, SizeOf(ElementList.pElements^));
    for j := 0 to ElementList.cElements - 1 do
    begin
      RegVal := GP.Values[j];
      Element := ElementList.pElements[j];
      Element.pKeyPath := RegVal.Key;
      Element.pValueName := RegVal.ValueName;
      Element.ulValueType := RegVal.ValueType;
      Element.cbValueData := RegVal.ValueSize;
      Element.pValueData := MemCtx^.GetMem(Element.cbValueData);
      Move(RegVal.Value[1], Element.pValueData^, Element.cbValueData);
    end;
  end;
end;

procedure TDJoin.LoadPolicyProvider(Provider: POP_POLICY_PART);
var
  i, j: Integer;
begin
  SetLength(fGroupPolicies, Provider^.cElementLists);
  for i := 0 to Provider^.cElementLists - 1 do
  begin
    GroupPolicies[i].Name := Provider^.pElementsLists[i].pSource;
    SetLength(GroupPolicies[i].Values, Provider^.pElementsLists[i].cElements);
    for j := 0 to Provider^.pElementsLists[i].cElements - 1 do
    begin
      GroupPolicies[i].Values[j].Key := Provider^.pElementsLists[i].pElements[j].pKeyPath;
      GroupPolicies[i].Values[j].ValueName := Provider^.pElementsLists[i].pElements[j].pValueName;
      GroupPolicies[i].Values[j].ValueType := Provider^.pElementsLists[i].pElements[j].ulValueType;
      GroupPolicies[i].Values[j].ValueSize := Provider^.pElementsLists[i].pElements[j].cbValueData;

      SetLength(GroupPolicies[i].Values[j].Value, GroupPolicies[i].Values[j].ValueSize);
      Move(Provider^.pElementsLists[i].pElements[j].pValueData^, GroupPolicies[i].Values[j].Value[1], GroupPolicies[i].Values[j].ValueSize);
    end;
  end;
end;

procedure TDJoin.SaveToFile(Filename: TFileName; EncodeUtf16: Boolean);
var
  Blob: RawByteString;
begin
  Blob := GetBlob(EncodeUtf16);
  // Insert BOM
  if EncodeUtf16 then
  begin
    Insert(#$ff#$fe, Blob, 1);
    Append(Blob, #0);
  end;
  FileFromString(Blob, Filename);
end;

function TDJoin.GetBlob(EncodeUtf16: Boolean): RawByteString;
var
  ProvisionData: TODJ_PROVISION_DATA;
  Provision: TODJ_PROVISION_DATA_ctr;
  Ctx: TNDRPackContext;
  Base64: RawByteString;
  MemCtx: TMemoryContext;
begin
  Result := '';
  FillProvision(@MemCtx, ProvisionData);
  Provision.p := @ProvisionData;

  Ctx := TNDRPackContext.Create;
  try
    TODJ_PROVISION_DATA_serialized_ptr.NDRPack(Ctx, Provision);

    Base64 := BinToBase64(Ctx.Buffer);
    if EncodeUtf16 then
      Result := Utf8DecodeToUnicodeRawByteString(PUtf8Char(@Base64[1]), Length(Base64))
    else
      Result := Base64;
  finally
    Ctx.Free;
    MemCtx.Clear;
  end;
end;

function TDJoin.Dump(DumpGpoRegistryValues: Boolean): RawUtf8;
var
  DomainGuidStr: RawUtf8;
  temp: TRawSmbiosInfo;
  GroupPolicy: TGroupPolicy;
  RegistryValue: TRegistryValue;
begin
  Result := '';
  DecodeSmbiosUuid(@DomainGUID, DomainGuidStr, temp);

  Append(Result, 'Machine Information:'#13#10);
  Append(Result, [' - Domain: ', MachineDomainName, #13#10]);
  Append(Result, [' - Name: ', MachineName, #13#10]);
  Append(Result, [' - Password: ', MachinePassword, #13#10]);
  Append(Result, [' - Rid: ', MachineRid, #13#10]);
  Append(Result, [' - Site Name: ', DCClientSiteName, #13#10]);

  Append(Result, CRLF+'Domain Policy Information:'#13#10);
  Append(Result, [' - Netbios Domain Name: ', NetbiosDomainName, #13#10]);
  Append(Result, [' - DNS Domain Name: ', DnsDomainName, #13#10]);
  Append(Result, [' - DNS Forest Name: ', DnsForestName, #13#10]);
  Append(Result, [' - Domain GUID: ', DomainGuidStr, #13#10]);
  Append(Result, [' - Domain SID: ', SidToText(@DomainSID), #13#10]);


  Append(Result, CRLF+'Domain Controller Information:'#13#10);
  Append(Result, [' - Name: ', DCName, #13#10]);
  Append(Result, [' - Address: ', DCAddress, #13#10]);
  Append(Result, [' - Address Type: ', DCAddressType, Format(' (%d)', [ DCAddressType]), #13#10]);
  Append(Result, Format(' - Flags: 0x%x'#13#10, [DCFlags]));
  Append(Result, [' - Site Name: ', DCSiteName, #13#10]);

  if Length(GroupPolicies) = 0 then
    Exit;
  Append(Result, CRLF+CRLF+'Embedded Group Policies:'+CRLF);
  for GroupPolicy in GroupPolicies do
  begin
    Append(Result, [' - ', GroupPolicy.Name]);
    if not DumpGpoRegistryValues then
    begin
      Append(Result, [#13#10]);
      continue;
    end;
    Append(Result, [':', #13#10]);
    for RegistryValue in GroupPolicy.Values do
    begin
      Append(Result, ['    - ', RegistryValue.Key, ' : ', RegistryValue.ValueName, ' ']);

      case RegistryValue.ValueType of
        REG_DWORD: Append(Result, [PUInt32(@RegistryValue.Value[1])^]);
        REG_QWORD: Append(Result, [PUInt64(@RegistryValue.Value[1])^]);
      end;
      Append(Result, [' (', RegistryTypeToString(RegistryValue.ValueType), ' on ', RegistryValue.ValueSize, ' bytes)'#13#10]);
    end;
  end;
end;

procedure TDJoin.DumpToConsole;
begin
  WriteLn(Dump(True));
end;

{ TDJoinParser }

class function TDJoinParser.ParseBinary(Binary: RawByteString; var DJoin: TDJoin
  ): Boolean;
var
  NdrCtx: TNDRUnpackContext;
  ProvData: TODJ_PROVISION_DATA_ctr;
  MemCtx: TMemoryContext;
begin
  NdrCtx := TNDRUnpackContext.Create(Binary, Length(Binary), @MemCtx);
  try
    try
      TODJ_PROVISION_DATA_serialized_ptr.NDRUnpack(NdrCtx, ProvData);

      Result := DJoin.LoadFromProvisionData(ProvData.p^);
    except
      Result := False;
    end;
  finally
    NdrCtx.Free;
    MemCtx.Clear;
  end;
end;

class function TDJoinParser.ParseFile(FileName: TFileName; var DJoin: TDJoin;
  Unicode: Boolean): Boolean;
begin
  Result := ParseFileContent(StringFromFile(Filename, True), DJoin, Unicode);
end;

class function TDJoinParser.ParseFileContent(FileContent: RawByteString;
  var DJoin: TDJoin; Unicode: Boolean): Boolean;
var
  Base64: RawUtf8;
  Binary: RawByteString;
begin
  if Unicode then
    Base64 := RawUnicodeToUtf8(pointer(FileContent), Length(WideString(FileContent)) div 2 - 1)
  else
    Base64 := FileContent;
  Binary := Base64toBin(Base64);

  // Not base64 encoded
  if Binary = '' then
    Exit(False);

  Result := ParseBinary(Binary, DJoin);
end;

end.

