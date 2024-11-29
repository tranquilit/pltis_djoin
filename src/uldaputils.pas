unit uLdapUtils;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.base,
  mormot.crypt.core,
  mormot.net.ldap;

type
  TComputerCreateRes = (ccrSuccess,
                     ccrAlreadyExisting,
                     ccrDeleteFailed,
                     ccrMoveFailed,
                     ccrCreateFailed,
                     ccrPwdEditFailed,
                     ccrSpnAddFailed,
                     ccrDnsAddFailed);
  TActionIfExists = (aieFail, aieOverwrite, aieMove);

  EComputerCreateException = class(Exception)
  public
    Status: TComputerCreateRes;
    LdapError: String;
    constructor Create(aMessage: String; aStatus: TComputerCreateRes; aLdapError: String = '');
  end;

function GetRandomPassword: RawUtf8;
function PrepareComputerEntry(Ldap: TLdapClient; ComputerName, ComputerOU: RawUtf8;
  out ErrorMessage: RawUtf8; var Password: SpiUtf8; ActionIfExists: TActionIfExists = aieFail;
  RemoveSPN: Boolean = False): TComputerCreateRes;
function UpdateComputerPassword(Ldap: TLdapClient; Computer: TLdapResult; var Password: SpiUtf8): Boolean;
function AddUserInGroups(Ldap: TLdapClient; ComputerDN: RawUtf8; Groups: TRawUtf8DynArray; out ErrorMessage: RawUtf8): Boolean;
function AddUserInGroup(Ldap: TLdapClient; ComputerDN, GroupDN: RawUtf8): Boolean;

function GetDCforIp(Ldap: TLdapClient; HostIp: RawUtf8 = ''): TLdapResult;
function GetDCDnsforIp(Ldap: TLdapClient; HostIp: RawUtf8): RawUtf8;
function GetSubnetForIp(Ldap: TLdapClient; HostIp: RawUtf8): RawUtf8;
function IsIpMatchingSubnet(Ip: RawUtf8; Subnet: RawUtf8): Boolean;
function Ip4ToCardinal(text: RawUtf8): Cardinal;

implementation

uses
  mormot.core.text,
  mormot.core.unicode,
  mormot.net.sock;

function GetRandomPassword: RawUtf8;
begin
  Result := TAesPrng.Main.RandomPassword(120);
end;

function PrepareComputerEntry(Ldap: TLdapClient; ComputerName,
  ComputerOU: RawUtf8; out ErrorMessage: RawUtf8; var Password: SpiUtf8;
  ActionIfExists: TActionIfExists; RemoveSPN: Boolean): TComputerCreateRes;
var
  HostEntry: TLdapResult;
  uacAttr: TLdapAttribute;
  dnsAttr: TLdapAttribute;
  spnAttr: TLdapAttribute;
  Cn: RawUtf8;
  Enum: TLdapError;

  function ExistAttrInList(const Element: RawUtf8; const Attr: TLdapAttribute): Boolean;
  var
    i: Integer;
  begin
    Result := False;
    for i := 0 to Attr.Count - 1 do
      if Attr.List[i] = Element then
      begin
        Result := True;
        Exit;
      end;
  end;
begin
  Result := ccrSuccess;
  if Password = '' then
    Password := GetRandomPassword;

  HostEntry := Ldap.SearchFirst(Ldap.DefaultDN, Format('(sAMAccountName=%s$)', [UpperCase(ComputerName)]), ['userAccountControl']);

  if Assigned(HostEntry) then
  begin
    case ActionIfExists of
    aieFail:
      begin
        ErrorMessage := 'Computer already existing';
        Result := ccrAlreadyExisting;
      end;
    aieOverwrite:
      begin
        if not Ldap.Delete(HostEntry.ObjectName, True) then
        begin
          ErrorMessage := 'Failed to delete the existing computer: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
          Result := ccrDeleteFailed;
        end;
        HostEntry := nil;
      end;
    aieMove:
      begin
      // No need to move if already at the good place
      if (LowerCase(HostEntry.ObjectName) <> LowerCase(Format('CN=%s,%s', [ComputerName, ComputerOU]))) then
      begin
        if Ldap.ModifyDN(HostEntry.ObjectName, 'CN='+ComputerName, ComputerOU, True) then
          HostEntry.ObjectName := Format('CN=%s,%s', [ComputerName, ComputerOU])
        else
        begin
          ErrorMessage := 'Failed to move the existing computer: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
          Result := ccrMoveFailed;
        end;
      end;

      if Result <> ccrMoveFailed then
      begin
        uacAttr := HostEntry.Attributes.Find('userAccountControl');
        // Host disabled
        if Assigned(uacAttr) and ((StrToInt(uacAttr.GetRaw) and $02) <> 0) then
        begin
          uacAttr.List[0] := IntToStr(StrToInt(uacAttr.GetRaw) and not $02);
          if not Ldap.Modify(HostEntry.ObjectName, lmoReplace, uacAttr) then
          begin
            ErrorMessage := 'Failed to reenabled the existing computer after move: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
            Result := ccrMoveFailed;
          end;
        end;
      end;
      end;
    end;
    if Result <> ccrSuccess then
      Exit;
  end;

  // Host doesn't exist, we must create it
  // Not a else statement because it can be modified if aieOverwrite
  if not Assigned(HostEntry) then
  begin
    if not Ldap.AddComputer(ComputerOU, ComputerName, ErrorMessage, Password, False) then
    begin
      ErrorMessage := 'Failed to create a new computer entry: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
      Result := ccrCreateFailed;
    end;
  end
  // If we didn't created the computer we still need to update the password
  else if not UpdateComputerPassword(Ldap, HostEntry, Password) then
  begin
    ErrorMessage := 'Failed to edit the computer password: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
    Result := ccrPwdEditFailed;
  end;


  //
  // servicePrincipalName and dNSHostName completion
  //
  HostEntry := Ldap.SearchFirst(Ldap.DefaultDN, Format('(sAMAccountName=%s$)', [UpperCase(ComputerName)]), ['userAccountControl', 'servicePrincipalName', 'dNSHostName']);

  if Assigned(HostEntry) then
  begin
    Cn := DNToCN(Ldap.DefaultDN);

    dnsAttr := HostEntry.Attributes.Find('dNSHostName');
    if assigned(dnsAttr) then
    begin
      dnsAttr.Clear;
      dnsAttr.Add(FormatUtf8('%.%', [LowerCase(ComputerName), LowerCase(Cn)]));

      if not Ldap.Modify(HostEntry.ObjectName, lmoReplace, dnsAttr) then
      begin
        ErrorMessage := 'Failed to edit the computer dNSHostName: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
        Result := ccrDnsAddFailed;
        Exit;
      end;
    end
    else
    begin
      dnsAttr := TLdapAttribute.Create('dNSHostName', atDnsHostName);
      try
        dnsAttr.Add(FormatUtf8('%.%', [LowerCase(ComputerName), LowerCase(Cn)]));

        if not Ldap.Modify(HostEntry.ObjectName, lmoAdd, dnsAttr) then
        begin
          ErrorMessage := 'Failed to edit the computer dNSHostName: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
          Result := ccrDnsAddFailed;
          Exit;
        end;
      finally
        dnsAttr.Free;
      end;
    end;

    spnAttr := HostEntry.Attributes.Find('servicePrincipalName');

    if RemoveSPN then
    begin
      if assigned(spnAttr) then
      begin
        HostEntry.Attributes.Delete('servicePrincipalName');
      end;
    end
    else
    begin
      if assigned(spnAttr) then
      begin
        if not ExistAttrInList(FormatUtf8('HOST/%', [UpperCase(ComputerName)]), spnAttr) then
          spnAttr.Add(FormatUtf8('HOST/%', [UpperCase(ComputerName)]));
        if not ExistAttrInList(FormatUtf8('HOST/%.%', [LowerCase(ComputerName), LowerCase(Cn)]), spnAttr) then
          spnAttr.Add(FormatUtf8('HOST/%.%', [LowerCase(ComputerName), LowerCase(Cn)]));
        if not ExistAttrInList(FormatUtf8('RestrictedKrbHost/%', [UpperCase(ComputerName)]), spnAttr) then
          spnAttr.Add(FormatUtf8('RestrictedKrbHost/%', [UpperCase(ComputerName)]));
        if not ExistAttrInList(FormatUtf8('RestrictedKrbHost/%.%', [LowerCase(ComputerName), LowerCase(Cn)]), spnAttr) then
          spnAttr.Add(FormatUtf8('RestrictedKrbHost/%.%', [LowerCase(ComputerName), LowerCase(Cn)]));

        if not Ldap.Modify(HostEntry.ObjectName, lmoReplace, spnAttr) then
        begin
          ErrorMessage := 'Failed to edit the computer servicePrincipalName: ' + RawLdapErrorString(Ldap.ResultCode, Enum);
          Result := ccrSpnAddFailed;
          Exit;
        end;
      end
      else
      begin
        spnAttr := TLdapAttribute.Create('servicePrincipalName', atServicePrincipalName);
        try
          spnAttr.Add(FormatUtf8('HOST/%', [UpperCase(ComputerName)]));
          spnAttr.Add(FormatUtf8('HOST/%.%', [LowerCase(ComputerName), LowerCase(Cn)]));
          spnAttr.Add(FormatUtf8('RestrictedKrbHost/%', [UpperCase(ComputerName)]));
          spnAttr.Add(FormatUtf8('RestrictedKrbHost/%.%', [LowerCase(ComputerName), LowerCase(Cn)]));

          if not Ldap.Modify(HostEntry.ObjectName, lmoAdd, spnAttr) then
          begin
            ErrorMessage := 'Failed to edit the computer servicePrincipalName: ' + RawLdapErrorString(Ldap.ResultCode, enum);
            Result := ccrSpnAddFailed;
            Exit;
          end;
        finally
          spnAttr.Free;
        end;
      end;
    end;
  end;
end;

function UpdateComputerPassword(Ldap: TLdapClient; Computer: TLdapResult;
  var Password: SpiUtf8): Boolean;
var
  QuotedPassword: SpiUtf8;
  PwdU16: RawByteString;
  PwdAttr: TLdapAttribute;
begin
  Result := False;
  if not Assigned(Computer) then
    Exit;

  if Password = '' then
    Password := GetRandomPassword;

  PwdAttr := TLdapAttribute.Create('unicodePwd', atUnicodePwd);
  try
    QuotedPassword := '"' + Password + '"';
    PwdU16 := Utf8DecodeToUnicodeRawByteString(QuotedPassword);
    PwdAttr.Add(PwdU16);
    if Ldap.Modify(Computer.ObjectName, lmoReplace, PwdAttr) then
      Result := True;
  finally
    PwdAttr.Free;
  end;
end;

function AddUserInGroups(Ldap: TLdapClient; ComputerDN: RawUtf8; Groups: TRawUtf8DynArray; out ErrorMessage: RawUtf8): Boolean;
var
  group: RawUtf8;
  enum: TLdapError;
begin
  Result := True;
  ErrorMessage := '';
  for group in Groups do
    if not AddUserInGroup(Ldap, ComputerDN, group) then
    begin
      Result := False;
      ErrorMessage := ErrorMessage + Format('%s: %s'#13#10, [group, RawLdapErrorString(Ldap.ResultCode, enum)]);
    end;
end;

function AddUserInGroup(Ldap: TLdapClient; ComputerDN, GroupDN: RawUtf8): Boolean;
var
  MemberAttr: TLdapAttribute;
  Operation: TLdapModifyOp;
begin
  Operation := lmoReplace;
  MemberAttr := Ldap.SearchObject(GroupDN, '', 'member');

  // No group member yet
  if not Assigned(MemberAttr) then
  begin
    Operation := lmoAdd;
    MemberAttr := TLdapAttribute.Create('member', atMember);
  end;

  MemberAttr.Add(ComputerDN);
  Result := Ldap.Modify(GroupDN, Operation, MemberAttr) or (Ldap.ResultCode = LDAP_RES_ENTRY_ALREADY_EXISTS);
end;

function Ip4ToCardinal(text: RawUtf8): Cardinal;
var
  addr: TNetAddr;
begin
  Result := 0;
  if addr.SetFromIP4(text, False) then
    Result := addr.IP4;
end;

function GetDCforIp(Ldap: TLdapClient; HostIp: RawUtf8): TLdapResult;
var
  Subnet: RawUtf8;
  DcBlObject: TLdapResult;
  previousScope: TLdapSearchScope;
  SiteDN: TLdapAttribute;
begin
  if HostIp = '' then
    HostIp := GetIPAddresses[0];
  Result := nil;
  Subnet := GetSubnetForIp(ldap, HostIp);
  // No subnet matching, fallback on first found domain controller
  if Subnet = '' then
  begin
    Result := ldap.SearchFirst(ldap.DefaultDN, '(primaryGroupID=516)', []);
    Exit;
  end;

  SiteDN := Ldap.SearchObject('CN='+subnet+',CN=Subnets,CN=Sites,CN=Configuration,' + ldap.DefaultDN, '', 'siteObject');
  if not Assigned(SiteDN) then
    Exit;
  previousScope := Ldap.SearchScope;
  ldap.SearchScope := lssSingleLevel;
  try
    DcBlObject := Ldap.SearchFirst('CN=Servers,' + SiteDN.GetReadable, '', ['serverReference']);
    if not Assigned(DcBlObject) then
      Exit;
    Result := ldap.SearchObject(DcBlObject.Attributes.GetByName( 'serverReference'), '',[]);
  finally
    ldap.SearchScope := previousScope;
  end;
end;

function GetDCDnsforIp(Ldap: TLdapClient; HostIp: RawUtf8): RawUtf8;
begin
  Result := GetDCforIp(ldap, HostIp).Attributes.Get(atDnsHostName);
end;

function GetSubnetForIp(Ldap: TLdapClient; HostIp: RawUtf8): RawUtf8;
var
  SubnetObj: TLdapResult;
  Subnet: RawUtf8;
  MatchingSubnets: TRawUtf8DynArray;
  LargestMask, MaskSize: LongInt;
  previousScope: TLdapSearchScope;
begin
  Result := '';
  previousScope := ldap.SearchScope;
  ldap.SearchScope := lssSingleLevel;
  try
    if not ldap.Search('CN=Subnets,CN=Sites,CN=Configuration,' + ldap.DefaultDN, False, '', ['']) then
      Exit;

    for SubnetObj in ldap.SearchResult.Items do
    begin
      Subnet := Copy(SubnetObj.ObjectName, 4, Pos(',', SubnetObj.ObjectName) - 4);
      if IsIpMatchingSubnet(HostIp, Subnet) then
      begin
        setLength(MatchingSubnets, Length(MatchingSubnets) + 1);
        MatchingSubnets[Length(MatchingSubnets) - 1] := Subnet;
      end;
    end;

    // No subnet matching the host ip
    if Length(MatchingSubnets) = 0 then
      Exit;
    // Only one is matching
    if Length(MatchingSubnets) = 1 then
    begin
      Result := MatchingSubnets[0];
      Exit;
    end;
    // Multiple matching, take the most restrictive
    LargestMask := 0;
    for Subnet in MatchingSubnets do
    begin
      MaskSize := StrToInt(String(Subnet).Split('/')[1]);
      if MaskSize > LargestMask then
      begin
        Result := Subnet;
        LargestMask := MaskSize;
      end;
    end;
  finally
    ldap.SearchScope := previousScope;
  end;
end;

function IsIpMatchingSubnet(Ip: RawUtf8; Subnet: RawUtf8): Boolean;
var
  SubnetParts: TStringArray;
  SubnetMask: Cardinal;
begin
  SubnetParts := String(Subnet).Split('/');
  {$ifdef ENDIAN_LITTLE}
  SubnetMask := -1 shr (32 - StrToUInt(SubnetParts[1]));
  {$else}
  SubnetMask := -1 shl (32 - StrToUInt(SubnetParts[1]));
  {$endif}
  Result := (Ip4ToCardinal(SubnetParts[0]) and SubnetMask) = (Ip4ToCardinal(Ip) and SubnetMask);
end;

constructor EComputerCreateException.Create(aMessage: String; aStatus: TComputerCreateRes; aLdapError: String);
begin
  Self.Status := aStatus;
  Self.LdapError := aLdapError;
  inherited Create(aMessage);
end;

end.

