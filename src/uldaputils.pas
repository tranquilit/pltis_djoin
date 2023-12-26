unit uLdapUtils;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.base,
  mormot.net.ldap;

type
  TComputerCreateRes = (ccrSuccess,
                     ccrAlreadyExisting,
                     ccrDeleteFailed,
                     ccrMoveFailed,
                     ccrCreateFailed,
                     ccrPwdEditFailed);
  TActionIfExists = (aieFail, aieOverwrite, aieMove);

  EComputerCreateException = class(Exception)
  public
    Status: TComputerCreateRes;
    LdapError: String;
    constructor Create(aMessage: String; aStatus: TComputerCreateRes; aLdapError: String = '');
  end;

function GetRandomPassword: RawUtf8;
function PrepareComputerEntry(Ldap: TLdapClient; ComputerName, ComputerOU: RawUtf8;
  out ErrorMessage: RawUtf8; var Password: SpiUtf8; ActionIfExists: TActionIfExists = aieFail): TComputerCreateRes;
function UpdateComputerPassword(Ldap: TLdapClient; Computer: TLdapResult; var Password: SpiUtf8): Boolean;

function GetDCforIp(Ldap: TLdapClient; HostIp: RawUtf8 = ''): TLdapResult;
function GetDCDnsforIp(Ldap: TLdapClient; HostIp: RawUtf8): RawUtf8;
function GetSubnetForIp(Ldap: TLdapClient; HostIp: RawUtf8): RawUtf8;
function IsIpMatchingSubnet(Ip: RawUtf8; Subnet: RawUtf8): Boolean;
function Ip4ToCardinal(text: RawUtf8): Cardinal;

implementation

uses
  mormot.core.unicode,
  mormot.net.sock;

function GetRandomPassword: RawUtf8;
var
  i: Integer;
begin
  SetLength(Result, 120);
  for i := 1 to 120 do
    Result[i] := Char(Random(Byte('~') - Byte('!')) + Byte('!'));
end;

function PrepareComputerEntry(Ldap: TLdapClient; ComputerName,
  ComputerOU: RawUtf8; out ErrorMessage: RawUtf8; var Password: SpiUtf8;
  ActionIfExists: TActionIfExists): TComputerCreateRes;
var
  HostEntry: TLdapResult;
begin
  Result := ccrSuccess;
  if Password = '' then
    Password := GetRandomPassword;

  HostEntry := Ldap.SearchFirst(Ldap.DefaultDN, Format('(sAMAccountName=%s$)', [UpperCase(ComputerName)]), ['']);

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
          ErrorMessage := 'Failed to delete the existing computer: ' + RawLdapErrorString(Ldap.ResultCode);
          Result := ccrDeleteFailed;
        end;
        HostEntry := nil;
      end;
    aieMove:
      // No need to move if already at the good place
      if (LowerCase(HostEntry.ObjectName) <> LowerCase(Format('CN=%s,%s', [ComputerName, ComputerOU]))) then
      begin
        if Ldap.ModifyDN(HostEntry.ObjectName, 'CN='+ComputerName, ComputerOU, True) then
          HostEntry.ObjectName := Format('CN=%s,%s', [ComputerName, ComputerOU])
        else
        begin
          ErrorMessage := 'Failed to move the existing computer: ' + RawLdapErrorString(Ldap.ResultCode);
          Result := ccrMoveFailed;
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
      ErrorMessage := 'Failed to create a new computer entry: ' + RawLdapErrorString(Ldap.ResultCode);
      Result := ccrCreateFailed;
    end;
  end
  // If we didn't created the computer we still need to update the password
  else if not UpdateComputerPassword(Ldap, HostEntry, Password) then
  begin
    ErrorMessage := 'Failed to edit the computer password: ' + RawLdapErrorString(Ldap.ResultCode);
    Result := ccrPwdEditFailed;
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

  PwdAttr := TLdapAttribute.Create('unicodePwd');
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
    Result := ldap.SearchObject(DcBlObject.Attributes.Get('serverReference'), '', []);
  finally
    ldap.SearchScope := previousScope;
  end;
end;

function GetDCDnsforIp(Ldap: TLdapClient; HostIp: RawUtf8): RawUtf8;
begin
  Result := GetDCforIp(ldap, HostIp).Attributes.Get('dNSHostName');
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

