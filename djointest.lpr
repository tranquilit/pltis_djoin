program djointest;

uses
  SysUtils,
  uDJoin,
  uDJoinTypes,
  uNDRContext,
  mormot.core.base,
  mormot.core.os,
  mormot.net.ldap,
  mormot.core.unicode,
  mormot.net.sock,
  mormot.core.text;

const DomGUID: TGUID = '{58691904-1932-4BC4-96A5-552942191D94}';


function DNToCannonical(DC: RawUtf8): RawUtf8;
const
  DomainComponent = 'DC';
  OrganizationalUnit = 'OU';
  CommonName = 'CN';
var
  P: PUtf8Char;
  Domain, OU, Common, PartType, Value: RawUtf8;
begin
  P := @DC[1];
  while Assigned(P) do
  begin
    GetNextItemTrimed(P, '=', PartType);
    GetNextItemTrimed(P, ',', Value);

    if PartType = DomainComponent then
    begin
      if Length(Domain) > 0 then
        Append(Domain, ['.', Value])
      else
        Domain := Value;
    end
    else if PartType = OrganizationalUnit then
      Append(OU, ['/', Value])
    else if PartType = CommonName then
      Append(Common, ['/', Value]);
  end;
  Result := LowerCase(Domain + OU + Common);
end;

function CreateComputer(ldap: TLdapClient; ComputerName, BaseDN, DN: RawUtf8; Password: SpiUtf8): RawUtf8;
var
  PwdU8: SpiUtf8;
  ComputerDN: RawUtf8;
  Attributes: TLdapAttributeList;
  ObjClass: TLdapAttribute;
begin
    ComputerDN := 'CN='+ComputerName+',' + DN +','+BaseDN;
    PwdU8 := '"'+Password+'"';

    Attributes := TLDAPAttributeList.Create;
    ObjClass := Attributes.Add('objectClass');
    ObjClass.Add('computer');
    Attributes.Add('cn').Add(ComputerName);
    Attributes.Add('sAMAccountName').Add(UpperCase(ComputerName)+'$');
    Attributes.Add('userAccountControl').Add('4096');
    Attributes.Add('unicodePwd').Add(Utf8DecodeToUnicodeRawByteString(@PwdU8[1], Length(PwdU8)));

    ldap.Delete(ComputerDN);
    ldap.Add(ComputerDN, Attributes);
    Result := ComputerDN;
    Attributes.Free;
end;

procedure LdapDjoin(OutputFile: TFileName);
var
  ldap: TLdapClient;
  TLSCtx: TNetTlsContext;
  BaseDN, ComputerDN, DN, ComputerName, Domain, DC, Addr, PolicyDN: RawUtf8;
  Password: SpiUtf8;
  DCObject, ComputerObject, DNObject: TLdapResult;
  Sid: TSid;
  SidBinary: RawByteString;
  Rid: Cardinal;
begin
  ldap := TLdapClient.Create;
  try
    ldap.TlsContext := @TLSCtx;
    ldap.TlsContext^.IgnoreCertificateErrors := True;
    ldap.TargetHost := '10.10.3.171';
    ldap.TargetPort := '389';
    ldap.UserName := 'administrator@aleroux.lan';
    ldap.Password := 'calimero';

    BaseDN := 'DC=ALEROUX,DC=LAN';
    DN := 'OU=test,OU=computers,OU=tranquilit';
    Password := 'Password';
    ComputerName := 'test-djoin-ldap';

    if ldap.Login and ldap.Bind then
    begin
      ComputerDN := CreateComputer(ldap, ComputerName, BaseDN, DN, Password);

      Domain := DNToCannonical(BaseDN);
      Addr := '\\'+ldap.TargetHost;

      // Computer Object
      ldap.Search(ComputerDN, False, '', []);
      ComputerObject := ldap.SearchResult.Items[0];
      SidBinary := ComputerObject.Attributes.Find('objectSid').GetRaw(0);
      Move(SidBinary[1], sid, Length(SidBinary));
      Rid := sid.SubAuthority[sid.SubAuthorityCount - 1];
      Dec(sid.SubAuthorityCount);

      // DC Object
      ldap.Search(BaseDN, False, '(primaryGroupID=516)', []);
      if ldap.SearchResult.Count = 0 then
        Exit;
      DCObject := ldap.SearchResult.Items[0];
      DC := '\\'+DCObject.Attributes.Find('dNSHostName').GetReadable(0);

      // Base Dn Object
      ldap.Search(BaseDN, False, '(distinguishedName='+BaseDN+')', []);
      DNObject := ldap.SearchResult.Items[0];
      PolicyDN := DNObject.Attributes.Find('dc').GetReadable(0);


      with TDJoin.Create do
      try
        MachineDomainName := Domain;
        MachineName := ComputerName;
        MachinePassword := Password;
        MachineRid := Rid;
        Options := 6; // ?

        PolicyDomainName := PolicyDN;
        DnsDomainName := Domain;
        DnsForestName := Domain;
        DomainGUID := DomGUID;
        DomainSID := sid;

        DCName := DC;
        DCAddress := Addr;
        DCAddressType := DS_INET_ADDRESS;
        DCFlags := $E00013FD;
        DCSiteName := 'Default-First-Site-Name';
        DCClientSiteName := 'Default-First-Site-Name';

        SaveToFile(OutputFile);
      finally
        Free;
      end;
    end;
  finally
    ldap.Free;
  end;
end;

procedure DumpFile(FileName: TFileName);
begin
  with TDJoin.Create do
  try
    LoadFromFile(FileName);
    Dump;
    DumpDS_Flags(DCFlags);
  finally
    Free;
  end;
end;

begin
  LdapDjoin('C:\temp\lazjoin.txt');
  DumpFile('C:\temp\djoin.txt');
end.

