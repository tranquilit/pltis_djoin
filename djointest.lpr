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

procedure LdapDjoin(OutputFile: TFileName);
var
  ldap: TLdapClient;
  TLSCtx: TNetTlsContext;
  BaseDN, ComputerDN, DN, ComputerName, Domain, DC, Addr, PolicyDN: RawUtf8;
  Password: SpiUtf8;
  DCObject, ComputerObject, DNObject: TLdapResult;
  Sid: TSid;
  DomGuid: TGuid;
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
      ComputerDN := 'CN='+ComputerName+',' + DN +','+BaseDN;
      if not ldap.AddComputer(DN +','+BaseDN, ComputerName, Password, True) then
        raise Exception.CreateFmt('Unable to create computer %s in domain', [ComputerDN]);

      Domain := DNToCannonical(BaseDN);
      Addr := '\\'+ldap.TargetHost;

      // Computer Object
      ComputerObject := ldap.SearchFirst(ComputerDN, '', []);
      if not (Assigned(ComputerObject) and ComputerObject.GetObjectSid(Sid)) then
        raise Exception.Create('Unable to retreive computer SID');
      Rid := sid.SubAuthority[sid.SubAuthorityCount - 1];
      Dec(sid.SubAuthorityCount);

      // DC Object
      DCObject := ldap.SearchFirst(BaseDN, '(primaryGroupID=516)', []);
      if not Assigned(DCObject) then
         raise Exception.Create('Unable to retreive Domain Controller object');
      DC := '\\'+DCObject.Attributes.Find('dNSHostName').GetReadable;

      // Base Dn Object
      DNObject := ldap.SearchFirst(BaseDN, '(distinguishedName='+BaseDN+')', []);
      if not Assigned(DNObject) then
         raise Exception.Create('Unable to retreive Domain object');
      PolicyDN := DNObject.Attributes.Find('dc').GetReadable;
      DomGuid := DNObject.objectGUID^;

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

        Dump;
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
  finally
    Free;
  end;
end;

begin
  LdapDjoin('C:\temp\lazjoin.txt');
  DumpFile('C:\temp\lazjoin.txt');
end.

