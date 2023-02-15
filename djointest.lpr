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
  BaseDN, ComputerDN, DN, ComputerName: RawUtf8;
  Password: SpiUtf8;
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

      with TDJoin.Create do
      try
        LoadFromLDAP(ldap, ComputerName, DN, BaseDN, Password);
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

