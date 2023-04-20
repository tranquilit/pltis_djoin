/// This unit is a part of the Open Source Tranquil IT DJoin,
// licensed under a MPL/GPL/LGPL three license - see LICENSE.md

program DJoinLDAP;

uses
  SysUtils,
  uDJoin,
  mormot.core.base,
  mormot.net.ldap,
  mormot.core.text,
  mormot.core.json;

procedure LdapDjoin(
  OutputFile: TFileName;
  ComputerName, ComputerOU, Password: RawUtf8;
  Settings: TLdapClientSettings = nil; UseKerberos: Boolean = True);
var
  ldap: TLdapClient;
  kbUser: RawUtf8;
begin
  ldap := TLdapClient.Create;
  try
    if Assigned(Settings) then
    begin
      ldap.Settings.TargetHost := Settings.TargetHost;
      ldap.Settings.TargetPort := Settings.TargetPort;
      ldap.Settings.UserName := Settings.UserName;
      ldap.Settings.Password := Settings.Password;
      ldap.Settings.KerberosDN := Settings.KerberosDN;
      ldap.Settings.KerberosSpn := Settings.KerberosSpn;
      ldap.Settings.Timeout := Settings.Timeout;
      ldap.Settings.Tls := Settings.Tls;
    end;

    if ldap.Connect then
    begin
      WriteLn('Successfully connected to ldap server: ', ObjectToJsonDebug(ldap.Settings));
      if UseKerberos and ldap.BindSaslKerberos('', @kbUser) then
        WriteLn(FormatUtf8('Bound as user % using kerberos', [kbUser]))
      else if ldap.Bind then
        WriteLn('Bound using classic bind')
      else
      begin
        WriteLn('Unable to bind to server');
      end;

      if ldap.Connected then
      begin
        WriteLn('Successfully connected and bound to ldap: ', ObjectToJsonDebug(ldap.Settings));

        with TDJoin.Create do
        try
          LoadFromLDAP(ldap, ComputerName, ComputerOU, Password);
          Dump;
          SaveToFile(OutputFile);
        finally
          Free;
        end;
      end;
    end;
  finally
    ldap.Free;
  end;
end;

var
  settings: TLdapClientSettings;
  ComputerName, ComputerOU, Password: RawUtf8;
begin
  ComputerName := 'my-computer';
  ComputerOU := 'OU=test,OU=computers,OU=company';
  Password := 'azerty';

  // Will try to connect to ldap using kerberos
  LdapDjoin('djoin_kerberos.txt', ComputerName, ComputerOU, Password);

  // Will try to connect with classic bind (modify values to match your ldap server)
  settings := TLdapClientSettings.Create;
  Settings.TargetHost := 'ad.company.it';
  Settings.TargetPort := '389';
  Settings.UserName := 'username@ad.company.it';
  Settings.Password := 'azerty';
  Settings.KerberosDN := 'ad.company.it';
  LdapDjoin('djoin_classic.txt', ComputerName, ComputerOU, Password, settings, False);
end.

