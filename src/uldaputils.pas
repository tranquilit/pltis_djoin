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

function GetRandomPassword: RawUtf8;
function PrepareComputerEntry(Ldap: TLdapClient; ComputerName, ComputerOU: RawUtf8;
  out ErrorMessage: RawUtf8; var Password: SpiUtf8; ActionIfExists: TActionIfExists = aieFail): TComputerCreateRes;
function UpdateComputerPassword(Ldap: TLdapClient; Computer: TLdapResult; var Password: SpiUtf8): Boolean;


implementation

uses
  mormot.core.unicode;

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
      Result := ccrAlreadyExisting;
    aieOverwrite:
      begin
        if not Ldap.Delete(HostEntry.ObjectName, True) then
          Result := ccrDeleteFailed;
        HostEntry := nil;
      end;
    aieMove:
      // No need to move if already at the good place
      if (LowerCase(HostEntry.ObjectName) <> LowerCase(Format('CN=%s,%s', [ComputerName, ComputerOU]))) then
      begin
        if Ldap.ModifyDN(HostEntry.ObjectName, 'CN='+ComputerName, ComputerOU, True) then
          HostEntry.ObjectName := Format('CN=%s,%s', [ComputerName, ComputerOU])
        else
          Result := ccrMoveFailed;
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
      Result := ccrCreateFailed;
  end
  // If we didn't created the computer we still need to update the password
  else if not UpdateComputerPassword(Ldap, HostEntry, Password) then
    Result := ccrPwdEditFailed;
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

end.

