unit uDjoinCLI;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.base,
  mormot.core.os,
  uDJoin,
  uLdapUtils;

type
  TDjoinAction = (daUndefined, daDump, daCreate);

  TCreateSettings = record
    Config: RawUtf8;
    Output: RawUtf8;
    Force: Boolean;
    UseLdap: Boolean;
    ActionIfExists: TActionIfExists;
    RemoveSPN: Boolean;
  end;

  TDumpSettings = record
    Base64: RawUtf8;
    BlobFile: RawUtf8;
  end;

  { TSettings }

  TSettings = object
    Action: TDjoinAction;
    Unicode: Boolean;
    Dump: TDumpSettings;
    Create: TCreateSettings;
    function Validate: Boolean;
  end;

  { TDJoinCLI }

  TDJoinCLI = class
  private
    fErrorCode: Integer;

    function AskConfirmation(Message: RawUtf8): Boolean;
    procedure Error(Message: RawUtf8; Code: Integer = 1);
    procedure Dump;
    procedure CreateBlob;
  public
    Settings: TSettings;

    constructor Create;

    class function GetHelp(ExeDesc: Boolean = True): RawUtf8;
    class procedure DisplayHelp(ExeDesc: Boolean = True);
    class procedure Start;

    function Run: Boolean;

    property ErrorCode: Integer read fErrorCode;
  end;

implementation

uses
  mormot.core.buffers,
  mormot.core.text,
  mormot.core.variants,
  mormot.core.data,
  mormot.net.ldap,
  mormot.net.sock,
  uDJoinTypes,
  Variants;

{ TSettings }

function TSettings.Validate: Boolean;
begin
  Result := False;
  if Action = daUndefined then
    Exit;
  case Action of
    daDump:
    begin
      if (Dump.Base64 = '') and (Dump.BlobFile = '') then
      begin
        WriteLn(StdErr, 'Missing input to dump');
        Exit;
      end;
      if (Dump.Base64 <> '') and not (FileExists(Dump.Base64) or IsBase64(Dump.Base64)) then
      begin
        WriteLn(StdErr, 'Base64 must be a filepath or a base64 encoded blob');
        Exit;
      end;
      if (Dump.BlobFile <> '') and not FileExists(Dump.BlobFile) then
      begin
        WriteLn(StdErr, 'Blob must be a filepath to a binary blob');
        Exit;
      end;
    end;
    daCreate:
    begin
      if Create.Config = '' then
      begin
        WriteLn(StdErr, 'Missing configuration to create blob');
        Exit;
      end;
      if not (FileExists(Create.Config) or IsBase64(Create.Config)) then
      begin
        WriteLn(StdErr, 'Config must be a filepath or a base64 encoded json');
        Exit;
      end;
    end;
  end;
  Result := True;
end;

{ DJoinCLI }

function TDJoinCLI.AskConfirmation(Message: RawUtf8): Boolean;
var
  Answer: String;
begin
  Result := Settings.Create.Force;
  if Result then
    Exit;
  repeat
    WriteLn(Message+ ' (y)');
    ReadLn(Answer);
  until Answer <> '';
  Result := (LowerCase(Answer) = 'y') or (LowerCase(Answer) = 'yes');
end;

procedure TDJoinCLI.Error(Message: RawUtf8; Code: Integer);
begin
  WriteLn(StdErr, Message);
  fErrorCode := Code;
end;

procedure TDJoinCLI.Dump;
begin
  with TDJoin.Create do
  try
    if Settings.Dump.Base64 <> '' then
    begin
      if FileExists(Settings.Dump.Base64) then
        LoadFromFile(Settings.Dump.Base64, Settings.Unicode)
      else
        LoadFromFileContent(Settings.Dump.Base64, False);
    end
    else
      LoadFromBinary(StringFromFile(Settings.Dump.BlobFile));
    WriteLn(FormatUtf8('Parsed djoin blob from %:', [Settings.Dump.Base64]));
    DumpToConsole;
  finally
    Free;
  end;
end;

procedure TDJoinCLI.CreateBlob;
var
  ConfigDV: TDocVariantData;
  ConfigStr: RawByteString;
  LdapPassword: SpiUtf8;
  dsid: TSid;
  StrSid: RawUtf8;
  LdapSettings: TLdapClientSettings;
  Ldap: TLdapClient;
  GroupPolicy: PVariant;
begin
  if FileExists(Settings.Create.Config) then
    ConfigStr := StringFromFile(Settings.Create.Config)
  else if IsBase64(Settings.Create.Config) then
    ConfigStr := Base64ToBin(Settings.Create.Config);
  if not ConfigDV.InitJson(ConfigStr, JSON_FAST) then
  begin
    WriteLn('Cannot load the given configuration. It must be a valid JSON file or base64');
    Exit;
  end;


  if Settings.Create.UseLdap then
  begin
    LdapSettings := TLdapClientSettings.Create;
    LdapSettings.TargetHost := ConfigDV.GetValueOrDefault('TargetHost', '');
    LdapSettings.TargetPort := ConfigDV.GetValueOrDefault('TargetPort', '389');
    LdapSettings.UserName := ConfigDV.GetValueOrDefault('Username', '');
    if LdapSettings.UserName <> '' then
    begin
      LdapSettings.Password := Trim(Executable.Command.Param(['p', 'password']));
      if Executable.Command.Option(['p', 'password']) then
      begin
        WriteLn('LDAP Password:');
        // TODO: Replace the ReadLn by a future "ReadPassword" in mORMot hiding the written password
        ReadLn(LdapPassword);
        LdapSettings.Password := Trim(LdapPassword);
        LdapPassword := '';
      end;
      if (LdapSettings.Password = '') then
        LdapSettings.Password := Trim(VarToStr(ConfigDV.GetValueOrDefault('Password', '')));
    end;
    LdapSettings.KerberosDN := ConfigDV.GetValueOrDefault('KerberosDN', '');
    LdapSettings.Timeout := ConfigDV.GetValueOrDefault('Timeout', 5000);
    LdapSettings.Tls := ConfigDV.GetValueOrDefault('Tls', False);
    LdapSettings.AllowUnsafePasswordBind := ConfigDV.GetValueOrDefault('AllowUnsafePasswordBind', False);
    Ldap := TLdapClient.Create(LdapSettings);

    if not Ldap.Connect then
    begin
      Error('Cannot establish connection with the ldap host');
      Exit;
    end;

    if not ldap.BindSaslKerberos then
      if ConfigDV.GetValueOrDefault('OnlyKerberos', True) or not ldap.Bind then
      begin
        Error('Cannot bind to ldap server');
        Exit;
      end;
  end;

  with TDJoin.Create do
  try
    try
      // Compute Password if not given
      if Settings.Create.UseLdap then
      begin
        // Compute OU if not given
        if ConfigDV.S['MachineName'] = '' then
          raise EDocVariant.Create('[MachineName] property not found');
        LoadFromLDAP(Ldap, ConfigDV.S['MachineName'],
                           VarToStr(ConfigDV.GetValueOrDefault('MachineOU', '')),
                           VarToStr(ConfigDV.GetValueOrDefault('MachinePassword', '')),
                           ConfigDV.S['DCName'], '',
                           Settings.Create.ActionIfExists,
                           Settings.Create.RemoveSPN);
        for GroupPolicy in ConfigDV.A['GroupPoliciesDisplayNames']^.Items do
          AddGroupPoliciesFromLdap(Ldap, VarToStr(GroupPolicy^));
        for GroupPolicy in ConfigDV.A['GroupPoliciesGUIDs']^.Items do
          AddGroupPoliciesFromLdap(Ldap, '', VarToStr(GroupPolicy^)) ;
      end
      else
      begin
        // Raise if value is missing
        ConfigDV.Options := [dvoValueCopiedByReference];

        MachineName := ConfigDV.S['MachineName'];
        MachinePassword := ConfigDV.S['MachinePassword'];
        if MachinePassword = '' then
          MachinePassword := GetRandomPassword;


        MachineDomainName := ConfigDV.S['MachineDomainName'];


        MachineRid := StrToInt(ConfigDV.S['MachineRid']);
        Options := 6;

        NetbiosDomainName := ConfigDV.S['NetbiosDomainName'];
        DnsDomainName := ConfigDV.S['DnsDomainName'];
        DnsForestName := ConfigDV.S['DnsForestName'];
        DomainGUID := StringToGuid(FormatUtf8('{%}', [ConfigDV.S['DomainGUID']]));
        if IsZero(@DomainGUID, SizeOf(DomainGUID)) then
          raise Exception.Create('Domain GUID format is invalid');

        StrSid := ConfigDV.S['DomainSID'];
        if TextToSid(@StrSid[1], dsid) then
          DomainSID := dsid
        else
          raise Exception.Create('Domain SID format is invalid');

        DCName := '\\'+ConfigDV.S['DCName'];
        DCAddress := '\\'+ConfigDV.S['DCAddress'];
        DCAddressType := DS_INET_ADDRESS;
        DCFlags := $E00013FD;
        DCSiteName := VarToStr(ConfigDV.GetValueOrDefault('DCSiteName', 'Default-First-Site-Name'));
        DCClientSiteName := VarToStr(ConfigDV.GetValueOrDefault('DCClientSiteName', 'Default-First-Site-Name'));
      end;

    except
      on E:EDocVariant do
      begin
        Error(FormatUtf8('Missing required property: %', [E.Message]));
        Exit;
      end;
      on E:Exception do
      begin
        Error(E.Message);
        Exit;
      end;
    end;
    if AskConfirmation(FormatUtf8('Save following djoin blob as % ?', [Settings.Create.Output]) + CRLF + Dump(Executable.Command.Option(['v', 'verbose']))) then
      SaveToFile(Settings.Create.Output, Settings.Unicode);
  finally
    Free;
  end;
end;

constructor TDJoinCLI.Create;
begin
  inherited Create;
  fErrorCode := 0;
  Settings.Create.RemoveSPN := False;
  Settings.Create.ActionIfExists := aieFail;
end;

function TDJoinCLI.Run: Boolean;
begin
  case Settings.Action of
    daDump:
      Dump;
    daCreate:
      CreateBlob;
  end;
  Result := ErrorCode = 0;
end;

class function TDJoinCLI.GetHelp(ExeDesc: Boolean): RawUtf8;
var
  ConfigParametersDoc: String;
begin
  with Executable.Command do
  begin
    if ExeDesc then
      ExeDescription := 'Tranquil IT Open Source implementation of Microsoft''s djoin.exe';
    if Arg(['dump', 'create'], 'Action to execute. Must be one of:'#10#9#9#9+
          '- dump: Dump a given djoin blob'#10#9#9#9+
          '- create: Create a new djoin file') then
    begin
      if Args[0] = 'dump' then
      begin
        Param(['b', 'base64'], 'Base64 encoded blob. Can be a filepath or the base64 content itself');
        Param('blob', 'Filepath of a djoin binary blob (not base64 encoded). Mostly used for debug');
      end else if Args[0] = 'create' then
      begin
        ConfigParametersDoc := 'Configuration json (filepath or base64) of the config to use.'#10#9#9+
          'Required values:'#10#9#9#9+
            '- MachineName: The name of the machine (ex: my-computer)';


        if not Option('ldap') then
        begin
          ConfigParametersDoc := ConfigParametersDoc +#10#9#9#9 +
            '- MachineDomainName: The domain name of the machine (ex: my.domain.lan)'#10#9#9#9+
            '- MachinePassword: The password of the machine (ex: mysuperpwd)'#10#9#9#9+
            '- MachineRid: The machine account RID (ex: 1130)'#10#9#9#9+
            '- NetbiosDomainName: The netbios domain name (ex: MYDOMAIN)'#10#9#9#9+
            '- DnsDomainName: The Dns domain (ex: my.domain.lan)'#10#9#9#9+
            '- DnsForestName: The forest domain name (ex: my.domain.lan)'#10#9#9#9+
            '- DomainGUID: The domain GUID (ex: 58691904-1932-4bc4-96a5-552942191d94)'#10#9#9#9+
            '- DomainSID: The domain SID (ex: S-1-5-21-157379786-3592381142-1446019043)'#10#9#9#9+
            '- DCName: The domain controller name (ex: \\bullseyex64.ad.company.it)'#10#9#9#9+
            '- DCAddress: The domain controller address (ex: \\192.168.42.42)'#10#9#9+
          'Optional values:'#10#9#9#9 +
            '- DCSiteName: The domain controller site name (default: Default-First-Site-Name)'#10#9#9#9+
            '- DCClientSiteName: The domain controller client site name (default: Default-First-Site-Name)';
        end else
        begin
          Param(['p', 'password'], 'LDAP Password. Read from stdin if no value provided. Has priority over the config file');
          ConfigParametersDoc := ConfigParametersDoc +#10#9#9 +
          'Optional values:'#10#9#9#9 +
            '- MachineOU: Machine parent OU (ex: OU=domain,DC=my,DC=domain,DC=lan). Default to COMPUTRS_CONTAINER well known object'#10#9#9#9+
            '- MachinePassword: The password of the machine (ex: mysuperpwd). Default to a randomly generated 120 bytes password'#10#9#9#9+
            '- TargetHost: Server address (ex: my.domain.lan). Default to current machine domain'#10#9#9#9+
            '- TargetPort: Server port (ex: 389). Default to 636'#10#9#9#9+
            '- UserName: LDAP username (ex: muser@my.domain.lan). Default to current user'#10#9#9#9+
            '- Password: LDAP password (ex: mypasswd). Not required if authenticating with kerberos'#10#9#9#9+
            '- KerberosDN: Kerberos canonical domain name (ex: my.domain.lan). Required if different than TargetHost'#10#9#9#9+
            '- Timeout: Timeout for operations in milliseconds (default: 5000)'#10#9#9#9+
            '- Tls: Whether the connection with the server must be secured through TLS (default: false)'#10#9#9#9+
            '- AllowUnsafePasswordBind: Whether sending password for bind on a non Tls connection is allowed (default: false)'#10#9#9#9+
            '- OnlyKerberos: Whether kerberos bind is the only authorized bind (default: true)'#10#9#9#9+
            '- GroupPoliciesDisplayNames: List of GPO display names (default: empty)'#10#9#9#9+
            '- GroupPoliciesGUIDs: List of GPO GUIDs (default: empty)'#10#9#9#9+
            '- DCName: The domain controller DNS HostName (ex: bullseyex64.ad.company.it)';
        end;

        Param(['c', 'config'], ConfigParametersDoc);
        Param(['o', 'output'], 'Output file', 'djoin.txt');
        Option(['f', 'force'], 'Doesn''t ask user confirmation (assume yes for all questions)');
        if Option('ldap', 'Connect to domain through ldap to complete djoin informations. See "djoin create -ldap -h" for more informations') then
        begin
          Param(['reuse'], 'Behavior when computer with sAmAccountName already exists in the domain. Must be one of:'#10#9#9#9+
            '- fail: Abort the djoin creation'#10#9#9#9+
            '- overwrite: Delete the existing entry and create a new one'#10#9#9#9+
            '- move: Move the existing entry to the given location. Does nothin if the computer is already at the given location.', 'fail');
        end;
      end;
    end;
    Param(['u', 'unicode'], 'Base64 blobs (in/out) are encoded in Utf16-le (as in Microsoft''s djoin blobs)', 'True');
    Result := FullDescription;
  end;
end;

class procedure TDJoinCLI.DisplayHelp(ExeDesc: Boolean);
begin
  WriteLn(GetHelp(ExeDesc));
end;

class procedure TDJoinCLI.Start;
var
  CLI: TDJoinCLI;
begin
  CLI := TDJoinCLI.Create;
  with Executable.Command do
  begin
    if Option(['h', 'help']) then
    begin
      DisplayHelp;
      Exit;
    end;

    CLI.Settings.Unicode := LowerCase(Param(['u', 'unicode'], '', 'True')) = 'true';
    if Arg(['dump', 'create']) then
    case Args[0] of
      'dump':
      begin
        CLI.Settings.Action := daDump;
        CLI.Settings.Dump.Base64 := Param(['b', 'base64']);
        CLI.Settings.Dump.BlobFile := Param('blob');
      end;
      'create':
      begin
        CLI.Settings.Action := daCreate;
        CLI.Settings.Create.Config := Param(['c', 'config']);
        CLI.Settings.Create.Output := Param(['o', 'output'], '', 'djoin.txt');
        CLI.Settings.Create.Force := Option(['f', 'force']);
        CLI.Settings.Create.UseLdap := Option('ldap');
        if CLI.Settings.Create.UseLdap then
        begin
          CLI.Settings.Create.RemoveSPN := Option('remove-spn');
          case Param('reuse', '', 'fail') of
            'fail': CLI.Settings.Create.ActionIfExists := aieFail;
            'overwrite': CLI.Settings.Create.ActionIfExists := aieOverwrite;
            'move': CLI.Settings.Create.ActionIfExists := aieMove;
            else
            begin
              WriteLn(StdErr, 'Invalid parameter for reuse');
              DisplayHelp(False);
              ExitCode := 1;
            end;
          end;
        end;
      end;
    end;

  end;

  if not CLI.Settings.validate then
  begin
    DisplayHelp(False);
    ExitCode := 1;
  end
  else if not CLI.Run then
    ExitCode := 1;
end;

end.

