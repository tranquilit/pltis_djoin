unit uDjoinCLI;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.base,
  mormot.core.os,
  uDJoin;

type
  TDjoinAction = (daUndefined, daDump);

  TDumpSettings = record
    Base64: RawUtf8;
    BlobFile: RawUtf8;
  end;

  { TSettings }

  TSettings = object
    Action: TDjoinAction;
    Unicode: Boolean;
    Dump: TDumpSettings;
    function Validate: Boolean;
  end;

  { TDJoinCLI }

  TDJoinCLI = class
  private
    fErrorCode: Integer;

    procedure Dump;
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
  mormot.core.text;

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
  end;
  Result := True;
end;

{ DJoinCLI }

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
    Dump;
  finally
    Free;
  end;
end;

constructor TDJoinCLI.Create;
begin
  inherited Create;
  fErrorCode := 0;
end;

function TDJoinCLI.Run: Boolean;
begin
  case Settings.Action of
    daDump:
      Dump;
  end;
  Result := ErrorCode = 0;
end;

class function TDJoinCLI.GetHelp(ExeDesc: Boolean): RawUtf8;
begin
  with Executable.Command do
  begin
    if ExeDesc then
      ExeDescription := 'Tranquil IT Open Source implementation of Microsoft''s djoin.exe';
    if Arg(['dump'], 'Action to execute. Must be one of:'#10#9#9#9+
          '- dump: Dump a given djoin blob') then
    begin
      if Args[0] = 'dump' then
      begin
        Param(['b', 'base64'], 'Base64 encoded blob. Can be a filepath or the base64 content itself');
        Param('blob', 'Filepath of a djoin binary blob (not base64 encoded). Mostly used for debug');
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
    if Arg(['dump']) then
    case Args[0] of
      'dump':
      begin
        CLI.Settings.Action := daDump;
        CLI.Settings.Dump.Base64 := Param(['b', 'base64']);
        CLI.Settings.Dump.BlobFile := Param('blob');
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

