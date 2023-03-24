program DJoinExtract;

uses
  SysUtils,
  uDJoin,
  mormot.core.text;

procedure DumpFile(FileName: TFileName);
begin
  with TDJoin.Create do
  try
    LoadFromFile(FileName);
    WriteLn(FormatUtf8('Parsed djoin blob from % :', [FileName]));
    Dump;
  finally
    Free;
  end;
end;

begin
  DumpFile('djoin.txt');
end.

