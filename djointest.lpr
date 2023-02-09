program djointest;

uses uDJoin;

begin
  with TDJoin.Create do
  try
    LoadFromFile('C:\temp\djoin_unix.txt');
    Dump;
  finally
    Free;
  end;
end.

