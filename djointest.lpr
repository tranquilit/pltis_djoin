program djointest;

uses uDJoin;

begin
  with TDJoin.Create do
  try
    LoadFromFile('C:\temp\djoin_unix_4.txt');
    Dump;
  finally
    Free;
  end;
end.

