program djointest;

uses uDJoin;

begin
  with TDJoin.Create do
  try
    LoadFromFile('C:\temp\djoin.txt');
    Dump;
  finally
    Free;
  end;
end.

