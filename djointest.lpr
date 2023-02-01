program djointest;

uses uDJoin;

begin
  with TDJoin.Create do
  try
    LoadFromFile('C:\temp\djoin.txt');
  finally
    Free;
  end;
end.

