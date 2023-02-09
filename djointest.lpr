program djointest;

uses
  uDJoin,
  uDJoinTypes,
  uNDRContext,
  mormot.core.base,
  mormot.core.os;

const DomGUID: TGUID = '{58691904-1932-4BC4-96A5-552942191D94}';

var
  Domain, Machine, DC, Addr: RawUtf8;
  TempSid: TSid;
begin
  Domain := 'aleroux.lan';
  Machine := 'test-join';
  DC := '\\bullseyex64.aleroux.lan';
  Addr :=  '\\10.10.3.171';

  with TDJoin.Create do
  try
    MachineDomainName := Domain;
    MachineName := Machine;
    MachinePassword := Machine;
    MachineRid := 1136;
    Options := 6; // ?

    PolicyDomainName := 'ALEROUX';
    DnsDomainName := Domain;
    DnsForestName := Domain;
    DomainGUID := DomGUID;
    TextToSid(PUtf8Char('S-1-5-21-157379786-3592381142-1446019043'), TempSid);
    DomainSID := TempSid;

    DCName := DC;
    DCAddress := Addr;
    DCAddressType := 1; // Use Enum
    DCFlags := $E00013FD;
    DCSiteName := 'Default-First-Site-Name';
    DCClientSiteName := 'Default-First-Site-Name';

    Dump;
    SaveToFile('C:\temp\lazjoin.txt');

  finally
    Free;
  end;

  with TDJoin.Create do
  try
    LoadFromFile('C:\temp\djoin_unix.txt');
    Dump;
  finally
    Free;
  end;
end.

