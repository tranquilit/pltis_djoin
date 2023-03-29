/// This unit is a part of the Open Source Tranquil IT DJoin,
// licensed under a MPL/GPL/LGPL three license - see LICENSE.md

program DJoinManual;

uses
  SysUtils,
  uDJoin,
  uDJoinTypes,
  mormot.core.base,
  mormot.core.os;

procedure CreateDjoin(OutputFile: TFileName);
var
  dsid: TSid;
begin
  with TDJoin.Create do
  try
    MachineDomainName := 'ad.company.it';
    MachineName := 'my-computer';
    MachinePassword := 'azerty';
    MachineRid := 1130;
    Options := 6;

    NetbiosDomainName := 'COMPANY';
    DnsDomainName := 'ad.company.it';
    DnsForestName := 'ad.company.it';
    DomainGUID := StringToGuid('{58691904-1932-4bc4-96a5-552942191d94}');
    if TextToSid('S-1-5-21-157379786-3592381142-1446019043', dsid) then
      DomainSID := dsid
    else
      raise Exception.Create('Invalid sid');

    DCName := '\\bullseyex64.ad.company.it';
    DCAddress := '\\192.168.42.42';
    DCAddressType := DS_INET_ADDRESS;
    DCFlags := $E00013FD;
    DCSiteName := 'Default-First-Site-Name';
    DCClientSiteName := 'Default-First-Site-Name';
    WriteLn('Saving djoin blob with following informations at ', OutputFile);
    Dump;
    SaveToFile(OutputFile);
  finally
    Free;
  end;
end;

begin
  CreateDjoin('djoin.txt');
end.

