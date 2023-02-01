unit uDJoin;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.os,
  mormot.core.buffers,
  mormot.core.unicode, mormot.core.base;

const
  MAX_SID_ELEMENTS = 10;

type
  {$A-} // every record (or object) is packed from now on

  TDJoinSectionHeader = record
    Version: UInt64;
    PayloadLength: UInt64;
  end;
  PDJoinSectionHeader = ^TDJoinSectionHeader;

  TDJoinString = record
    BuffSize: UInt32;
    BuffOffset: UInt32;
    BuffLen: UInt32;
    Buffer: Char;
  end;
  PDJoinString = ^TDJoinString;

  TDJoinSID = record
    Header: UInt32;
    Size: UInt32;
    Data: array [0..MAX_SID_ELEMENTS - 1] of UInt32;
  end;
  PDJoinSID = ^TDJoinSID;

  TMagicDecoder = record
    case longint of
    0: (ui64: UInt64);
    1: (ui32_1, ui32_2: UInt32);
    2: (ui16_1, ui16_2, ui16_3, ui16_4: UInt16);
    3: (bytes: array [0 .. 7] of Byte);
  end;
  PMagicDecoder = ^TMagicDecoder;

  { TDJoin }

  TDJoin = class
  private
    fOptions: PInt32;

    fBinaryContent: RawByteString;

    procedure NextString(var Str: PDJoinString);

    function ConvertString(Str: PDJoinString; BuffLen: SizeInt): RawUtf8;
  public
    constructor Create;

    /// Load a DJoin file in memory
    // - Return true if the file has been successfully loaded
    function LoadFromFile(const Filename: TFileName): boolean;

    /// Unload the current file in memory
    // - Can be called even if no file is loaded
    procedure Unload;

    function StartAddress: Pointer;
    property Options: PInt32 read fOptions;
  end;



implementation

const
  EXPECTED_VERSION : UInt64 = $cccccccc00081001;
  OPTIONS_OFFSET = $40;
  GLOBAL_DOMAIN_OFFSET = $b4;
  DNS_POLICY_GUID_OFFSET = $6c;

{ TDJoin }

procedure TDJoin.NextString(var Str: PDJoinString);
begin
  Str := Pointer(Str) + 12 + (Str^.BuffLen + (Str^.BuffLen mod 2)) * 2;
end;

function TDJoin.ConvertString(Str: PDJoinString; BuffLen: SizeInt): RawUtf8;
var
  Res: RawUtf8;
begin
  // Corrupted
  if (@str^.Buffer > StartAddress + BuffLen) or (@str^.Buffer + str^.BuffLen > StartAddress + BuffLen) then
    Exit;

  Result := RawUnicodeToUtf8(@Str^.Buffer, Str^.BuffLen);
end;

constructor TDJoin.Create;
begin

end;

function TDJoin.LoadFromFile(const Filename: TFileName): boolean;
var
  Header: PDJoinSectionHeader;
  CurrentStr: PDJoinString;
  Sid: PDJoinSID;
  BuffLen: SizeInt;
  Base64Utf16: RawByteString;
  Base64, guidStr: RawUtf8;
  guid: PGuid;
  temp: TRawSmbiosInfo;
begin
  Unload;
  Base64Utf16 := StringFromFile(Filename);
  Base64 := RawUnicodeToUtf8(pointer(Base64Utf16), Length(WideString(Base64Utf16)) div 2 - 1);
  fBinaryContent := Base64toBin(Base64);
  FileFromString(fBinaryContent, 'C:\temp\djoin.bin');
  BuffLen := Length(fBinaryContent);
  Result := fBinaryContent <> '';

  // Not base64 encoded
  if not Result then
    Exit;

  Header := StartAddress;
  // Payload length and actual length differs
  if (Header^.Version <> EXPECTED_VERSION) or (Header^.PayloadLength <> BuffLen - sizeof(Header^)) then
    Exit(False);

  // File too short to contains the options
  if OPTIONS_OFFSET + sizeof(fOptions^) > BuffLen then
    Exit(False);
  fOptions := StartAddress + OPTIONS_OFFSET;

  // File too short to contains the policy guid
  if DNS_POLICY_GUID_OFFSET + sizeof(guid^) > BuffLen then
    Exit(False);
  WriteLn(sizeof(guid^));
  guid := StartAddress + DNS_POLICY_GUID_OFFSET;

  // File too short to contains the domain name
  if GLOBAL_DOMAIN_OFFSET + sizeof(TDJoinString) > BuffLen then
    Exit(False);
  CurrentStr := StartAddress + GLOBAL_DOMAIN_OFFSET + 12; /// Not sure about the +12
  WriteLn('Machine Information:');
  WriteLn(' - Domain: ', ConvertString(CurrentStr, BuffLen));

  NextString(CurrentStr);
  WriteLn(' - Computer name: ', ConvertString(CurrentStr, BuffLen));

  NextString(CurrentStr);
  WriteLn(' - Computer password: ', ConvertString(CurrentStr, BuffLen));

  WriteLn(CRLF,'Domain Policy Information:');
  NextString(CurrentStr);
  WriteLn(' - Domain Name: ', ConvertString(CurrentStr, BuffLen));

  NextString(CurrentStr);
  WriteLn(' - DNS Name: ', ConvertString(CurrentStr, BuffLen));

  NextString(CurrentStr);
  WriteLn(' - Forest Name: ', ConvertString(CurrentStr, BuffLen));

  DecodeSmbiosUuid(guid, guidStr, temp);
  WriteLn(' - Domain GUID: ', guidStr);
            //($01714198) + 12 + 28    -> + 40 0x28
  NextString(CurrentStr);
  Sid := Pointer(CurrentStr);
  Sid := Pointer(CurrentStr) + 4;

  // File too short to contains the SID informations
  if (Pointer(Sid) > StartAddress + BuffLen) or (@sid^.Data[0] > StartAddress + BuffLen) then
    Exit(False);

  // Too many SID elements
  if Sid^.Size > MAX_SID_ELEMENTS then
    Exit(False);

  Result := True;
end;

procedure TDJoin.Unload;
begin
  fBinaryContent := '';
  fOptions := nil;
end;

function TDJoin.StartAddress: Pointer;
begin
  Result := @fBinaryContent[1];
end;

end.

