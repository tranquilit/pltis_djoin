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

  TCommonTypeHeader = record
    case bool of
      False: (Version: Byte;
             Endianness: Byte;
             Length: UInt16;
             Filler: UInt32;);
      True: (Header: UInt64);
  end;
  PCommonTypeHeader = ^TCommonTypeHeader;

  TPrivateTypeHeader = record
    ObjectBufferLength: UInt32;
    Filler: UInt32;
  end;
  PPrivateTypeHeader = ^TPrivateTypeHeader;

  TRDNPrivateHeader = record
    CommonHeader: TCommonTypeHeader;
    PrivateHeader: TPrivateTypeHeader;
  end;
  PRDNPrivateHeader = ^TRDNPrivateHeader;

  TDJoinString = record
    BuffSize: UInt32;
    BuffOffset: UInt32;
    BuffLen: UInt32;
    Buffer: Char;
  end;
  PDJoinString = ^TDJoinString;

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

    fBufferLength: SizeInt;
    fBinaryContent: RawByteString;

    function GetODJ_PROVISION_DATA_header: PRDNPrivateHeader;
    procedure NextString(var Str: PDJoinString);

    function ConvertString(Str: PDJoinString): RawUtf8;
  public
    constructor Create;

    /// Load a DJoin file in memory
    // - Return true if the file has been successfully loaded
    function LoadFromFile(const Filename: TFileName): boolean;

    /// Unload the current file in memory
    // - Can be called even if no file is loaded
    procedure Unload;

    function StartAddress: Pointer;

    property ODJ_PROVISION_DATA_header: PRDNPrivateHeader read GetODJ_PROVISION_DATA_header;
    property Options: PInt32 read fOptions;
    property BufferLength: SizeInt read fBufferLength;
  end;



implementation

const
  EXPECTED_COMMON_HEADER : UInt64 = $cccccccc00081001;
  OPTIONS_OFFSET = $40;
  GLOBAL_DOMAIN_OFFSET = $b4;
  DNS_POLICY_GUID_OFFSET = $78;

{ TDJoin }

procedure TDJoin.NextString(var Str: PDJoinString);
begin
  Str := Pointer(Str) + 12 + (Str^.BuffLen + (Str^.BuffLen mod 2)) * 2;
end;

function TDJoin.GetODJ_PROVISION_DATA_header: PRDNPrivateHeader;
begin
  Result := StartAddress;
end;

function TDJoin.ConvertString(Str: PDJoinString): RawUtf8;
begin
  // Corrupted
  if (@str^.Buffer > StartAddress + BufferLength) or (@str^.Buffer + str^.BuffLen > StartAddress + BufferLength) then
    Exit;

  Result := RawUnicodeToUtf8(@Str^.Buffer, Str^.BuffLen);
end;

constructor TDJoin.Create;
begin

end;

function TDJoin.LoadFromFile(const Filename: TFileName): boolean;
var
  CurrentStr: PDJoinString;
  Sid: PSid;
  Base64Utf16: RawByteString;
  Base64, guidStr: RawUtf8;
  guid: PGuid;
  temp: TRawSmbiosInfo;
  i: Integer;
begin
  Unload;
  Base64Utf16 := StringFromFile(Filename);
  Base64 := RawUnicodeToUtf8(pointer(Base64Utf16), Length(WideString(Base64Utf16)) div 2 - 1);
  fBinaryContent := Base64toBin(Base64);
  fBufferLength := Length(fBinaryContent);
  FileFromString(fBinaryContent, 'C:\temp\djoin_unix.bin');
  Result := fBinaryContent <> '';

  // Not base64 encoded
  if not Result then
    Exit;

  // Payload length and actual length differs
  if (ODJ_PROVISION_DATA_header^.CommonHeader.Header <> EXPECTED_COMMON_HEADER) or (ODJ_PROVISION_DATA_header^.PrivateHeader.ObjectBufferLength <> BufferLength - sizeof(ODJ_PROVISION_DATA_header^)) then
    Exit(False);

  // File too short to contains the options
  if OPTIONS_OFFSET + sizeof(fOptions^) > BufferLength then
    Exit(False);
  fOptions := StartAddress + OPTIONS_OFFSET;

  // File too short to contains the policy guid
  if DNS_POLICY_GUID_OFFSET + sizeof(guid^) > BufferLength then
    Exit(False);
  guid := StartAddress + DNS_POLICY_GUID_OFFSET;

  // File too short to contains the domain name
  if GLOBAL_DOMAIN_OFFSET + sizeof(TDJoinString) > BufferLength then
    Exit(False);
  CurrentStr := StartAddress + GLOBAL_DOMAIN_OFFSET + 12; /// Not sure about the +12
  WriteLn('Machine Information:');
  WriteLn(' - Domain: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - Computer name: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - Computer password: ', ConvertString(CurrentStr));

  WriteLn(CRLF,'Domain Policy Information:');
  NextString(CurrentStr);
  WriteLn(' - Domain Name: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - DNS Name: ', ConvertString(CurrentStr));

  NextString(CurrentStr);
  WriteLn(' - Forest Name: ', ConvertString(CurrentStr));

  DecodeSmbiosUuid(guid, guidStr, temp);
  WriteLn(' - Domain GUID: ', guidStr);

  NextString(CurrentStr);
  Sid := Pointer(CurrentStr) + 4;

  // File too short to contains the SID informations
  if (Pointer(Sid) > StartAddress + BufferLength) or (@sid^.SubAuthority[sid^.SubAuthorityCount] > StartAddress + BufferLength) then
    Exit(False);
  WriteLn(' - SID: ', SidToText(sid));

  // Too many SID elements
  //if Sid^.Size > MAX_SID_ELEMENTS then
  //  Exit(False);

  Result := True;
end;

procedure TDJoin.Unload;
begin
  fBinaryContent := '';
  fOptions := nil;
end;

function TDJoin.StartAddress: Pointer;
begin
  if fBinaryContent = '' then
    Result := nil
  else
    Result := @fBinaryContent[1];
end;

end.

