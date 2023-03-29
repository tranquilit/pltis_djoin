/// This unit is a part of the Open Source Tranquil IT DJoin,
// licensed under a MPL/GPL/LGPL three license - see LICENSE.md

unit uNDRContext;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.os,
  mormot.core.base;

const
  NDR_Scalar = $1;
  NDR_Buffer = $2;
  NDR_ScalarBuffer = $3;

type
  {$A-} // every record (or object) is packed from now on

  TNDR_Ptr = UInt32;

  TCommonTypeHeader = record
    case Boolean of
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

  TNDRPrivateHeader = record
    CommonHeader: TCommonTypeHeader;
    PrivateHeader: TPrivateTypeHeader;
  end;
  PNDRPrivateHeader = ^TNDRPrivateHeader;

  { TMemoryContext }

  TMemoryContext = object
    fMemory: TRawByteStringDynArray;

    function ItemCount: SizeUInt;
    function GetMem(NbItem: SizeUInt; ItemSize: SizeUint = 1): Pointer;
    function GetZeroedMem(NbItem: SizeUInt; ItemSize: SizeUint = 1): Pointer;
    procedure Clear;
  end;
  PMemoryContext = ^TMemoryContext;

  { TNDRContext }

  TNDRContext = class
  public
    Buffer: RawByteString;
    BufferLength: SizeInt;
    Current: SizeInt;

    constructor Create(Buf: RawByteString; BufLen: SizeInt);

    function StartPtr: Pointer;
    function CurrentPtr: Pointer;
  end;

  { TNDRUnpackContext }

  TNDRUnpackContext = class(TNDRContext)
  private
    fMemoryContext: PMemoryContext;
  public
    constructor Create(Buf: RawByteString; BufLen: SizeInt; MemoryContext: PMemoryContext);

    function Unpack(Size: SizeInt): Pointer;
    procedure UnpackAlign(Size: SizeInt);
    function UnpackHeader: TNDRPrivateHeader;
    function UnpackUInt32: UInt32;
    function UnpackUInt16: UInt16;
    function UnpackPtr: Pointer;
    function UnpackGuid: TGuid;
    function UnpackSidPtr: PSid;
    function UnpackWideStr: WideString;

    property MemoryContext: PMemoryContext read fMemoryContext;
  end;
  PNDR_Context = ^TNDRUnpackContext;

  { TNDRPackContext }

  TNDRPackContext = class(TNDRContext)
  private
    PointerCount: SizeInt;
  public
    constructor Create;

    procedure Padd(Size: SizeInt);
    procedure Pack(Content: Pointer; Len: SizeInt);
    procedure PackHeader(Size: SizeInt);
    procedure PackByte(Value: Byte);
    procedure PackUInt16(Value: UInt16);
    procedure PackUInt32(Value: UInt32);
    procedure PackPtr(Value: Pointer);
    procedure PackGuid(Value: TGuid);
    procedure PackSidPtr(Value: PSid);
    procedure PackWideStr(Value: WideString);
  end;

  { TNDRCustomType }

  generic TNDRCustomType<NDRType> = class
    class procedure NDRUnpack(Ctx: TNDRUnpackContext; var Data: NDRType; NDRFormat: UInt32 = NDR_ScalarBuffer);
    class procedure NDRPack(Ctx: TNDRPackContext; var Data: NDRType; NDRFormat: UInt32 = NDR_ScalarBuffer);
    class function NDRSize(var Data: NDRType; NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;

  { TNDRPointer }

  generic TNDRPointer<NDRType> = object
  type
    PNDRType = ^NDRType;
  public
    p: PNDRType;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    function NDRSize(NDRFormat: UInt32 = NDR_ScalarBuffer): SizeUInt;
  end;

  function NDRSidPtrSize(Sid: PSid): SizeUInt;
  function NDRWideStrSize(WideStr: WideString): SizeUInt;

implementation

uses
  mormot.core.buffers,
  mormot.core.text,
  mormot.core.unicode;

const
  EXPECTED_COMMON_HEADER : UInt64 = $cccccccc00081001;
  COMMON_HEADER_FILLER : UInt32 = $CCCCCCCC;
  PRIVATE_HEADER_FILLER: UInt32 = 0;

function NDRSidPtrSize(Sid: PSid): SizeUInt;
begin
  if not Assigned(Sid) then
    Exit(0);
  Result := 8 + Sizeof(UInt32) * Sid^.SubAuthorityCount;
end;

function NDRWideStrSize(WideStr: WideString): SizeUInt;
var
  SLen: PtrInt;
begin
  SLen := StrLenW(PWideChar(@WideStr[1])) + 1;
  Result := SizeOf(UInt32) * 3 + (SLen + (SLen mod 2))* 2;
end;

{ TMemoryContext }

function TMemoryContext.ItemCount: SizeUInt;
begin
  Result := Length(fMemory);
end;

function TMemoryContext.GetMem(NbItem: SizeUInt; ItemSize: SizeUint): Pointer;
begin
  SetLength(fMemory, ItemCount + 1);
  setLength(fMemory[ItemCount - 1], NbItem * ItemSize);
  Result := @fMemory[ItemCount - 1][1];
end;

function TMemoryContext.GetZeroedMem(NbItem: SizeUInt; ItemSize: SizeUint
  ): Pointer;
begin
  Result := GetMem(NbItem, ItemSize);
  FillZero(Result^, NbItem * ItemSize);
end;

procedure TMemoryContext.Clear;
begin
  SetLength(fMemory, 0);
end;

{ TNDRContext }

constructor TNDRContext.Create(Buf: RawByteString; BufLen: SizeInt);
begin
  Buffer := Buf;
  BufferLength := BufLen;
  Current := 0;
end;

function TNDRContext.StartPtr: Pointer;
begin
  Result := @Buffer[1];
end;

function TNDRContext.CurrentPtr: Pointer;
begin
  Result := StartPtr + Current;
end;

{ TNDRUnpackContext }

constructor TNDRUnpackContext.Create(Buf: RawByteString; BufLen: SizeInt;
  MemoryContext: PMemoryContext);
begin
  inherited Create(Buf, BufLen);
  fMemoryContext := MemoryContext;
end;

function TNDRUnpackContext.UnpackHeader: TNDRPrivateHeader;
begin
  Result := PNDRPrivateHeader(Unpack(SizeOf(Result)))^;
  if not  ((Result.CommonHeader.Header = EXPECTED_COMMON_HEADER) and
           (Result.PrivateHeader.ObjectBufferLength <= BufferLength - sizeof(Result)) and
           (Result.PrivateHeader.Filler = PRIVATE_HEADER_FILLER)) then
    raise Exception.CreateFmt('Invalid Custom NDR Header at 0x%x', [Current - SizeOf(Result)]);
end;

function TNDRUnpackContext.Unpack(Size: SizeInt): Pointer;
begin
  Result := CurrentPtr;
  Inc(Current, Size);
  if Current > BufferLength then
    raise Exception.Create('NDR context out of bounds');
end;

procedure TNDRUnpackContext.UnpackAlign(Size: SizeInt);
begin
  Current := (Current + Size - 1) and (not (Size - 1));
end;

function TNDRUnpackContext.UnpackUInt32: UInt32;
begin
  Result := PUInt32(Unpack(SizeOf(UInt32)))^;
end;

function TNDRUnpackContext.UnpackUInt16: UInt16;
begin
 Result := PUInt16(Unpack(SizeOf(UInt16)))^;
end;

function TNDRUnpackContext.UnpackPtr: Pointer;
begin
  /// Pointers value must not be used as pointer
  // The only test must be whether they are nil or not
  Result := Pointer(UnpackUInt32);
end;

function TNDRUnpackContext.UnpackGuid: TGuid;
begin
  Result := PGuid(Unpack(SizeOf(TGuid)))^;
end;

function TNDRUnpackContext.UnpackSidPtr: PSid;
var
  NbAuth, Len: UInt32;
begin
  NbAuth := UnpackUInt32;
  Len := 8 + Sizeof(UInt32) * NbAuth;
  Result := MemoryContext^.GetMem(Len);
  Move(PSid(Unpack(Len))^, Result^, Len);
end;

function TNDRUnpackContext.UnpackWideStr: WideString;
var
  Len: UInt32;
begin
  // Length
  UnpackUInt32;
  // Always 0
  UnpackUInt32;
  // MaxLength
  Len := UnpackUInt32;
  Len := Len + (Len mod 2);

  SetLength(Result, Len);
  Move(PWideChar(Unpack(Len * 2))^, Result[1], Len * 2);
end;

{ TNDRPackContext }

constructor TNDRPackContext.Create;
begin
  inherited Create('', 0);
end;

procedure TNDRPackContext.Padd(Size: SizeInt);
var
  i: Integer;
begin
  for i := 0 to Size - 1 do
    PackByte(0);
end;

procedure TNDRPackContext.Pack(Content: Pointer; Len: SizeInt);
begin
  Append(Buffer, Content, Len);
  Inc(BufferLength, Len);
end;

procedure TNDRPackContext.PackHeader(Size: SizeInt);
var
  Header: TNDRPrivateHeader;
begin
  Header.CommonHeader.Version := 1;
  Header.CommonHeader.Endianness := $10;
  Header.CommonHeader.Length := 8;
  Header.CommonHeader.Filler := COMMON_HEADER_FILLER;

  Header.PrivateHeader.ObjectBufferLength := Size;
  Header.PrivateHeader.Filler := PRIVATE_HEADER_FILLER;
  Pack(@Header, SizeOf(Header));
end;

procedure TNDRPackContext.PackByte(Value: Byte);
begin
  Pack(@Value, SizeOf(Value));
end;

procedure TNDRPackContext.PackUInt16(Value: UInt16);
begin
  Pack(@Value, SizeOf(Value));
end;

procedure TNDRPackContext.PackUInt32(Value: UInt32);
begin
  Pack(@Value, SizeOf(Value));
end;

procedure TNDRPackContext.PackPtr(Value: Pointer);
var
  PtrVal: UInt32;
begin
  PtrVal := 0;
  if Assigned(Value) then
  begin
    PtrVal := (PointerCount * 4) or $00020000;
    Inc(PointerCount);
  end;
  PackUInt32(PtrVal);
end;

procedure TNDRPackContext.PackGuid(Value: TGuid);
begin
  Pack(@Value, SizeOf(Value));
end;

procedure TNDRPackContext.PackSidPtr(Value: PSid);
var
  Len: UInt32;
begin
  Len := 8 + Sizeof(UInt32) * Value^.SubAuthorityCount;
  PackUInt32(Value^.SubAuthorityCount);
  Pack(Value, Len);
end;

procedure TNDRPackContext.PackWideStr(Value: WideString);
var
  StringLength: PtrInt;
begin
  StringLength := StrLenW(PWideChar(@Value[1])) + 1;

  PackUInt32(StringLength);
  PackUInt32(0);
  PackUInt32(StringLength);
  Pack(@Value[1], StringLength * 2);
  if (StringLength mod 2) > 0 then
    PackUInt16(0);
end;

{ TNDRCustomType }

class procedure TNDRCustomType.NDRUnpack(Ctx: TNDRUnpackContext;
  var Data: NDRType; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.UnpackHeader;
    // Object pointer
    Data.NDRUnpack(Ctx, NDR_ScalarBuffer);
  end;
end;

class procedure TNDRCustomType.NDRPack(Ctx: TNDRPackContext; var Data: NDRType;
  NDRFormat: UInt32);
var
  PreviousPtrCount, DataSize, PaddingBytes: SizeInt;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    DataSize := Data.NDRSize(NDR_ScalarBuffer);
    PaddingBytes := DataSize mod 8;
    Inc(DataSize, PaddingBytes);
    Ctx.PackHeader(DataSize);
    PreviousPtrCount := Ctx.PointerCount;
    Ctx.PointerCount := 0;
    Data.NDRPack(Ctx, NDR_ScalarBuffer);
    Ctx.Padd(PaddingBytes); // Align on 0x8
    Ctx.PointerCount := PreviousPtrCount;
  end;
end;

class function TNDRCustomType.NDRSize(var Data: NDRType; NDRFormat: UInt32
  ): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Inc(Result, SizeOf(TNDRPrivateHeader));
    Inc(Result, Data.NDRSize(NDR_ScalarBuffer));
    Inc(Result, Result mod 8); // Align on 0x8
  end;
end;

{ TNDRPointer }

procedure TNDRPointer.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
    p := Ctx.UnpackPtr;

  if (NDRFormat and NDR_Buffer) > 0 then
  begin
    if Assigned(p) then
    begin
      p := Ctx.MemoryContext^.GetZeroedMem(SizeOf(p^));
      p^.NDRUnpack(Ctx, NDR_ScalarBuffer);
    end;
  end;
end;

procedure TNDRPointer.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
    Ctx.PackPtr(p);

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(p) then
      p^.NDRPack(Ctx, NDR_ScalarBuffer);
end;

function TNDRPointer.NDRSize(NDRFormat: UInt32): SizeUInt;
begin
  Result := 0;

  if (NDRFormat and NDR_Scalar) > 0 then
    Inc(Result, SizeOf(p));

  if (NDRFormat and NDR_Buffer) > 0 then
    if Assigned(p) then
      Inc(Result, p^.NDRSize(NDR_ScalarBuffer));
end;

end.

