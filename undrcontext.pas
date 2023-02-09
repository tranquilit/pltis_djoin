unit uNDRContext;

{$mode ObjFPC}{$H+}

interface

uses
  Classes,
  SysUtils,
  mormot.core.os;

const
  NDR_Scalar = $1;
  NDR_Buffer = $2;
  NDR_ScalarBuffer = $3;

type
  {$A-} // every record (or object) is packed from now on

  TNDR_Ptr = UInt32;

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

  TNDRPrivateHeader = record
    CommonHeader: TCommonTypeHeader;
    PrivateHeader: TPrivateTypeHeader;
  end;
  PNDRPrivateHeader = ^TNDRPrivateHeader;

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
  public
    constructor Create(Buf: RawByteString; BufLen: SizeInt);

    function Unpack(Size: SizeInt): Pointer;
    procedure UnpackAlign(Size: SizeInt);
    function UnpackHeader: TNDRPrivateHeader;
    function UnpackUInt32: UInt32;
    function UnpackUInt16: UInt16;
    function UnpackPtr: Pointer;
    function UnpackGuid: TGuid;
    function UnpackSidPtr: PSid;
    function UnpackWideStr: WideString;
  end;
  PNDR_Context = ^TNDRUnpackContext;

  { TNDRPackContext }

  TNDRPackContext = class(TNDRContext)
  private
    PointerCount: SizeInt;
  public
    constructor Create;

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
  end;

  { TNDRPointer }

  generic TNDRPointer<NDRType> = object
    p: NDRType;

    procedure NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
    procedure NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32 = NDR_ScalarBuffer);
  end;

implementation

uses
  mormot.core.buffers,
  mormot.core.unicode,
  mormot.core.base;

const
  EXPECTED_COMMON_HEADER : UInt64 = $cccccccc00081001;
  COMMON_HEADER_FILLER : UInt32 = $CCCCCCCC;
  PRIVATE_HEADER_FILLER: UInt32 = 0;

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

constructor TNDRUnpackContext.Create(Buf: RawByteString; BufLen: SizeInt);
begin
  inherited Create(Buf, BufLen);
end;

function TNDRUnpackContext.UnpackHeader: TNDRPrivateHeader;
var
  Header: PNDRPrivateHeader;
  Valid: Boolean;
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
  /// TO FREE
  Result := GetMem(Len);
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

procedure TNDRPackContext.Pack(Content: Pointer; Len: SizeInt);
begin
  AppendBufferToRawByteString(Buffer, Content^, Len);
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
  BufferLen: SizeInt;
  StringLength: PtrInt;
begin
  BufferLen := Length(Value);
  StringLength := StrLenW(PWideChar(@Value[1])) + 1;

  PackUInt32(StringLength);
  PackUInt32(0);
  PackUInt32(StringLength);
  Pack(@Value[1], BufferLen * 2);
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
  PreviousOffset: SizeInt;
  SubCtx: TNDRPackContext;
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    PreviousOffset := Ctx.Current;
    SubCtx := TNDRPackContext.Create;
    try
      Data.NDRPack(SubCtx, NDR_ScalarBuffer);
      Ctx.PackHeader(SubCtx.BufferLength);
      Ctx.Pack(SubCtx.StartPtr, SubCtx.BufferLength);
    finally
      SubCtx.Free;
    end;
  end;
end;

{ TNDRPointer }

procedure TNDRPointer.NDRUnpack(Ctx: TNDRUnpackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    if Assigned(Ctx.UnpackPtr) then
      p.NDRUnpack(Ctx, NDR_ScalarBuffer);
  end;
end;

procedure TNDRPointer.NDRPack(Ctx: TNDRPackContext; NDRFormat: UInt32);
begin
  if (NDRFormat and NDR_Scalar) > 0 then
  begin
    Ctx.PackPtr(@p);
    p.NDRPack(Ctx, NDR_ScalarBuffer);
  end;
end;

end.

