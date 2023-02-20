{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit pltis_djoin;

{$warn 5023 off : no warning about unused units}
interface

uses
  uDJoin, uDJoinTypes, uNDRContext, LazarusPackageIntf;

implementation

procedure Register;
begin
end;

initialization
  RegisterPackage('pltis_djoin', @Register);
end.
