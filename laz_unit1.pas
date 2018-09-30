unit laz_unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  decutil, deccipher, dechash, decfmt;

type

  { TForm1 }

  TForm1 = class(TForm)
    Button1: TButton;
    Button2: TButton;
    Edit1: TEdit;
    Label1: TLabel;
    Memo1: TMemo;
    Memo2: TMemo;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
  private

  public

  end;

var
  Form1: TForm1;
   ACipherClass: TDECCipherClass = TCipher_Rijndael;
  ACipherMode: TCipherMode = cmCBCx;
  AHashClass: TDECHashClass = THash_sha256;
  ATextFormat: TDECFormatClass = TFormat_Mime64;
  AKDFIndex: LongWord = 1;

implementation

{$R *.lfm}
function Encrypt(const AText: wideString; const APassword: wideString): wideString; overload;
var
  ASalt: Binary;
  AData: Binary;
  APass: Binary;
begin
  with ValidCipher(ACipherClass).Create, Context do
    try
      ASalt := RandomBinary(16);
      APass := ValidHash(AHashClass).KDFx(APassword[1], Length(APassword) * SizeOf(APassword[1]), ASalt[1],
        Length(ASalt), KeySize, TFormat_Copy, AKDFIndex);
      Mode := ACipherMode;
      Init(APass);
      SetLength(AData, Length(AText) * SizeOf(AText[1]));
      Encode(AText[1], AData[1], Length(AData));
      Result := ValidFormat(ATextFormat).Encode(ASalt + AData + CalcMAC);
    finally
      Free;
      ProtectBinary(ASalt);
      ProtectBinary(AData);
      ProtectBinary(APass);
    end;
end;

function Decrypt(const AText: WideString; const APassword: WideString): WideString; overload;
var
  ASalt: Binary;
  AData: Binary;
  ACheck: Binary;
  APass: Binary;
  ALen: integer;
begin
  with ValidCipher(ACipherClass).Create, Context do
    try
      ASalt := ValidFormat(ATextFormat).Decode(AText);
      ALen := Length(ASalt) - 16 - BufferSize;
      AData := System.Copy(ASalt, 17, ALen);
      ACheck := System.Copy(ASalt, ALen + 17, BufferSize);
      SetLength(ASalt, 16);
      APass := ValidHash(AHashClass).KDFx(APassword[1], Length(APassword) * SizeOf(APassword[1]), ASalt[1],
        Length(ASalt), KeySize, TFormat_Copy, AKDFIndex);
      Mode := ACipherMode;
      Init(APass);
      SetLength(Result, ALen div SizeOf(AText[1]));
      Decode(AData[1], Result[1], ALen);
      if ACheck <> CalcMAC then
        raise Exception.Create('Invalid data ....');
    finally
      Free;
      ProtectBinary(ASalt);
      ProtectBinary(AData);
      ProtectBinary(ACheck);
      ProtectBinary(APass);
    end;
end;

{ TForm1 }

procedure TForm1.Button1Click(Sender: TObject);
var
s,k:ansistring;
begin
 s:=memo1.Text;
 k:=edit1.text;
 memo2.Text:=encrypt(s,k);
 memo1.Clear;

end;

procedure TForm1.Button2Click(Sender: TObject);
var
s,k:ansistring;
begin
s:=memo2.Text;
k:=edit1.text;
memo1.Text:=decrypt(s,k);
memo2.Clear;

end;


end.

