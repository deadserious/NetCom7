unit ufrmMain;

interface

uses
{$IFDEF MSWINDOWS}
  WinApi.Windows, WinApi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, Vcl.Forms, Vcl.Controls, Vcl.StdCtrls,
  Vcl.ExtCtrls, Vcl.Samples.Spin, Vcl.Graphics, Vcl.Imaging.jpeg,
  System.Diagnostics, System.SyncObjs, ncLines, ncUDPSocketsDual, ncIPUtils;

type
  TForm1 = class(TForm)
    memLog: TMemo;
    pnlToolbar: TPanel;
    btnActivate: TButton;
    pnlAddress: TPanel;
    edtHost: TEdit;
    edtPort: TSpinEdit;
    Panel1: TPanel;
    btnSendData: TButton;
    Panel2: TPanel;
    edtDataToSend: TEdit;
    Panel3: TPanel;
    btnSendCommand: TButton;
    Panel4: TPanel;
    edtCommandData: TEdit;
    Panel6: TPanel;
    btnSendScreenshot: TButton;
    UDPClient: TncUDPClientDual;

    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnActivateClick(Sender: TObject);
    procedure edtHostChange(Sender: TObject);
    procedure edtPortChange(Sender: TObject);
    procedure edtDataToSendEnter(Sender: TObject);
    procedure edtDataToSendExit(Sender: TObject);
    procedure Log(const AMessage: string);
    procedure memLogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure btnSendDataClick(Sender: TObject);
    procedure btnSendCommandClick(Sender: TObject);
    procedure btnSendScreenshotClick(Sender: TObject);
    procedure UDPClientReadDatagram(Sender: TObject; aLine: TncLine;
      const aBuf: TBytes; aBufCount: Integer;
      const SenderAddr: TSockAddrStorage);
    procedure UDPClientCommand(Sender: TObject; aLine: TncLine;
      const aSenderAddr: TSockAddrStorage; aCmd: Integer; const aData: TBytes;
      aFlags: Byte; aSequence: UInt16);

  private
    FCommandParser: TStringList;
    FCommandLock: TCriticalSection;
    function CaptureScreenshot: TBytes;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function TForm1.CaptureScreenshot: TBytes;
var
  DC: HDC;
  ScreenBMP: TBitmap;
  jpgImage: TJPEGImage;
  MS: TMemoryStream;
begin
  Result := nil;

  // Create required objects for screen capture
  ScreenBMP := TBitmap.Create;
  jpgImage := TJPEGImage.Create;
  MS := TMemoryStream.Create;
  try
    // Set bitmap dimensions to match screen resolution
    ScreenBMP.Width := Screen.Width;
    ScreenBMP.Height := Screen.Height;

    // Get device context for the entire screen (0 = desktop window)
    DC := GetDC(0);
    try
      // Copy screen pixels to bitmap using BitBlt
      BitBlt(ScreenBMP.Canvas.Handle, 0, 0, Screen.Width,
        Screen.Height, DC, 0, 0, SRCCOPY);
    finally
      ReleaseDC(0, DC);
    end;

    // Convert to JPEG with 30% quality for network efficiency
    jpgImage.Assign(ScreenBMP);
    jpgImage.CompressionQuality := 30;
    jpgImage.SaveToStream(MS);

    // Return JPEG data
    MS.Position := 0;
    SetLength(Result, MS.Size);
    if MS.Size > 0 then
      MS.ReadBuffer(Result[0], MS.Size);

    Log(Format('Screenshot captured: %d bytes', [Length(Result)]));

  finally
    ScreenBMP.Free;
    jpgImage.Free;
    MS.Free;
  end;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  // Initialize command parsing structures
  FCommandParser := TStringList.Create;
  FCommandParser.Delimiter := '|';
  FCommandParser.StrictDelimiter := True;
  FCommandLock := TCriticalSection.Create;

  // Initialize controls
  edtCommandData.Text := 'Hello Server!';
  edtHost.Text := '127.0.0.1';
  edtPort.Value := 16233;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  UDPClient.Active := False;
  
  if Assigned(FCommandParser) then
    FCommandParser.Free;
  if Assigned(FCommandLock) then
    FCommandLock.Free;
end;

procedure TForm1.btnActivateClick(Sender: TObject);
begin
  if UDPClient.Active then
  begin
    UDPClient.Active := False;
    btnActivate.Caption := 'Start UDP Client';
    Log('UDP Client Deactivated');
  end
  else
  begin
    if Trim(edtHost.Text) = '' then
    begin
      Log('Host field cannot be blank.');
      Exit;
    end;

    try
      UDPClient.Host := edtHost.Text;
      UDPClient.Port := edtPort.Value;
      UDPClient.Active := True;
      btnActivate.Caption := 'Stop UDP Client';
      Log('UDP Client Activated');
    except
      on E: Exception do
        Log('Failed to activate UDP Client: ' + E.Message);
    end;
  end;
end;

procedure TForm1.edtHostChange(Sender: TObject);
begin
  try
    UDPClient.Host := edtHost.Text;
  except
    edtHost.OnChange := nil;
    try
      edtHost.Text := UDPClient.Host;
    finally
      edtHost.OnChange := edtHostChange;
    end;
    raise;
  end;
end;

procedure TForm1.edtPortChange(Sender: TObject);
begin
  try
    UDPClient.Port := edtPort.Value;
  except
    edtPort.OnChange := nil;
    try
      edtPort.Value := UDPClient.Port;
    finally
      edtPort.OnChange := edtPortChange;
    end;
    raise;
  end;
end;

procedure TForm1.edtDataToSendEnter(Sender: TObject);
begin
  btnSendData.Default := True;
end;

procedure TForm1.edtDataToSendExit(Sender: TObject);
begin
  btnSendData.Default := False;
end;

procedure TForm1.btnSendDataClick(Sender: TObject);
begin
  try
    if not UDPClient.Active then
    begin
      Log('Cannot send - client not active');
      Exit;
    end;

    if Trim(edtDataToSend.Text) = '' then
    begin
      Log('Cannot send - Data field cannot be blank.');
      Exit;
    end;

    UDPClient.Send(edtDataToSend.Text);
    Log(Format('[RAW DATA] Sent: %s', [edtDataToSend.Text]));
  except
    on E: Exception do
      Log('Error sending: ' + E.Message);
  end;
end;

procedure TForm1.btnSendCommandClick(Sender: TObject);
var
  CommandData: TBytes;
begin
  try
    if not UDPClient.Active then
    begin
      Log('Cannot send command - client not active');
      Exit;
    end;

    if Trim(edtCommandData.Text) <> '' then
      CommandData := BytesOf(edtCommandData.Text)
    else
      SetLength(CommandData, 0);

    UDPClient.SendCommand(0, BytesOf('MSG|') + CommandData);

  except
    on E: Exception do
      Log('Error sending command: ' + E.Message);
  end;
end;

procedure TForm1.btnSendScreenshotClick(Sender: TObject);
var
  ScreenshotData: TBytes;
begin
  try
    if not UDPClient.Active then
    begin
      Log('Cannot send screenshot - client not active');
      Exit;
    end;

    Log('Capturing screenshot...');
    ScreenshotData := CaptureScreenshot;
    
    if Length(ScreenshotData) = 0 then
    begin
      Log('Failed to capture screenshot');
      Exit;
    end;

    UDPClient.SendCommand(0, BytesOf('ScreenShot|') + ScreenshotData);

    Log('SEND SCREENSHOT')

  except
    on E: Exception do
      Log('Error sending screenshot: ' + E.Message);
  end;
end;

procedure TForm1.UDPClientCommand(Sender: TObject; aLine: TncLine;
  const aSenderAddr: TSockAddrStorage; aCmd: Integer; const aData: TBytes;
  aFlags: Byte; aSequence: UInt16);
var
  SenderIP: string;
  DataStr: string;
  CommandName: string;
begin
  try
    SenderIP := TncIPUtils.GetIPFromStorage(aSenderAddr);
  except
    on E: EIPError do
      SenderIP := Format('Invalid Address: %s', [E.Message]);
  end;

  if Length(aData) > 0 then
    DataStr := StringOf(aData)
  else
    DataStr := '(no data)';

  // Parse command using same logic as TCP demo
  FCommandLock.Enter;
  try
    FCommandParser.Clear;
    FCommandParser.DelimitedText := DataStr;

    if FCommandParser.Count > 0 then
    begin
      CommandName := FCommandParser[0];
      
      // Handle different commands
      if CommandName = 'TITLE' then
      begin
        if FCommandParser.Count > 1 then
        begin
          Self.Caption := FCommandParser[1];
          Log(Format('[COMMAND] Title changed to: %s', [FCommandParser[1]]));
        end;
      end
      else
      begin
        Log(Format('[COMMAND] Received from %s: %s', [SenderIP, CommandName]));
      end;
    end
    else
    begin
      Log(Format('[COMMAND] Received from %s: ID=%d, Data=%s, Flags=%d, Seq=%d', 
        [SenderIP, aCmd, DataStr, aFlags, aSequence]));
    end;
  finally
    FCommandLock.Leave;
  end;
end;

procedure TForm1.UDPClientReadDatagram(Sender: TObject; aLine: TncLine;
  const aBuf: TBytes; aBufCount: Integer; const SenderAddr: TSockAddrStorage);
var
  ReceivedData: string;
  SenderIP: string;
begin
  ReceivedData := StringOf(Copy(aBuf, 0, aBufCount));

  try
    SenderIP := TncIPUtils.GetIPFromStorage(SenderAddr);
  except
    on E: EIPError do
      SenderIP := Format('Invalid Address: %s', [E.Message]);
  end;

  Log(Format('[RAW DATA] Received from %s: %s', [SenderIP, ReceivedData]));
end;

procedure TForm1.Log(const AMessage: string);
begin
  TThread.Queue(nil,
    procedure
    begin
      try
        memLog.Lines.Add(Format('[%s] %s', [FormatDateTime('hh:nn:ss.zzz', Now), AMessage]));
      finally
      end;
    end);
end;

procedure TForm1.memLogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
begin
  if (Shift = [ssCtrl]) and (Key = Ord('A')) then
    memLog.SelectAll
  else if (Shift = [ssCtrl]) and (Key = Ord('C')) then
    memLog.CopyToClipboard;
end;

end. 