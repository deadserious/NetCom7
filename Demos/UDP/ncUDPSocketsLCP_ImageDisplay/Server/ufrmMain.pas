unit ufrmMain;

interface

uses
{$IFDEF MSWINDOWS}
  WinApi.Windows, WinApi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, System.Math, Vcl.Forms, Vcl.Controls, Vcl.StdCtrls,
  Vcl.ExtCtrls, Vcl.Samples.Spin, Vcl.Graphics, Vcl.Imaging.jpeg,
  System.Diagnostics, System.SyncObjs, ncLines, ncIPUtils,
  ncUDPSocketsLCP;

type
  TForm1 = class(TForm)
    memLog: TMemo;
    pnlToolbar: TPanel;
    btnActivate: TButton;
    pblPort: TPanel;
    edtPort: TSpinEdit;
    Panel1: TPanel;
    btnSendCommand: TButton;
    Panel2: TPanel;
    edtCommandData: TEdit;
    Label1: TLabel;
    Image1: TImage;
    UDPServer: TncUDPServerLCP;
    
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnActivateClick(Sender: TObject);
    procedure Log(const AMessage: string);
    procedure memLogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure edtPortChange(Sender: TObject);
    procedure btnSendCommandClick(Sender: TObject);
    procedure UDPServerCommand(Sender: TObject; aLine: TncLine;
      const aSenderAddr: TSockAddrStorage; aCmd: Integer; const aData: TBytes;
      aFlags: Byte; aSequence: UInt16);

  private
    FCommandParser: TStringList;
    FCommandLock: TCriticalSection;
    FLastClientAddr: TSockAddrStorage;
    FHasLastClient: Boolean;
    
    procedure DisplayScreenShot(const aData: TBytes);
    procedure SendCommandToLastClient(const AMessage: string);
  public
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

procedure TForm1.FormCreate(Sender: TObject);
begin
  // Initialize command parsing structures
  FCommandParser := TStringList.Create;
  FCommandParser.Delimiter := '|';
  FCommandParser.StrictDelimiter := True;
  FCommandLock := TCriticalSection.Create;
  
  // Initialize client tracking
  FHasLastClient := False;
  
  // Initialize image display
  Image1.Picture.Bitmap.SetSize(Image1.Width, Image1.Height);
  Image1.Picture.Bitmap.Canvas.Brush.Color := clBlack;
  Image1.Picture.Bitmap.Canvas.FillRect(Rect(0, 0, Image1.Width, Image1.Height));
  
  edtCommandData.Text := 'TITLE|New Window Title';
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  UDPServer.Active := False;
  
  if Assigned(FCommandParser) then
    FCommandParser.Free;
  if Assigned(FCommandLock) then
    FCommandLock.Free;
end;

procedure TForm1.btnActivateClick(Sender: TObject);
begin
  if UDPServer.Active then
  begin
    UDPServer.Active := False;
    btnActivate.Caption := 'Start UDP Server';
    Log('UDP Server Deactivated');
  end
  else
  begin
    try
      UDPServer.Port := edtPort.Value;
      UDPServer.Active := True;
      btnActivate.Caption := 'Stop UDP Server';
      Log('UDP Server Activated on port ' + IntToStr(edtPort.Value));
    except
      on E: Exception do
        Log('Failed to activate UDP Server: ' + E.Message);
    end;
  end;
end;

procedure TForm1.edtPortChange(Sender: TObject);
begin
  try
    UDPServer.Port := edtPort.Value;
  except
    edtPort.OnChange := nil;
    try
      edtPort.Value := UDPServer.Port;
    finally
      edtPort.OnChange := edtPortChange;
    end;
    raise;
  end;
end;

procedure TForm1.btnSendCommandClick(Sender: TObject);
begin
  if not FHasLastClient then
  begin
    Log('No client available - receive a packet from a client first');
    Exit;
  end;
  
  if Trim(edtCommandData.Text) = '' then
  begin
    Log('Command data cannot be blank');
    Exit;
  end;
  
  SendCommandToLastClient(edtCommandData.Text);
end;

procedure TForm1.SendCommandToLastClient(const AMessage: string);
var
  ClientIP: string;
begin
  if not UDPServer.Active then
    Exit;

  if not FHasLastClient then
  begin
    Log('No client address available');
    Exit;
  end;

  try
    ClientIP := TncIPUtils.GetIPFromStorage(FLastClientAddr);
    UDPServer.SendCommand(FLastClientAddr, 0, BytesOf(AMessage));
    Log(Format('[COMMAND] Sent to %s: %s', [ClientIP, AMessage]));
  except
    on E: Exception do
      Log('Error sending command: ' + E.Message);
  end;
end;

procedure TForm1.UDPServerCommand(Sender: TObject; aLine: TncLine; const aSenderAddr: TSockAddrStorage; aCmd: Integer; const aData: TBytes; aFlags: Byte; aSequence: UInt16);
var
  SenderIP: string;
begin
  try
    // Get sender IP for logging
    SenderIP := TncIPUtils.GetIPFromStorage(aSenderAddr);
    
    // Store last client info for sending commands back
    FLastClientAddr := aSenderAddr;
    FHasLastClient := True;

    // Log command reception with size info
    Log(Format('[COMMAND] Received from %s: Cmd=%d, DataSize=%d bytes, Flags=%d, Seq=%d', 
      [SenderIP, aCmd, Length(aData), aFlags, aSequence]));

    // Parse command data as string for processing
    var DataStr: string;
    if Length(aData) > 0 then
      DataStr := StringOf(aData)
    else
      DataStr := '';

    FCommandLock.Enter;
    try
      FCommandParser.Clear;
      FCommandParser.DelimitedText := DataStr;

      if FCommandParser.Count > 0 then
      begin
        var CommandName := FCommandParser[0];
        
        ////////////////////////////////////////////////////////////////////////////////
        /// Handle command ScreenShot (client sending image)
        ////////////////////////////////////////////////////////////////////////////////
      if CommandName = 'ScreenShot' then
      begin

        if FCommandParser.Count > 1 then
        begin

          TThread.Queue(nil,
            procedure
            var
              imageData: TBytes;
            begin
              try
                // Extract image data from command - skip "ScreenShot|" (10 bytes)
                // aData contains: "ScreenShot|" + JPEG binary data
                imageData := Copy(aData, 11, Length(aData));

                Form1.DisplayScreenShot(imageData);

                Log('RECEIVE SCREENSHOT');

                // Send acknowledgment back to client
                UDPServer.SendCommand(aSenderAddr, 0, BytesOf('TITLE|Screenshot Received!'));

              except
                on E: Exception do
                begin
                  Log(Format('[%s] Error processing screenshot: %s', [TimeToStr(Now), E.Message]));
                end;
              end;
            end);
        end
      end
        ////////////////////////////////////////////////////////////////////////////////
        /// Handle command TITLE (changing client window title)
        ////////////////////////////////////////////////////////////////////////////////
        else if CommandName = 'TITLE' then
        begin
          if FCommandParser.Count > 1 then
          begin
            Log(Format('[TITLE] Setting title from %s: %s', [SenderIP, FCommandParser[1]]));
            TThread.Queue(nil, procedure
            begin
              Caption := FCommandParser[1];
            end);
          end;
        end
        ////////////////////////////////////////////////////////////////////////////////
        /// Handle command MSG (general message)
        ////////////////////////////////////////////////////////////////////////////////
        else if CommandName = 'MSG' then
        begin
          if FCommandParser.Count > 1 then
          begin
            Log(Format('[MSG] Message from %s: %s', [SenderIP, FCommandParser[1]]));
          end;
        end
        ////////////////////////////////////////////////////////////////////////////////
        /// Handle unknown commands
        ////////////////////////////////////////////////////////////////////////////////
        else
        begin
          Log(Format('[COMMAND] Unknown command from %s: %s', [SenderIP, CommandName]));

          // Echo the command back to the client
          UDPServer.SendCommand(aSenderAddr, 100, BytesOf('Echo: ' + DataStr));
        end;
      end
      else
      begin
        Log(Format('[COMMAND] Raw command from %s: %s', [SenderIP, DataStr]));

        // Send response for unstructured commands
        UDPServer.SendCommand(aSenderAddr, 101, BytesOf('Received: ' + DataStr));
      end;
    finally
      FCommandLock.Leave;
    end;
  except
    on E: Exception do
      Log(Format('Error processing command: %s', [E.Message]));
  end;
end;

procedure TForm1.DisplayScreenShot(const aData: TBytes);
var
  MS: TMemoryStream;
  jpgImage: TJPEGImage;
begin
  // Create streams for JPEG loading
  MS := TMemoryStream.Create;
  jpgImage := TJPEGImage.Create;
  try
    // Load JPEG data directly into stream
    MS.WriteBuffer(aData[0], Length(aData));
    MS.Position := 0;

    // Load JPEG from data stream
    jpgImage.LoadFromStream(MS);

    // Display in TImage component
    if Assigned(Form1) and Assigned(Form1.Image1) then
    begin
      Form1.Image1.Picture.Assign(jpgImage);
      Form1.Image1.Stretch := True;
    end;

  finally
    MS.Free;
    jpgImage.Free;
  end;
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