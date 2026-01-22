unit NetComRegister;

interface

uses
  WinApi.Windows, System.Classes, System.SysUtils, ToolsAPI, DesignIntf, DesignEditors,
  ncSockets, ncSocketsDual, ncSources, ncSocketsThd, ncCommandHandlers, ncDBSrv, ncDBCnt,
  ncUDPSockets, ncUDPSocketsLCP, ncUDPSocketsDual;

type
  TncTCPSocketDefaultEditor = class(TDefaultEditor)
  public
    procedure EditProperty(const Prop: IProperty; var Continue: Boolean); override;
  end;

  TncUDPSocketDefaultEditor = class(TDefaultEditor)  // Added UDP editor
  public
    procedure EditProperty(const Prop: IProperty; var Continue: Boolean); override;
  end;

  TncUDPSocketLCPDefaultEditor = class(TDefaultEditor)  // Added UDP LCP editor
  public
    procedure EditProperty(const Prop: IProperty; var Continue: Boolean); override;
  end;

  TncUDPSocketDualDefaultEditor = class(TDefaultEditor)  // Added UDP Dual editor
  public
    procedure EditProperty(const Prop: IProperty; var Continue: Boolean); override;
  end;

  TncSourceDefaultEditor = class(TDefaultEditor)
  public
    procedure EditProperty(const Prop: IProperty; var Continue: Boolean); override;
  end;

procedure Register;

implementation

procedure Register;
begin
  RegisterComponents('NetCom7', [
    TncTCPServer,
    TncTCPClient,
    TncTCPServerDual,  // Dual enhanced socket components
    TncTCPClientDual,
    TncTCPServerThd,        // Threaded socket components
    TncTCPClientThd,
    TncUDPServer,     // Raw UDP components
    TncUDPClient,
    TncUDPServerLCP,  // LCP-only UDP components
    TncUDPClientLCP,
    TncUDPServerDual, // Dual-mode UDP components
    TncUDPClientDual,
    TncServerSource,
    TncClientSource,
    TncCommandHandler,
    TncDBServer,
    TncDBDataset
  ]);

  RegisterComponentEditor(TncTCPServer, TncTCPSocketDefaultEditor);
  RegisterComponentEditor(TncTCPClient, TncTCPSocketDefaultEditor);
  RegisterComponentEditor(TncTCPServerDual, TncTCPSocketDefaultEditor);  // Dual enhanced socket editors
  RegisterComponentEditor(TncTCPClientDual, TncTCPSocketDefaultEditor);
  RegisterComponentEditor(TncTCPServerThd, TncTCPSocketDefaultEditor);     // Threaded socket editors
  RegisterComponentEditor(TncTCPClientThd, TncTCPSocketDefaultEditor);
  RegisterComponentEditor(TncUDPServer, TncUDPSocketDefaultEditor);  // Raw UDP editors
  RegisterComponentEditor(TncUDPClient, TncUDPSocketDefaultEditor);
  RegisterComponentEditor(TncUDPServerLCP, TncUDPSocketLCPDefaultEditor);  // LCP UDP editors
  RegisterComponentEditor(TncUDPClientLCP, TncUDPSocketLCPDefaultEditor);
  RegisterComponentEditor(TncUDPServerDual, TncUDPSocketDualDefaultEditor);  // Dual UDP editors
  RegisterComponentEditor(TncUDPClientDual, TncUDPSocketDualDefaultEditor);
  RegisterComponentEditor(TncServerSource, TncSourceDefaultEditor);
  RegisterComponentEditor(TncClientSource, TncSourceDefaultEditor);

  UnlistPublishedProperty(TncDBDataset, 'Connection');
  UnlistPublishedProperty(TncDBDataset, 'ConnectionString');
  RegisterPropertyEditor(TypeInfo(string), TncDBDataset, 'ConnectionString', nil);

  ForceDemandLoadState(dlDisable);
end;

function GetVersion(aMinor: Boolean = True; aRelease: Boolean = True; aBuild: Boolean = True): string;
var
  VerInfoSize: DWORD;
  VerInfo: Pointer;
  VerValueSize: DWORD;
  VerValue: PVSFixedFileInfo;
  Dummy: DWORD;
  strBuffer: array [0 .. MAX_PATH] of Char;
begin
  GetModuleFileName(hInstance, strBuffer, MAX_PATH);
  VerInfoSize := GetFileVersionInfoSize(strBuffer, Dummy);
  if VerInfoSize <> 0 then
  begin
    GetMem(VerInfo, VerInfoSize);
    try
      GetFileVersionInfo(strBuffer, 0, VerInfoSize, VerInfo);
      VerQueryValue(VerInfo, '\', Pointer(VerValue), VerValueSize);
      with VerValue^ do
      begin
        Result := IntToStr(dwFileVersionMS shr 16); // Major always there
        if aMinor then
          Result := Result + '.' + IntToStr(dwFileVersionMS and $FFFF);
        if aRelease then
          Result := Result + '.' + IntToStr(dwFileVersionLS shr 16);
        if aBuild then
          Result := Result + '.' + IntToStr(dwFileVersionLS and $FFFF);
      end;
    finally
      FreeMem(VerInfo, VerInfoSize);
    end;
  end
  else
    Result := '1.0.0.0';
end;

const
  ICON_SPLASH = 'TNCICON';
  ICON_ABOUT = 'TNCICON';

var
  AboutBoxServices: IOTAAboutBoxServices = nil;
  AboutBoxIndex: Integer = 0;

resourcestring
  resPackageName = 'NetCom7 Network Communications Framework';
  resLicence = 'Full Edition for RAD Studio';
  resAboutCopyright = 'Copyright @ 2020 Bill Demos (VasDemos@yahoo.co.uk)';
  resAboutDescription =
    'Netcom7 Communicatios Framework enables you to use communication components with the ease of use of the Delphi programming language. Create and handle client/server sockets, sources and DB elements with no single line of API calls.';

procedure RegisterSplashScreen;
var
  SplashScreenHandle: HBitmap;
begin
  SplashScreenHandle := LoadBitmap(hInstance, ICON_SPLASH);
  try
    SplashScreenServices.AddPluginBitmap(resPackageName + ' ' + GetVersion, SplashScreenHandle, False, resLicence);
  finally
    DeleteObject(SplashScreenHandle);
  end;
end;

procedure RegisterAboutBox;
var
  ProductImage: HBitmap;
begin
  Supports(BorlandIDEServices, IOTAAboutBoxServices, AboutBoxServices);
  ProductImage := LoadBitmap(FindResourceHInstance(hInstance), ICON_ABOUT);
  AboutBoxIndex := AboutBoxServices.AddPluginInfo(resPackageName + GetVersion,
    resAboutCopyright + #13#10 + resAboutDescription, ProductImage, False, resLicence);
end;

procedure UnregisterAboutBox;
begin
  if (AboutBoxIndex <> 0) and Assigned(AboutBoxServices) then
  begin
    AboutBoxServices.RemovePluginInfo(AboutBoxIndex);
    AboutBoxIndex := 0;
    AboutBoxServices := nil;
  end;
end;

{ TncTCPSocketDefaultEditor }

procedure TncTCPSocketDefaultEditor.EditProperty(const Prop: IProperty; var Continue: Boolean);
begin
  if CompareText(Prop.GetName, 'ONREADDATA') = 0 then
  begin
    Prop.Edit;
    Continue := False;
  end
  else
    inherited;
end;

{ TncUDPSocketDefaultEditor }  // Added UDP editor implementation

procedure TncUDPSocketDefaultEditor.EditProperty(const Prop: IProperty; var Continue: Boolean);
begin
  if CompareText(Prop.GetName, 'ONREADDATAGRAM') = 0 then
  begin
    Prop.Edit;
    Continue := False;
  end
  else
    inherited;
end;

{ TncUDPSocketLCPDefaultEditor }  // Added UDP LCP editor implementation

procedure TncUDPSocketLCPDefaultEditor.EditProperty(const Prop: IProperty; var Continue: Boolean);
begin
  if CompareText(Prop.GetName, 'ONCOMMAND') = 0 then
  begin
    Prop.Edit;
    Continue := False;
  end
  else
    inherited;
end;

{ TncUDPSocketDualDefaultEditor }  // Added UDP Dual editor implementation

procedure TncUDPSocketDualDefaultEditor.EditProperty(const Prop: IProperty; var Continue: Boolean);
begin
  if (CompareText(Prop.GetName, 'ONREADDATAGRAM') = 0) or
     (CompareText(Prop.GetName, 'ONCOMMAND') = 0) then
  begin
    Prop.Edit;
    Continue := False;
  end
  else
    inherited;
end;

{ TncSourceDefaultEditor }

procedure TncSourceDefaultEditor.EditProperty(const Prop: IProperty; var Continue: Boolean);
begin
  if CompareText(Prop.GetName, 'ONHANDLECOMMAND') = 0 then
  begin
    Prop.Edit;
    Continue := False;
  end
  else
    inherited;
end;

initialization
  RegisterSplashScreen;
  RegisterAboutBox;

finalization
  UnregisterAboutBox;

end.

