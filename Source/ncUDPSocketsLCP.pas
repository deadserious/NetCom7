unit ncUDPSocketsLCP;
// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package - UDP Socket Components (LCP Only - Protocol Only)
//
// This unit implements UDP Server and UDP Client components with 
// lightweight command protocol support ONLY (no raw UDP support)
//
// 25/07/2025- by J.Pauwels
// - Replace TCriticalSection to TMonitor
//
// 23/07/2025
// - Removed raw UDP support (OnReadData)
// - Protocol-only implementation
// Currently implemented :
// - Broadcast
// - Lightweight Command Protocol (LCP) ONLY
// - Auto-chunking for large data
//
// Written by J.Pauwels
//
// /////////////////////////////////////////////////////////////////////////////


{$IF CompilerVersion >= 21.0}
{$WEAKLINKRTTI ON}
{$RTTI EXPLICIT METHODS([]) PROPERTIES([]) FIELDS([])}
{$ENDIF}

interface

uses
{$IFDEF MSWINDOWS}
  Winapi.Windows, Winapi.Winsock2,
{$ELSE}
  Posix.SysSocket, Posix.Unistd,
{$ENDIF}
  System.Classes, System.SysUtils, System.SyncObjs, System.Math, System.Diagnostics, System.TimeSpan, System.DateUtils,
  ncLines, ncSocketList, ncThreads, ncIPUtils, System.Generics.Collections;

const
  DefPort = 16233;
  DefHost = '';
  DefReadBufferLen = 64 * 1024; // 64KB default for UDP
  DefReaderThreadPriority = ntpNormal;
  DefEventsUseMainThread = False;
  DefUseReaderThread = True;
  DefBroadcast = False;
  DefFamily = afIPv4;

  // UDP Performance constants
  UDP_COMMAND_MAGIC = $4E43; // 'NC'
  UDP_CHUNK_MAGIC = $4E44;   // 'ND' signature for chunk packets
  UDP_MAX_SAFE_PAYLOAD = 1392; // Optimal MTU (avoids fragmentation)
  UDP_CHUNK_TIMEOUT = 5000;    // 5 seconds timeout for incomplete transfers

type
  // UDP Command Header Structure
  TUdpCommandHeader = packed record
    Cmd: Integer;        // Command ID (matches ncSocketsPro)
    Flags: Byte;         // Command flags for future extensibility
    Sequence: UInt16;    // Sequence number for tracking/ordering
  end;

  // Complete UDP Command Packet Structure
  TUdpCommandPacket = packed record
    Magic: UInt16;              // Protocol detection signature
    Header: TUdpCommandHeader;  // Command header
    // Variable data follows after this structure
  end;

  // UDP Chunk Header Structure (for auto-chunking large commands)
  TUdpChunkHeader = packed record
    Magic: UInt16;       // Chunk magic signature ($4E44 = 'ND')
    TransferID: UInt32;  // Unique transfer identifier
    ChunkIndex: UInt16;  // Current chunk number (0-based)
    TotalChunks: UInt16; // Total number of chunks
    OriginalCmd: Integer; // Original command ID
    OriginalFlags: Byte;  // Original command flags
    OriginalSequence: UInt16; // Original sequence number
  end;

  // Pointer type for zero-copy operations
  PUdpChunkHeader = ^TUdpChunkHeader;

  // Chunk reassembly tracking
  TChunkTransfer = record
    TransferID: UInt32;
    OriginalCmd: Integer;
    OriginalFlags: Byte;
    OriginalSequence: UInt16;
    TotalChunks: UInt16;
    FragmentsRemaining: UInt16;
    LastActivity: TDateTime;
    CompleteData: TBytes;           // Pre-allocated full buffer  
    Fragments: array of UInt32;    // Bitwise tracking
    ActualDataSize: UInt32;        // Real size of the complete data (calculated when complete)
    LastChunkSize: UInt16;         // Size of the last chunk (for accurate total calculation)

    // Helper methods for bitwise operations
    function IsFragmentReceived(FragmentIndex: UInt16): Boolean;
    procedure SetFragmentReceived(FragmentIndex: UInt16);
  end;

  // Chunk transfer manager
  TncChunkManager = class
  private
    FTransfers: TDictionary<UInt32, TChunkTransfer>; // Hash table for O(1) lookup
    FLock: TObject; // TMonitor synchronization object
    function GenerateTransferID: UInt32;
    procedure CleanupExpiredTransfers;
  public
    constructor Create;
    destructor Destroy; override;
    function StartTransfer(ACmd: Integer; AFlags: Byte; ASequence: UInt16; ATotalChunks: UInt16; AActualDataSize: UInt32): UInt32;
    function CreateTransferFromChunk(ATransferID: UInt32; ATotalChunks: UInt16; AOriginalCmd: Integer; AOriginalFlags: Byte; AOriginalSequence: UInt16): Boolean;
    function AddChunk(ATransferID: UInt32; AChunkIndex: UInt16; const AChunkData: TBytes): Boolean;
    function CompleteTransfer(ATransferID: UInt32; out ACmd: Integer; out AFlags: Byte;
      out ASequence: UInt16; out ACompleteData: TBytes): Boolean;
  end;

resourcestring
  ECannotSetPortWhileSocketActiveStr = 'Cannot set Port property while socket is active';
  ECannotSetHostWhileSocketActiveStr = 'Cannot set Host property while socket is active';
  ECannotSendWhileSocketInactiveStr = 'Cannot send data while socket is inactive';
  ECannotSetUseReaderThreadWhileSocketActiveStr = 'Cannot set UseReaderThread property while socket is active';
  ECannotReceiveIfUseReaderThreadStr = 'Cannot receive data if UseReaderThread is set. Use OnCommand event handler to get protocol data or set UseReaderThread property to false';
  ECannotSetFamilyWhileConnectionIsActiveStr = 'Cannot set Family property whilst the connection is active';
type
  EPropertySetError = class(Exception);

  // Event types for UDP
  TncOnDatagramEvent = procedure(Sender: TObject; aLine: TncLine;const aBuf: TBytes; aBufCount: Integer;const SenderAddr: TSockAddrStorage) of object;

  // UDP Command Protocol Event
  TncOnUDPCommandEvent = procedure(Sender: TObject; aLine: TncLine; const aSenderAddr: TSockAddrStorage;
    aCmd: Integer; const aData: TBytes; aFlags: Byte; aSequence: UInt16) of object;


  // Base UDP Socket class
  TncUDPBaseLCP = class(TComponent)
  private
    FInitActive: Boolean;
    FFamily: TAddressType;
    FPort: Integer;
    FEventsUseMainThread: Boolean;
    FBroadcast: Boolean;
    FLine: TncLine;
    FReadBufferLen: Integer;
    FOnCommand: TncOnUDPCommandEvent;
    FChunkManager: TncChunkManager;  // For auto-chunking large commands
    function GetReadBufferLen: Integer;
    procedure SetReadBufferLen(const Value: Integer);
    function GetActive: Boolean; virtual; abstract;
    procedure SetActive(const Value: Boolean);
    function GetFamily: TAddressType;
    procedure SetFamily(const Value: TAddressType);
    function GetPort: Integer;
    procedure SetPort(const Value: Integer);
    function GetReaderThreadPriority: TncThreadPriority;
    procedure SetReaderThreadPriority(const Value: TncThreadPriority);
    function GetBroadcast: Boolean;
    procedure SetBroadcast(const Value: Boolean);

  private
    FUseReaderThread: Boolean;
    procedure DoActivate(aActivate: Boolean); virtual; abstract;
    procedure SetUseReaderThread(const Value: Boolean);
  protected
    PropertyLock: TObject; // TMonitor synchronization object
    ReadBuf: TBytes;
    procedure Loaded; override;
    function CreateLineObject: TncLine; virtual;
    function GetLine: TncLine; virtual; abstract;
  public
    LineProcessor: TncReadyThread;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    function Kind: TSocketType; virtual;

    property Active: Boolean read GetActive write SetActive default False;
    property Family: TAddressType read GetFamily write SetFamily default afIPv4;
    property Port: Integer read GetPort write SetPort default DefPort;
    property ReaderThreadPriority: TncThreadPriority read GetReaderThreadPriority write SetReaderThreadPriority default DefReaderThreadPriority;
    property EventsUseMainThread: Boolean read FEventsUseMainThread write FEventsUseMainThread default DefEventsUseMainThread;
    property UseReaderThread: Boolean read FUseReaderThread write SetUseReaderThread default DefUseReaderThread;
    property Broadcast: Boolean read GetBroadcast write SetBroadcast default DefBroadcast;
    property OnCommand: TncOnUDPCommandEvent read FOnCommand write FOnCommand;
    property ReadBufferLen: Integer read GetReadBufferLen write SetReadBufferLen default DefReadBufferLen;
  published
  end;

  // UDP Client implementation
  TncUDPClientProcessor = class;

  TncCustomUDPClientLCP = class(TncUDPBaseLCP)
  private
    FHost: string;
    function GetActive: Boolean; override;
    procedure SetHost(const Value: string);
    function GetHost: string;
  protected
    procedure DoActivate(aActivate: Boolean); override;
    function GetLine: TncLine; override;
  public
    ReadSocketHandles: TSocketHandleArray;
    Line: TncLine;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aBytes: TBytes;const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aStr: string; const DestAddr: TSockAddrStorage); overload;
    procedure Send(const aBuf; aBufSize: Integer); overload;
    procedure Send(const aBytes: TBytes); overload;
    procedure Send(const aStr: string); overload;

    // UDP Command Protocol Methods
    procedure SendCommand(aCmd: Integer; const aData: TBytes; aFlags: Byte = 0; aSequence: UInt16 = 0); overload;
    procedure SendCommand(const aRemoteHost: string; aRemotePort: Integer; aCmd: Integer; const aData: TBytes; aFlags: Byte = 0; aSequence: UInt16 = 0); overload;

    function Receive(aTimeout: Cardinal = 2000): TBytes;
    property Host: string read GetHost write SetHost;
  end;

  TncUDPClientLCP = class(TncCustomUDPClientLCP)
  published
    property Active;
    property Family;
    property Port;
    property Host;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property Broadcast;
    property ReadBufferLen;
    property OnCommand;
  end;

  TncUDPClientProcessor = class(TncReadyThread)
  private
    FClientSocket: TncCustomUDPClientLCP;
  public
    ReadySocketsChanged: Boolean;
    constructor Create(aClientSocket: TncCustomUDPClientLCP);
    procedure ProcessDatagram; inline;
    procedure ProcessEvent; override;
  end;

  // UDP Server implementation
  TncUDPServerProcessor = class;

  TncCustomUDPServerLCP = class(TncUDPBaseLCP)
  private
    function GetActive: Boolean; override;
  protected
    procedure DoActivate(aActivate: Boolean); override;
    function GetLine: TncLine; override;
  public
    ReadSocketHandles: TSocketHandleArray;
    Line: TncLine;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aBytes: TBytes;const DestAddr: TSockAddrStorage); overload;
    procedure SendTo(const aStr: string; const DestAddr: TSockAddrStorage); overload;

    // UDP Command Protocol Methods
    procedure SendCommand(const DestAddr: TSockAddrStorage; aCmd: Integer; const aData: TBytes; aFlags: Byte = 0; aSequence: UInt16 = 0); overload;
    procedure SendCommand(const aRemoteHost: string; aRemotePort: Integer; aCmd: Integer; const aData: TBytes; aFlags: Byte = 0; aSequence: UInt16 = 0); overload;

    function Receive(aTimeout: Cardinal = 2000): TBytes;
  end;

  TncUDPServerLCP = class(TncCustomUDPServerLCP)
  published
    property Active;
    property Family;
    property Port;
    property ReaderThreadPriority;
    property EventsUseMainThread;
    property UseReaderThread;
    property Broadcast;
    property ReadBufferLen;
    property OnCommand;
  end;

  TncUDPServerProcessor = class(TncReadyThread)
  private
    FServerSocket: TncCustomUDPServerLCP;
  public
    ReadySocketsChanged: Boolean;
    constructor Create(aServerSocket: TncCustomUDPServerLCP);
    procedure ProcessDatagram; inline;
    procedure ProcessEvent; override;
  end;

  // We bring in TncLine so that a form that uses our components does
  // not have to reference ncLines unit to get the type
  TncLine = ncLines.TncLine;

  // We make a descendant of TncLine so that we can access the API functions.
  // These API functions are not made puclic in TncLine so that the user cannot
  // mangle up the line
  TncLineInternal = class(TncLine);

implementation

{ TncUDPBaseLCP }

constructor TncUDPBaseLCP.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  PropertyLock := TObject.Create;

  FInitActive := False;
  FFamily := DefFamily;
  FPort := DefPort;
  FEventsUseMainThread := DefEventsUseMainThread;
  FUseReaderThread := DefUseReaderThread;
  FBroadcast := DefBroadcast;
  FReadBufferLen := DefReadBufferLen;
  FOnCommand := nil;
  FChunkManager := TncChunkManager.Create; // Initialize the chunk manager

  SetLength(ReadBuf, DefReadBufferLen);

end;

function TncUDPBaseLCP.Kind: TSocketType;
begin
  Result := stUDP;
end;

destructor TncUDPBaseLCP.Destroy;
begin
  PropertyLock.Free;
  FChunkManager.Free; // Free the chunk manager
  inherited Destroy;
end;

procedure TncUDPBaseLCP.Loaded;
begin
  inherited Loaded;
  if FInitActive then
    DoActivate(True);
end;

function TncUDPBaseLCP.CreateLineObject: TncLine;
begin
  Result := TncLine.Create;
  TncLineInternal(Result).SetKind(Kind);
  TncLineInternal(Result).SetFamily(FFamily);
end;

procedure TncUDPBaseLCP.SetActive(const Value: Boolean);
begin
  TMonitor.Enter(PropertyLock);
  try
    if not(csLoading in ComponentState) then
      DoActivate(Value);
    FInitActive := GetActive;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

function TncUDPBaseLCP.GetFamily: TAddressType;
begin
  TMonitor.Enter(PropertyLock);
  try
    Result := FFamily;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncUDPBaseLCP.SetFamily(const Value: TAddressType);
begin
  if not(csLoading in ComponentState) then
  begin
    if Active then
      raise EPropertySetError.Create
        (ECannotSetFamilyWhileConnectionIsActiveStr);
  end;

  TMonitor.Enter(PropertyLock);
  try
    // Update base class family
    FFamily := Value;

    // Update the Line's family
    if FLine <> nil then
    begin
      TncLineInternal(FLine).SetFamily(Value);
    end;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

function TncUDPBaseLCP.GetPort: Integer;
begin
  TMonitor.Enter(PropertyLock);
  try
    Result := FPort;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncUDPBaseLCP.SetPort(const Value: Integer);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetPortWhileSocketActiveStr);

  TMonitor.Enter(PropertyLock);
  try
    FPort := Value;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

function TncUDPBaseLCP.GetReaderThreadPriority: TncThreadPriority;
begin
  TMonitor.Enter(PropertyLock);
  try
    Result := ToNcThreadPriority(LineProcessor.Priority);
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncUDPBaseLCP.SetReaderThreadPriority(const Value: TncThreadPriority);
begin
  TMonitor.Enter(PropertyLock);
  try
    try
      LineProcessor.Priority := FromNcThreadPriority(Value);
    except
      // Some android devices cannot handle changing priority
    end;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

function TncUDPBaseLCP.GetBroadcast: Boolean;
begin
  TMonitor.Enter(PropertyLock);
  try
    Result := FBroadcast;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncUDPBaseLCP.SetBroadcast(const Value: Boolean);
begin
  TMonitor.Enter(PropertyLock);
  try
    FBroadcast := Value;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncUDPBaseLCP.SetUseReaderThread(const Value: Boolean);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetUseReaderThreadWhileSocketActiveStr);

  TMonitor.Enter(PropertyLock);
  try
    FUseReaderThread := Value;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

function TncUDPBaseLCP.GetReadBufferLen: Integer;
begin
  TMonitor.Enter(PropertyLock);
  try
    Result := FReadBufferLen;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncUDPBaseLCP.SetReadBufferLen(const Value: Integer);
begin
  TMonitor.Enter(PropertyLock);
  try
    FReadBufferLen := Value;
    SetLength(ReadBuf, FReadBufferLen);
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

{ TncCustomUDPClientLCP }

constructor TncCustomUDPClientLCP.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FHost := DefHost;

  Line := CreateLineObject;

  // Create Line with correct family
  Line := CreateLineObject;
  if Line.Family <> FFamily then
  begin
    TncLineInternal(Line).SetFamily(FFamily);
  end;

  LineProcessor := TncUDPClientProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
end;

destructor TncCustomUDPClientLCP.Destroy;
begin
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Line.Free;

  inherited Destroy;
end;

function TncCustomUDPClientLCP.GetLine: TncLine;
begin
  Result := Line;
end;

procedure TncCustomUDPClientLCP.DoActivate(aActivate: Boolean);
begin
  // Exit if socket is already in requested state
  if aActivate = GetActive then
    Exit;

  if aActivate then
  begin
    try

    // Verify family setting before creating handle
    if Line.Family <> FFamily then
    begin
      TncLineInternal(Line).SetFamily(FFamily);
    end;

      // Create socket handle and establish connection
      TncLineInternal(Line).CreateClientHandle(FHost, FPort, GetBroadcast);

      // Enable broadcast mode if requested
      if GetBroadcast then
        TncLineInternal(Line).EnableBroadcast;

      // Configure socket buffer sizes for optimal performance
      try
        TncLineInternal(Line).SetReceiveSize(GetReadBufferLen);
        TncLineInternal(Line).SetWriteSize(GetReadBufferLen);
      except
        on E: Exception do
        begin
          TncLineInternal(Line).DestroyHandle;
          raise;
        end;
      end;

      // Initialize socket handle array for reading
      SetLength(ReadSocketHandles, 1);
      ReadSocketHandles[0] := Line.Handle;

      // Start reader thread if enabled
      if UseReaderThread then
        LineProcessor.Run;
    except
      on E: Exception do
      begin
        // Clean up on activation failure
        TncLineInternal(Line).DestroyHandle;
        SetLength(ReadSocketHandles, 0);
        raise;
      end;
    end;
  end
  else
  begin
    // Clean up when deactivating
    TncLineInternal(Line).DestroyHandle;
    SetLength(ReadSocketHandles, 0);
  end;
end;

function TncCustomUDPClientLCP.GetActive: Boolean;
begin
  Result := Line.Active;
end;

function TncCustomUDPClientLCP.GetHost: string;
begin
  TMonitor.Enter(PropertyLock);
  try
    Result := FHost;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncCustomUDPClientLCP.SetHost(const Value: string);
begin
  if not(csLoading in ComponentState) then
    if Active then
      raise EPropertySetError.Create(ECannotSetHostWhileSocketActiveStr);

  TMonitor.Enter(PropertyLock);
  try
    FHost := Value;
  finally
    TMonitor.Exit(PropertyLock);
  end;
end;

procedure TncCustomUDPClientLCP.Send(const aBuf; aBufSize: Integer);
var
  storage: TSockAddrStorage;
  addrV4: PSockAddrIn;
  addrV6: PSockAddrIn6;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  case Family of
    afIPv4:
      begin
        if GetBroadcast then
        begin
          FillChar(storage, SizeOf(storage), 0);
          storage.ss_family := AF_INET;

          addrV4 := PSockAddrIn(@storage);
          addrV4^.sin_family := AF_INET;
          addrV4^.sin_port := htons(FPort);

          // Use Winsock API directly for IPv4 broadcast
          var addr := inet_addr(PAnsiChar(AnsiString(FHost)));
          if addr <> INADDR_NONE then
            addrV4^.sin_addr.S_addr := addr
          else
            raise Exception.Create('Invalid IPv4 address format');

          SendTo(aBuf, aBufSize, storage);
        end
        else
          TncLineInternal(Line).SendBuffer(aBuf, aBufSize);
      end;

    afIPv6:
      begin
        if GetBroadcast then
          raise Exception.Create('Broadcast is not supported in IPv6. Use multicast instead.')
        else if FHost = '' then
          raise Exception.Create('Host address cannot be empty for IPv6')
        else
        begin
          // Validate IPv6 address format
          if not TncIPUtils.IsIPv6ValidAddress(FHost) then
            raise Exception.Create('Invalid IPv6 address format');

          FillChar(storage, SizeOf(storage), 0);
          storage.ss_family := AF_INET6;

          addrV6 := PSockAddrIn6(@storage);
          addrV6^.sin6_family := AF_INET6;
          addrV6^.sin6_port := htons(FPort);

          // Handle link-local address with scope ID
          if TncIPUtils.IsLinkLocal(FHost) then
          begin
            var scopePos := Pos('%', FHost);
            if scopePos > 0 then
            begin
              var hostAddr := Copy(FHost, 1, scopePos - 1);
              var scope := Copy(FHost, scopePos + 1, Length(FHost));
              var scopeID: Cardinal;
              if TryStrToUInt(scope, scopeID) then
              begin
                addrV6^.sin6_scope_id := scopeID;
                // Convert the address part without scope ID
                if not TncIPUtils.StringToAddress(hostAddr, addrV6^.sin6_addr) then
                  raise Exception.Create('Invalid IPv6 address format');
              end
              else
                raise Exception.Create('Invalid IPv6 scope ID');
            end
            else if not TncIPUtils.StringToAddress(FHost, addrV6^.sin6_addr) then
              raise Exception.Create('Invalid IPv6 address format');
          end
          else if not TncIPUtils.StringToAddress(FHost, addrV6^.sin6_addr) then
            raise Exception.Create('Invalid IPv6 address format');

          SendTo(aBuf, aBufSize, storage);
        end;
      end;
  end;
end;

procedure TncCustomUDPClientLCP.Send(const aBytes: TBytes);
begin
  if Length(aBytes) > 0 then
    Send(aBytes[0], Length(aBytes));
end;

procedure TncCustomUDPClientLCP.Send(const aStr: string);
begin
  Send(BytesOf(aStr));
end;

// UDP Command Protocol Methods for TncCustomUDPClientLCP

procedure TncCustomUDPClientLCP.SendCommand(aCmd: Integer; const aData: TBytes; aFlags: Byte; aSequence: UInt16);
begin
  SendCommand(FHost, FPort, aCmd, aData, aFlags, aSequence);
end;

procedure TncCustomUDPClientLCP.SendCommand(const aRemoteHost: string; aRemotePort: Integer; aCmd: Integer; const aData: TBytes; aFlags: Byte; aSequence: UInt16);
var
  HeaderSize, DataSize, TotalSize: Integer;
  storage: TSockAddrStorage;
  addrV4: PSockAddrIn;
  addrV6: PSockAddrIn6;

  // For normal sending
  Packet: TBytes;
  PacketHeader: TUdpCommandPacket;

  // For chunking
  ChunkHeader: TUdpChunkHeader;
  ChunkPacket: TBytes;
  TransferID: UInt32;
  TotalChunks: UInt16;
  ChunkIndex: UInt16;
  CurrentPos: Integer;
  ChunkDataSize: Integer;
  MaxChunkDataSize: Integer;

begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  // IPv6 broadcast validation
  if (Family = afIPv6) and GetBroadcast then
    raise Exception.Create('Broadcast is not supported in IPv6. Use multicast instead.');

  // Calculate total command packet size
  HeaderSize := SizeOf(TUdpCommandPacket);
  DataSize := Length(aData);
  TotalSize := HeaderSize + DataSize;

  // Build destination address first (common for both paths)
  case Family of
    afIPv4:
      begin
        FillChar(storage, SizeOf(storage), 0);
        storage.ss_family := AF_INET;
        addrV4 := PSockAddrIn(@storage);
        addrV4^.sin_family := AF_INET;
        addrV4^.sin_port := htons(aRemotePort);
        var addr := inet_addr(PAnsiChar(AnsiString(aRemoteHost)));
        if addr <> INADDR_NONE then
          addrV4^.sin_addr.S_addr := addr
        else
          raise Exception.Create('Invalid IPv4 address format');
      end;

    afIPv6:
      begin
        if not TncIPUtils.IsIPv6ValidAddress(aRemoteHost) then
          raise Exception.Create('Invalid IPv6 address format');
        FillChar(storage, SizeOf(storage), 0);
        storage.ss_family := AF_INET6;
        addrV6 := PSockAddrIn6(@storage);
        addrV6^.sin6_family := AF_INET6;
        addrV6^.sin6_port := htons(aRemotePort);
        if TncIPUtils.IsLinkLocal(aRemoteHost) then
        begin
          var scopePos := Pos('%', aRemoteHost);
          if scopePos > 0 then
          begin
            var hostAddr := Copy(aRemoteHost, 1, scopePos - 1);
            var scope := Copy(aRemoteHost, scopePos + 1, Length(aRemoteHost));
            var scopeID: Cardinal;
            if TryStrToUInt(scope, scopeID) then
            begin
              addrV6^.sin6_scope_id := scopeID;
              if not TncIPUtils.StringToAddress(hostAddr, addrV6^.sin6_addr) then
                raise Exception.Create('Invalid IPv6 address format');
            end
            else
              raise Exception.Create('Invalid IPv6 scope ID');
          end
          else if not TncIPUtils.StringToAddress(aRemoteHost, addrV6^.sin6_addr) then
            raise Exception.Create('Invalid IPv6 address format');
        end
        else if not TncIPUtils.StringToAddress(aRemoteHost, addrV6^.sin6_addr) then
          raise Exception.Create('Invalid IPv6 address format');
      end;
  end;

  // Check if auto-chunking is needed
  if TotalSize <= UDP_MAX_SAFE_PAYLOAD then
  begin
    // ===============================================
    // NORMAL SEND - Single packet
    // ===============================================

    PacketHeader.Magic := UDP_COMMAND_MAGIC;
    PacketHeader.Header.Cmd := aCmd;
    PacketHeader.Header.Flags := aFlags;
    PacketHeader.Header.Sequence := aSequence;

    SetLength(Packet, TotalSize);
    Move(PacketHeader, Packet[0], HeaderSize);
    if DataSize > 0 then
      Move(aData[0], Packet[HeaderSize], DataSize);

    SendTo(Packet, storage);
  end
  else
  begin
    // ===============================================
    // AUTO-CHUNKING - Multiple packets
    // ===============================================

    MaxChunkDataSize := UDP_MAX_SAFE_PAYLOAD - SizeOf(TUdpChunkHeader);
    TotalChunks := (DataSize + MaxChunkDataSize - 1) div MaxChunkDataSize;
    TransferID := FChunkManager.StartTransfer(aCmd, aFlags, aSequence, TotalChunks, DataSize);

    // Immediate packet sending for maximum speed
    SetLength(ChunkPacket, UDP_MAX_SAFE_PAYLOAD);

    ChunkHeader.Magic := UDP_CHUNK_MAGIC;
    ChunkHeader.TransferID := TransferID;
    ChunkHeader.TotalChunks := TotalChunks;
    ChunkHeader.OriginalCmd := aCmd;
    ChunkHeader.OriginalFlags := aFlags;
    ChunkHeader.OriginalSequence := aSequence;

    CurrentPos := 0;

    // Send packets immediately without preparation overhead
    for ChunkIndex := 0 to TotalChunks - 1 do
    begin
      ChunkDataSize := MaxChunkDataSize;
      if ChunkIndex = TotalChunks - 1 then
        ChunkDataSize := DataSize - CurrentPos;

      ChunkHeader.ChunkIndex := ChunkIndex;

      // Build and send packet immediately (zero overhead)
      Move(ChunkHeader, ChunkPacket[0], SizeOf(TUdpChunkHeader));
      if ChunkDataSize > 0 then
        Move(aData[CurrentPos], ChunkPacket[SizeOf(TUdpChunkHeader)], ChunkDataSize);

      // Send immediately at maximum speed (no delays, no burst preparation)
      SendTo(ChunkPacket[0], SizeOf(TUdpChunkHeader) + ChunkDataSize, storage);

      Inc(CurrentPos, ChunkDataSize);
    end;
  end;
end;

// 1. Base SendTo that does the actual sending
procedure TncCustomUDPClientLCP.SendTo(const aBuf; aBufSize: Integer;
  const DestAddr: TSockAddrStorage);
var
  AddrLen: Integer;
  {$IFDEF MSWINDOWS}
  BytesSent: Integer;
  {$ELSE}
  BytesSent: ssize_t;
  {$ENDIF}
  DestIP: string;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  try
    // Get destination address for logging/error reporting
    DestIP := TncIPUtils.GetIPFromStorage(DestAddr);

    // Set proper address length based on family
    case DestAddr.ss_family of
      AF_INET: AddrLen := SizeOf(TSockAddr);
      AF_INET6: AddrLen := SizeOf(TSockAddrIn6);
    else
      AddrLen := SizeOf(TSockAddrStorage);
    end;

    {$IFDEF MSWINDOWS}
    BytesSent := Winapi.Winsock2.sendto(Line.Handle, aBuf, aBufSize, 0,
      Psockaddr(@DestAddr), AddrLen);
    if BytesSent = SOCKET_ERROR then
      raise Exception.CreateFmt('Failed to send to %s: %s',
        [DestIP, SysErrorMessage(WSAGetLastError)]);
    {$ELSE}
    BytesSent := Posix.SysSocket.sendto(Line.Handle, @aBuf, aBufSize, 0,
      Psockaddr(@DestAddr), AddrLen);
    if BytesSent < 0 then
      raise Exception.CreateFmt('Failed to send to %s: %s',
        [DestIP, SysErrorMessage(GetLastError)]);
    {$ENDIF}
  except
    on E: EIPError do
      raise Exception.Create('Invalid destination address: ' + E.Message);
  end;
end;

// 2. SendTo for byte arrays
procedure TncCustomUDPClientLCP.SendTo(const aBytes: TBytes;
  const DestAddr: TSockAddrStorage);
begin
  if Length(aBytes) > 0 then
    SendTo(aBytes[0], Length(aBytes), DestAddr);
end;

// 3. SendTo for strings
procedure TncCustomUDPClientLCP.SendTo(const aStr: string; const DestAddr: TSockAddrStorage);
var
  bytes: TBytes;
  len: Integer;
begin
  bytes := BytesOf(aStr);
  len := Length(bytes);
  if len > 0 then
    SendTo(bytes[0], len, DestAddr);
end;

function TncCustomUDPClientLCP.Receive(aTimeout: Cardinal = 2000): TBytes;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
  SenderIP: string;
begin
  if UseReaderThread then
    raise Exception.Create(ECannotReceiveIfUseReaderThreadStr);

  Active := True;

  if not ReadableAnySocket([Line.Handle], aTimeout) then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  BufRead := recvfrom(Line.Handle, ReadBuf[0], Length(ReadBuf), 0,
    PSockAddr(@SenderAddr)^, SenderAddrLen);

  try
    if BufRead > 0 then
    begin
      // Get sender IP for logging if needed
      SenderIP := TncIPUtils.GetIPFromStorage(SenderAddr);
      Result := Copy(ReadBuf, 0, BufRead);
    end
    else if BufRead = 0 then
    begin
      SetLength(Result, 0);
      // Optional: raise Exception.Create('Connection closed by peer');
    end
    else
    begin
      SetLength(Result, 0);
      {$IFDEF MSWINDOWS}
      raise Exception.Create('Receive error: ' + SysErrorMessage(WSAGetLastError));
      {$ELSE}
      raise Exception.Create('Receive error: ' + SysErrorMessage(GetLastError));
      {$ENDIF}
    end;
  except
    on E: EIPError do
    begin
      SetLength(Result, 0);
      raise Exception.Create('Invalid sender address: ' + E.Message);
    end;
  end;
end;

{ TncUDPClientProcessor }

constructor TncUDPClientProcessor.Create(aClientSocket: TncCustomUDPClientLCP);
begin
  FClientSocket := aClientSocket;
  ReadySocketsChanged := False;
  inherited Create;
end;

procedure TncUDPClientProcessor.ProcessDatagram;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
  Magic: UInt16;
  CommandHeader: TUdpCommandHeader;
  CommandData: TBytes;
  PacketSize: Integer;

  // For chunk handling
  ChunkHeader: TUdpChunkHeader;
  ChunkData: TBytes;
  CompleteCmd: Integer;
  CompleteFlags: Byte;
  CompleteSequence: UInt16;
  CompleteData: TBytes;
begin
  // Initialize sender address structure
  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  // Receive datagram with proper address structure
  BufRead := recvfrom(FClientSocket.Line.Handle,
    FClientSocket.ReadBuf[0],
    Length(FClientSocket.ReadBuf),
    0,
    PSockAddr(@SenderAddr)^,
    SenderAddrLen);

  if BufRead > 0 then
  begin
    // Check minimum size for any structured packet
    if (BufRead >= SizeOf(UInt16)) then
    begin
      // Extract magic number to check protocol type
      Move(FClientSocket.ReadBuf[0], Magic, SizeOf(Magic));

      if Magic = UDP_COMMAND_MAGIC then
      begin
        // ===============================================
        // NORMAL COMMAND PACKET
        // ===============================================
        if BufRead >= SizeOf(TUdpCommandPacket) then
        begin
          Move(FClientSocket.ReadBuf[SizeOf(UInt16)], CommandHeader, SizeOf(CommandHeader));

          PacketSize := SizeOf(TUdpCommandPacket);
          if BufRead > PacketSize then
          begin
            SetLength(CommandData, BufRead - PacketSize);
            Move(FClientSocket.ReadBuf[PacketSize], CommandData[0], BufRead - PacketSize);
          end
          else
            SetLength(CommandData, 0);

          if Assigned(FClientSocket.OnCommand) then
            try
              FClientSocket.OnCommand(FClientSocket,
                FClientSocket.Line,
                SenderAddr,
                CommandHeader.Cmd,
                CommandData,
                CommandHeader.Flags,
                CommandHeader.Sequence);
            except
            end;
        end;
      end
      else if Magic = UDP_CHUNK_MAGIC then
      begin
        // ===============================================
        // CHUNK PACKET - Auto-reassembly
        // ===============================================

        if BufRead >= SizeOf(TUdpChunkHeader) then
        begin
          // Direct header access
          Move(FClientSocket.ReadBuf[0], ChunkHeader, SizeOf(ChunkHeader));

          // Direct chunk data extraction
          PacketSize := SizeOf(TUdpChunkHeader);
          if BufRead > PacketSize then
          begin
            // Use buffer slice directly instead of copying
            SetLength(ChunkData, BufRead - PacketSize);
            Move(FClientSocket.ReadBuf[PacketSize], ChunkData[0], BufRead - PacketSize);
          end
          else
            SetLength(ChunkData, 0);

          // Ensure transfer exists (create if first chunk)
          FClientSocket.FChunkManager.CreateTransferFromChunk(ChunkHeader.TransferID, ChunkHeader.TotalChunks,
            ChunkHeader.OriginalCmd, ChunkHeader.OriginalFlags, ChunkHeader.OriginalSequence);

          // Add chunk to manager
          if FClientSocket.FChunkManager.AddChunk(ChunkHeader.TransferID, ChunkHeader.ChunkIndex, ChunkData) then
          begin
            // Only check completion if chunk was successfully added
            if FClientSocket.FChunkManager.CompleteTransfer(ChunkHeader.TransferID, CompleteCmd, CompleteFlags, CompleteSequence, CompleteData) then
            begin
              // Transfer complete - fire OnCommand with reassembled data
              if Assigned(FClientSocket.OnCommand) then
                try
                  FClientSocket.OnCommand(FClientSocket,
                    FClientSocket.Line,
                    SenderAddr,
                    CompleteCmd,
                    CompleteData,
                    CompleteFlags,
                    CompleteSequence);
                except
                end;
            end;
          end;
        end;
      end;
      // NOTE: LCP ONLY - No else clause for raw data
      // Any non-protocol packets are silently ignored
    end;
    // NOTE: LCP ONLY - Packets too small for protocol headers are silently ignored
  end;
end;

procedure TncUDPClientProcessor.ProcessEvent;
begin
  while (not Terminated) do
    try
      if FClientSocket.Line.Active then
      begin
        if ReadableAnySocket(FClientSocket.ReadSocketHandles, 100) then
        begin
          if ReadySocketsChanged then
          begin
            ReadySocketsChanged := False;
            Continue;
          end;
          if FClientSocket.EventsUseMainThread then
            Synchronize(ProcessDatagram)
          else
            ProcessDatagram;
        end;
      end
      else
        Exit;
    except
      // Continue processing even after errors
    end;
end;

{ TncChunkManager }

constructor TncChunkManager.Create;
begin
  inherited Create;
  FLock := TObject.Create;
  FTransfers := TDictionary<UInt32, TChunkTransfer>.Create;
end;

destructor TncChunkManager.Destroy;
begin
  FLock.Free;
  FTransfers.Free;
  inherited Destroy;
end;

function TncChunkManager.GenerateTransferID: UInt32;
begin
  // Simple transfer ID generation (timestamp + random)
  Result := UInt32(GetTickCount) xor UInt32(Random(65536));
end;

procedure TncChunkManager.CleanupExpiredTransfers;
var
  Now: TDateTime;
  TransferID: UInt32;
  Transfer: TChunkTransfer;
  ExpiredIDs: TArray<UInt32>;
  I: Integer;
begin
  Now := System.SysUtils.Now;
  SetLength(ExpiredIDs, 0);

  // First pass: identify expired transfers
  for Transfer in FTransfers.Values do
  begin
    if MilliSecondsBetween(Now, Transfer.LastActivity) > UDP_CHUNK_TIMEOUT then
    begin
      SetLength(ExpiredIDs, Length(ExpiredIDs) + 1);
      ExpiredIDs[High(ExpiredIDs)] := Transfer.TransferID;
    end;
  end;

  // Second pass: remove expired transfers
  for I := 0 to High(ExpiredIDs) do
    FTransfers.Remove(ExpiredIDs[I]);
end;

function TncChunkManager.StartTransfer(ACmd: Integer; AFlags: Byte; ASequence: UInt16; ATotalChunks: UInt16; AActualDataSize: UInt32): UInt32;
var
  Transfer: TChunkTransfer;
  MaxDataSize: Integer;
  BitArraySize: Integer;
begin
  TMonitor.Enter(FLock);
  try
    CleanupExpiredTransfers;

    Transfer.TransferID := GenerateTransferID;
    Transfer.OriginalCmd := ACmd;
    Transfer.OriginalFlags := AFlags;
    Transfer.OriginalSequence := ASequence;
    Transfer.TotalChunks := ATotalChunks;
    Transfer.FragmentsRemaining := ATotalChunks; // Initialize FragmentsRemaining
    Transfer.LastActivity := System.SysUtils.Now;
    Transfer.ActualDataSize := AActualDataSize; // Store the actual data size
    Transfer.LastChunkSize := 0; // Will be set when last chunk is received

    // Pre-allocate only maximum needed size (not over-allocate)
    MaxDataSize := ATotalChunks * (UDP_MAX_SAFE_PAYLOAD - SizeOf(TUdpChunkHeader));
    SetLength(Transfer.CompleteData, MaxDataSize);
    
    // Calculate bit array size (32 fragments per UInt32)
    BitArraySize := (ATotalChunks + 31) div 32;
    SetLength(Transfer.Fragments, BitArraySize);
    // Initialize all bits to 0
    if BitArraySize > 0 then
      FillChar(Transfer.Fragments[0], BitArraySize * SizeOf(UInt32), 0);

    FTransfers.Add(Transfer.TransferID, Transfer);

    Result := Transfer.TransferID;
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TncChunkManager.CreateTransferFromChunk(ATransferID: UInt32; ATotalChunks: UInt16; AOriginalCmd: Integer; AOriginalFlags: Byte; AOriginalSequence: UInt16): Boolean;
var
  Transfer: TChunkTransfer;
  MaxDataSize: Integer;
  BitArraySize: Integer;
begin
  Result := False;
  TMonitor.Enter(FLock);
  try
    // Check if transfer already exists
    if FTransfers.TryGetValue(ATransferID, Transfer) then
    begin
      Result := True; // Already exists
      Exit;
    end;

    // Create new transfer
    Transfer.TransferID := ATransferID;
    Transfer.OriginalCmd := AOriginalCmd;
    Transfer.OriginalFlags := AOriginalFlags;
    Transfer.OriginalSequence := AOriginalSequence;
    Transfer.TotalChunks := ATotalChunks;
    Transfer.FragmentsRemaining := ATotalChunks; // Initialize FragmentsRemaining
    Transfer.LastActivity := System.SysUtils.Now;
    Transfer.ActualDataSize := 0; // Will be calculated when all chunks received
    Transfer.LastChunkSize := 0; // Will be set when last chunk is received

    // Pre-allocate buffer for maximum possible data size
    MaxDataSize := ATotalChunks * (UDP_MAX_SAFE_PAYLOAD - SizeOf(TUdpChunkHeader));
    SetLength(Transfer.CompleteData, MaxDataSize);
    
    // Calculate bit array size (32 fragments per UInt32)
    BitArraySize := (ATotalChunks + 31) div 32;
    SetLength(Transfer.Fragments, BitArraySize);
    // Initialize all bits to 0
    if BitArraySize > 0 then
      FillChar(Transfer.Fragments[0], BitArraySize * SizeOf(UInt32), 0);

    FTransfers.Add(Transfer.TransferID, Transfer);

    Result := True;
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TncChunkManager.AddChunk(ATransferID: UInt32; AChunkIndex: UInt16; const AChunkData: TBytes): Boolean;
var
  Transfer: TChunkTransfer;
  ChunkOffset: Integer;
  DataSize: Integer;
  MaxChunkSize: Integer;
begin
  Result := False;
  DataSize := Length(AChunkData);

  // Quick validation before lock
  if DataSize = 0 then Exit;

  // Single lock operation only
  TMonitor.Enter(FLock);
  try
    if FTransfers.TryGetValue(ATransferID, Transfer) then
    begin
      // Transfer exists - add chunk
      if (AChunkIndex < Transfer.TotalChunks) and (not Transfer.IsFragmentReceived(AChunkIndex)) then
      begin
        // Calculate offset once and copy directly
        MaxChunkSize := UDP_MAX_SAFE_PAYLOAD - SizeOf(TUdpChunkHeader);
        ChunkOffset := AChunkIndex * MaxChunkSize;

        // Direct memory operation
        if ChunkOffset + DataSize <= Length(Transfer.CompleteData) then
        begin
          Move(AChunkData[0], Transfer.CompleteData[ChunkOffset], DataSize);

          // Update tracking
          Transfer.SetFragmentReceived(AChunkIndex);
          Dec(Transfer.FragmentsRemaining);
          Transfer.LastActivity := System.SysUtils.Now;
          
          // Track last chunk size for accurate total calculation
          if AChunkIndex = Transfer.TotalChunks - 1 then
            Transfer.LastChunkSize := DataSize;
            
          // If all chunks received, calculate actual data size
          if Transfer.FragmentsRemaining = 0 then
            Transfer.ActualDataSize := (Transfer.TotalChunks - 1) * MaxChunkSize + Transfer.LastChunkSize;

          // Update the transfer back to dictionary once
          FTransfers.AddOrSetValue(ATransferID, Transfer);
          Result := True;
        end;
      end;
    end;
  finally
    TMonitor.Exit(FLock);
  end;
end;

function TncChunkManager.CompleteTransfer(ATransferID: UInt32; out ACmd: Integer; out AFlags: Byte;
  out ASequence: UInt16; out ACompleteData: TBytes): Boolean;
var
  Transfer: TChunkTransfer;
begin
  Result := False;
  TMonitor.Enter(FLock);
  try
    if FTransfers.TryGetValue(ATransferID, Transfer) and (Transfer.FragmentsRemaining = 0) then
    begin
      // All chunks received - prepare output
      ACmd := Transfer.OriginalCmd;
      AFlags := Transfer.OriginalFlags;
      ASequence := Transfer.OriginalSequence;

      // Use the stored actual data size (from sender)
      if Transfer.ActualDataSize > 0 then
      begin
        SetLength(ACompleteData, Transfer.ActualDataSize);
        Move(Transfer.CompleteData[0], ACompleteData[0], Transfer.ActualDataSize);
      end
      else
        SetLength(ACompleteData, 0);

      // Remove completed transfer
      FTransfers.Remove(ATransferID);
      Result := True;
    end;
  finally
    TMonitor.Exit(FLock);
  end;
end;

{ TChunkTransfer - bitwise fragment tracking }

function TChunkTransfer.IsFragmentReceived(FragmentIndex: UInt16): Boolean;
begin
  if FragmentIndex >= TotalChunks then
  begin
    Result := False;
    Exit;
  end;
  // Bitwise check: (fragments[fragmentNumber / 32] & (1u << (fragmentNumber % 32))) == 0
  Result := (Fragments[FragmentIndex div 32] and (UInt32(1) shl (FragmentIndex mod 32))) <> 0;
end;

procedure TChunkTransfer.SetFragmentReceived(FragmentIndex: UInt16);
begin
  if FragmentIndex < TotalChunks then
    // Bitwise set: fragments[fragmentNumber / 32] |= (1u << (fragmentNumber % 32))
    Fragments[FragmentIndex div 32] := Fragments[FragmentIndex div 32] or (UInt32(1) shl (FragmentIndex mod 32));
end;

{ TncCustomUDPServerLCP }

constructor TncCustomUDPServerLCP.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  Line := CreateLineObject;

  // Create Line with correct family
  Line := CreateLineObject;
  if Line.Family <> FFamily then
  begin
    TncLineInternal(Line).SetFamily(FFamily);
  end;

  LineProcessor := TncUDPServerProcessor.Create(Self);
  try
    LineProcessor.Priority := FromNcThreadPriority(DefReaderThreadPriority);
  except
    // Some Android devices do not like this
  end;
end;

destructor TncCustomUDPServerLCP.Destroy;
begin
  Active := False;

  LineProcessor.Terminate;
  LineProcessor.WakeupEvent.SetEvent;
  LineProcessor.WaitFor;
  LineProcessor.Free;

  Line.Free;

  inherited Destroy;
end;

function TncCustomUDPServerLCP.GetLine: TncLine;
begin
  Result := Line;
end;

function TncCustomUDPServerLCP.GetActive: Boolean;
begin
  Result := Line.Active;
end;

procedure TncCustomUDPServerLCP.DoActivate(aActivate: Boolean);
begin
  if aActivate = GetActive then
    Exit;

  if aActivate then
  begin

    // Verify family setting before creating handle
    if Line.Family <> FFamily then
    begin
      TncLineInternal(Line).SetFamily(FFamily);
    end;

    // CreateServerHandle will bind to all interfaces (0.0.0.0)
    // through the AI_PASSIVE flag in ncLines.CreateServerHandle
    TncLineInternal(Line).CreateServerHandle(FPort);

    // Enable broadcast if needed
    if Broadcast then
      TncLineInternal(Line).EnableBroadcast;

    // Set socket buffer sizes for better performance
    try
      TncLineInternal(Line).SetReceiveSize(ReadBufferLen);
      TncLineInternal(Line).SetWriteSize(ReadBufferLen);
    except
      // Ignore buffer size errors
    end;

    SetLength(ReadSocketHandles, 1);
    ReadSocketHandles[0] := Line.Handle;

    if UseReaderThread then
    begin
      LineProcessor.WaitForReady;
      LineProcessor.Run;
    end;
  end
  else
  begin
    TncLineInternal(Line).DestroyHandle;
    SetLength(ReadSocketHandles, 0);
  end;
end;

// 1. Base SendTo that does the actual sending
procedure TncCustomUDPServerLCP.SendTo(const aBuf; aBufSize: Integer; const DestAddr: TSockAddrStorage);
var
  AddrLen: Integer;
  {$IFDEF MSWINDOWS}
  BytesSent: Integer;
  {$ELSE}
  BytesSent: ssize_t;
  {$ENDIF}
  DestIP: string;
begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);
  try
    // Get destination address for logging/error reporting
    DestIP := TncIPUtils.GetIPFromStorage(DestAddr);
    // Set proper address length based on family
    case DestAddr.ss_family of
      AF_INET: AddrLen := SizeOf(TSockAddr);
      AF_INET6: AddrLen := SizeOf(TSockAddrIn6);
    else
      AddrLen := SizeOf(TSockAddrStorage);
    end;
    {$IFDEF MSWINDOWS}
    BytesSent := Winapi.Winsock2.sendto(Line.Handle, aBuf, aBufSize, 0,
      Psockaddr(@DestAddr), AddrLen);
    if BytesSent = SOCKET_ERROR then
      raise Exception.CreateFmt('Failed to send to %s: %s',
        [DestIP, SysErrorMessage(WSAGetLastError)]);
    {$ELSE}
    BytesSent := Posix.SysSocket.sendto(Line.Handle, @aBuf, aBufSize, 0,
      Psockaddr(@DestAddr), AddrLen);
    if BytesSent < 0 then
      raise Exception.CreateFmt('Failed to send to %s: %s',
        [DestIP, SysErrorMessage(GetLastError)]);
    {$ENDIF}
  except
    on E: EIPError do
      raise Exception.Create('Invalid destination address: ' + E.Message);
  end;
end;

// 2. SendTo for byte arrays
procedure TncCustomUDPServerLCP.SendTo(const aBytes: TBytes; const DestAddr: TSockAddrStorage);
begin
  if Length(aBytes) > 0 then
    SendTo(aBytes[0], Length(aBytes), DestAddr);
end;

// 3. SendTo for strings
procedure TncCustomUDPServerLCP.SendTo(const aStr: string; const DestAddr: TSockAddrStorage);
var
  bytes: TBytes;
  len: Integer;
begin
  bytes := BytesOf(aStr);
  len := Length(bytes);
  if len > 0 then
    SendTo(bytes[0], len, DestAddr);
end;

// UDP Command Protocol Methods for TncCustomUDPServerLCP

procedure TncCustomUDPServerLCP.SendCommand(const DestAddr: TSockAddrStorage; aCmd: Integer; const aData: TBytes; aFlags: Byte; aSequence: UInt16);
var
  HeaderSize, DataSize, TotalSize: Integer;

  // For normal sending
  Packet: TBytes;
  PacketHeader: TUdpCommandPacket;

  // For chunking
  ChunkHeader: TUdpChunkHeader;
  ChunkPacket: TBytes;
  TransferID: UInt32;
  TotalChunks: UInt16;
  ChunkIndex: UInt16;
  CurrentPos: Integer;
  ChunkDataSize: Integer;
  MaxChunkDataSize: Integer;

begin
  if not Active then
    raise EPropertySetError.Create(ECannotSendWhileSocketInactiveStr);

  // Calculate total command packet size
  HeaderSize := SizeOf(TUdpCommandPacket);
  DataSize := Length(aData);
  TotalSize := HeaderSize + DataSize;

  // Check if auto-chunking is needed
  if TotalSize <= UDP_MAX_SAFE_PAYLOAD then
  begin
    // ===============================================
    // NORMAL SEND - Single packet
    // ===============================================
    PacketHeader.Magic := UDP_COMMAND_MAGIC;
    PacketHeader.Header.Cmd := aCmd;
    PacketHeader.Header.Flags := aFlags;
    PacketHeader.Header.Sequence := aSequence;

    SetLength(Packet, TotalSize);
    Move(PacketHeader, Packet[0], HeaderSize);
    if DataSize > 0 then
      Move(aData[0], Packet[HeaderSize], DataSize);

    SendTo(Packet, DestAddr);
  end
  else
  begin
    // ===============================================
    // AUTO-CHUNKING - Multiple packets
    // ===============================================

    MaxChunkDataSize := UDP_MAX_SAFE_PAYLOAD - SizeOf(TUdpChunkHeader);
    TotalChunks := (DataSize + MaxChunkDataSize - 1) div MaxChunkDataSize;
    TransferID := FChunkManager.StartTransfer(aCmd, aFlags, aSequence, TotalChunks, DataSize);

    // Immediate packet sending for maximum speed
    SetLength(ChunkPacket, UDP_MAX_SAFE_PAYLOAD);

    ChunkHeader.Magic := UDP_CHUNK_MAGIC;
    ChunkHeader.TransferID := TransferID;
    ChunkHeader.TotalChunks := TotalChunks;
    ChunkHeader.OriginalCmd := aCmd;
    ChunkHeader.OriginalFlags := aFlags;
    ChunkHeader.OriginalSequence := aSequence;

    CurrentPos := 0;

    // Send packets immediately without preparation overhead
    for ChunkIndex := 0 to TotalChunks - 1 do
    begin
      ChunkDataSize := MaxChunkDataSize;
      if ChunkIndex = TotalChunks - 1 then
        ChunkDataSize := DataSize - CurrentPos;

      ChunkHeader.ChunkIndex := ChunkIndex;

      // Build and send packet immediately (zero overhead)
      Move(ChunkHeader, ChunkPacket[0], SizeOf(TUdpChunkHeader));
      if ChunkDataSize > 0 then
        Move(aData[CurrentPos], ChunkPacket[SizeOf(TUdpChunkHeader)], ChunkDataSize);

      // Send immediately at maximum speed (no delays, no burst preparation)
      SendTo(ChunkPacket[0], SizeOf(TUdpChunkHeader) + ChunkDataSize, DestAddr);

      Inc(CurrentPos, ChunkDataSize);
    end;
  end;
end;

procedure TncCustomUDPServerLCP.SendCommand(const aRemoteHost: string; aRemotePort: Integer; aCmd: Integer; const aData: TBytes; aFlags: Byte; aSequence: UInt16);
var
  storage: TSockAddrStorage;
  addrV4: PSockAddrIn;
  addrV6: PSockAddrIn6;
begin
  // IPv6 broadcast validation
  if (Family = afIPv6) and Broadcast then
    raise Exception.Create('Broadcast is not supported in IPv6. Use multicast instead.');

  // Build destination address based on family
  case Family of
    afIPv4:
      begin
        FillChar(storage, SizeOf(storage), 0);
        storage.ss_family := AF_INET;

        addrV4 := PSockAddrIn(@storage);
        addrV4^.sin_family := AF_INET;
        addrV4^.sin_port := htons(aRemotePort);

        var addr := inet_addr(PAnsiChar(AnsiString(aRemoteHost)));
        if addr <> INADDR_NONE then
          addrV4^.sin_addr.S_addr := addr
        else
          raise Exception.Create('Invalid IPv4 address format');

        SendCommand(storage, aCmd, aData, aFlags, aSequence);
      end;

    afIPv6:
      begin
        if not TncIPUtils.IsIPv6ValidAddress(aRemoteHost) then
          raise Exception.Create('Invalid IPv6 address format');

        FillChar(storage, SizeOf(storage), 0);
        storage.ss_family := AF_INET6;

        addrV6 := PSockAddrIn6(@storage);
        addrV6^.sin6_family := AF_INET6;
        addrV6^.sin6_port := htons(aRemotePort);

        // Handle link-local address with scope ID
        if TncIPUtils.IsLinkLocal(aRemoteHost) then
        begin
          var scopePos := Pos('%', aRemoteHost);
          if scopePos > 0 then
          begin
            var hostAddr := Copy(aRemoteHost, 1, scopePos - 1);
            var scope := Copy(aRemoteHost, scopePos + 1, Length(aRemoteHost));
            var scopeID: Cardinal;
            if TryStrToUInt(scope, scopeID) then
            begin
              addrV6^.sin6_scope_id := scopeID;
              if not TncIPUtils.StringToAddress(hostAddr, addrV6^.sin6_addr) then
                raise Exception.Create('Invalid IPv6 address format');
            end
            else
              raise Exception.Create('Invalid IPv6 scope ID');
          end
          else if not TncIPUtils.StringToAddress(aRemoteHost, addrV6^.sin6_addr) then
            raise Exception.Create('Invalid IPv6 address format');
        end
        else if not TncIPUtils.StringToAddress(aRemoteHost, addrV6^.sin6_addr) then
          raise Exception.Create('Invalid IPv6 address format');

        SendCommand(storage, aCmd, aData, aFlags, aSequence);
      end;
  end;
end;

function TncCustomUDPServerLCP.Receive(aTimeout: Cardinal = 2000): TBytes;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
  SenderIP: string;
begin
  if UseReaderThread then
    raise Exception.Create(ECannotReceiveIfUseReaderThreadStr);

  Active := True;

  if not ReadableAnySocket([Line.Handle], aTimeout) then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  BufRead := recvfrom(Line.Handle, ReadBuf[0], Length(ReadBuf), 0,
    PSockAddr(@SenderAddr)^, SenderAddrLen);

  try
    if BufRead > 0 then
    begin
      // Get sender IP for logging if needed
      SenderIP := TncIPUtils.GetIPFromStorage(SenderAddr);
      Result := Copy(ReadBuf, 0, BufRead);
    end
    else if BufRead = 0 then
    begin
      SetLength(Result, 0);
      // Optional: raise Exception.Create('Connection closed by peer');
    end
    else
    begin
      SetLength(Result, 0);
      {$IFDEF MSWINDOWS}
      raise Exception.Create('Receive error: ' + SysErrorMessage(WSAGetLastError));
      {$ELSE}
      raise Exception.Create('Receive error: ' + SysErrorMessage(GetLastError));
      {$ENDIF}
    end;
  except
    on E: EIPError do
    begin
      SetLength(Result, 0);
      raise Exception.Create('Invalid sender address: ' + E.Message);
    end;
  end;
end;

{ TncUDPServerProcessor }

constructor TncUDPServerProcessor.Create(aServerSocket: TncCustomUDPServerLCP);
begin
  FServerSocket := aServerSocket;
  ReadySocketsChanged := False;
  inherited Create;
end;


procedure TncUDPServerProcessor.ProcessDatagram;
var
  BufRead: Integer;
  SenderAddr: TSockAddrStorage;
  SenderAddrLen: Integer;
  Magic: UInt16;
  CommandHeader: TUdpCommandHeader;
  CommandData: TBytes;
  PacketSize: Integer;

  // For chunk handling
  ChunkHeader: TUdpChunkHeader;
  ChunkData: TBytes;
  CompleteCmd: Integer;
  CompleteFlags: Byte;
  CompleteSequence: UInt16;
  CompleteData: TBytes;
begin
  SenderAddrLen := SizeOf(TSockAddrStorage);
  FillChar(SenderAddr, SenderAddrLen, 0);

  BufRead := recvfrom(FServerSocket.Line.Handle,
    FServerSocket.ReadBuf[0],
    Length(FServerSocket.ReadBuf),
    0,
    PSockAddr(@SenderAddr)^,
    SenderAddrLen);

  if BufRead > 0 then
  begin
    // Check minimum size for any structured packet
    if (BufRead >= SizeOf(UInt16)) then
    begin
      // Extract magic number to check protocol type
      Move(FServerSocket.ReadBuf[0], Magic, SizeOf(Magic));

      if Magic = UDP_COMMAND_MAGIC then
      begin
        // ===============================================
        // NORMAL COMMAND PACKET
        // ===============================================
        if BufRead >= SizeOf(TUdpCommandPacket) then
        begin
          Move(FServerSocket.ReadBuf[SizeOf(UInt16)], CommandHeader, SizeOf(CommandHeader));

          PacketSize := SizeOf(TUdpCommandPacket);
          if BufRead > PacketSize then
          begin
            SetLength(CommandData, BufRead - PacketSize);
            Move(FServerSocket.ReadBuf[PacketSize], CommandData[0], BufRead - PacketSize);
          end
          else
            SetLength(CommandData, 0);

          if Assigned(FServerSocket.OnCommand) then
            try
              FServerSocket.OnCommand(FServerSocket,
                FServerSocket.Line,
                SenderAddr,
                CommandHeader.Cmd,
                CommandData,
                CommandHeader.Flags,
                CommandHeader.Sequence);
            except
            end;
        end;
      end
      else if Magic = UDP_CHUNK_MAGIC then
      begin
        // ===============================================
        // CHUNK PACKET - Auto-reassembly
        // ===============================================

        if BufRead >= SizeOf(TUdpChunkHeader) then
        begin
          // Direct header access
          Move(FServerSocket.ReadBuf[0], ChunkHeader, SizeOf(ChunkHeader));

          // Direct chunk data extraction
          PacketSize := SizeOf(TUdpChunkHeader);
          if BufRead > PacketSize then
          begin
            // Use buffer slice directly instead of copying
            SetLength(ChunkData, BufRead - PacketSize);
            Move(FServerSocket.ReadBuf[PacketSize], ChunkData[0], BufRead - PacketSize);
          end
          else
            SetLength(ChunkData, 0);

          // Ensure transfer exists (create if first chunk)
          FServerSocket.FChunkManager.CreateTransferFromChunk(ChunkHeader.TransferID, ChunkHeader.TotalChunks,
            ChunkHeader.OriginalCmd, ChunkHeader.OriginalFlags, ChunkHeader.OriginalSequence);

          // Add chunk to manager
          if FServerSocket.FChunkManager.AddChunk(ChunkHeader.TransferID, ChunkHeader.ChunkIndex, ChunkData) then
          begin
            // Only check completion if chunk was successfully added
            if FServerSocket.FChunkManager.CompleteTransfer(ChunkHeader.TransferID, CompleteCmd, CompleteFlags, CompleteSequence, CompleteData) then
            begin
              // Transfer complete - fire OnCommand with reassembled data
              if Assigned(FServerSocket.OnCommand) then
                try
                  FServerSocket.OnCommand(FServerSocket,
                    FServerSocket.Line,
                    SenderAddr,
                    CompleteCmd,
                    CompleteData,
                    CompleteFlags,
                    CompleteSequence);
                except
                end;
            end;
          end;
        end;
      end;
      // NOTE: LCP ONLY - No else clause for raw data
      // Any non-protocol packets are silently ignored
    end;
    // NOTE: LCP ONLY - Packets too small for protocol headers are silently ignored
  end;
end;

procedure TncUDPServerProcessor.ProcessEvent;
begin
  if FServerSocket.EventsUseMainThread then
    while FServerSocket.Active and (not Terminated) do
      try
        if ReadableAnySocket(FServerSocket.ReadSocketHandles, 500) then
        begin
          if ReadySocketsChanged then
          begin
            ReadySocketsChanged := False;
            Continue;
          end;
          Synchronize(ProcessDatagram);
        end;
      except
      end
  else
    while FServerSocket.Active and (not Terminated) do
      try
        if ReadableAnySocket(FServerSocket.ReadSocketHandles, 500) then
        begin
          if ReadySocketsChanged then
          begin
            ReadySocketsChanged := False;
            Continue;
          end;
          ProcessDatagram;
        end;
      except
      end;
end;

end.