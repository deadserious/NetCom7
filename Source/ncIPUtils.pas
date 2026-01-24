unit ncIPUtils;
// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package - IP Address utils
//
//
//
// 21/01/2025
// - Initial creation
// Written by J.Pauwels
//
// /////////////////////////////////////////////////////////////////////////////

interface

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  Winapi.Winsock2,
  Winapi.IpHlpApi,
  Winapi.IpTypes,
  {$ELSE}
  Posix.Base,
  Posix.SysSocket,
  Posix.NetDB,
  Posix.NetIf,
  Posix.NetinetIn,
  Posix.ArpaInet,
  Posix.Unistd,
  {$ENDIF}
  System.SysUtils,
  System.Classes;

const
  IPV6_ADDR_LEN = 16;  // IPv6 address length in bytes
  IPV6_STR_MAX_LEN = 46; // Maximum string length for IPv6 address including null terminator
  SOCKADDR_STORAGE_SIZE = 128; // Size of sockaddr_storage structure

  {$IFDEF MSWINDOWS}
  AF_INET6 = 23;
  {$ENDIF}

type
  TIn6Addr = record
    case Integer of
      0: (s6_bytes: array[0..15] of Byte);
      1: (s6_words: array[0..7] of Word);
  end;
  PIn6Addr = ^TIn6Addr;

  TSockAddrIn6 = record
    sin6_family: Word;       // AF_INET6
    sin6_port: Word;         // Transport layer port #
    sin6_flowinfo: Cardinal; // IPv6 flow information
    sin6_addr: TIn6Addr;     // IPv6 address
    sin6_scope_id: Cardinal; // Set of interfaces for scope
  end;
  PSockAddrIn6 = ^TSockAddrIn6;

  // Socket storage structure - used for both IPv4 and IPv6
  TSockAddrStorage = record
    ss_family: Word;                    // Address family
    __ss_pad1: array [0..5] of Byte;    // 6 bytes of padding
    __ss_align: Int64;                  // Force alignment
    __ss_pad2: array [0..111] of Byte;  // 112 bytes of padding
  end;
  PSockAddrStorage = ^TSockAddrStorage;

  {$IFNDEF MSWINDOWS}
  TBytesOfUint = record
    s_b1, s_b2, s_b3, s_b4: Byte;
  end;

  TSinAddr = record
    case UInt32 of
      0: (S_un_b : TBytesOfUint);
      1: (S_addr : UInt32);
  end;

  // Define Windows-compatible types for Linux
  TSockAddrIn = packed record
    sin_family: Word;
    sin_port: Word;
    sin_addr: TSinAddr;
    sin_zero: array[0..7] of Byte;
  end;
  PSockAddrIn = ^TSockAddrIn;
  {$ENDIF}

  EIPError = class(Exception);

  TIPFamily = (ipfUnknown, ipfIPv4, ipfIPv6);

  // Function types for dynamic loading
  {$IFDEF MSWINDOWS}
  TInetPton = function(Family: Integer; const pszAddrString: PAnsiChar;
    pAddrBuf: Pointer): Integer; stdcall;
  TInetNtop = function(Family: Integer; pAddr: Pointer;
    pStringBuf: PAnsiChar; StringBufSize: size_t): PAnsiChar; stdcall;
  {$ENDIF}

  TncIPUtils = class
  private
    {$IFDEF MSWINDOWS}
    class var
      InetPton: TInetPton;
      InetNtop: TInetNtop;
    class function LoadIPv6Functions: Boolean;
    {$ENDIF}
    class function StripPortFromAddressString(const S: string): string;
  public
    class constructor Create;

    // Generic IP Helpers
    class function DetectIPFamily(const S: string): TIPFamily;
    class function LocalIPForDestinationIP(DestinationIP : AnsiString) : string;
    class function AllLocalIPs : TArray<string>;
    class function IsLocalIP(IP : string) : boolean;

    // SockAddrStorage methods
    class function StorageToString(const Storage: TSockAddrStorage): string;
    class function IsIPv6Storage(const Storage: TSockAddrStorage): Boolean;
    class function GetStorageFamily(const Storage: TSockAddrStorage): Word;
    class function StorageToIPv6Address(const Storage: TSockAddrStorage;
      out Addr: TSockAddrIn6): Boolean;
    class function GetIPFromStorage(const Storage: TSockAddrStorage): string;
    class function GetPortFromStorage(const Storage: TSockAddrStorage): Word;

    // Existing IPv6 methods
    class function IsIPv6ValidAddress(const AddrStr: string): Boolean;
    class function AddressToString(const Addr: TIn6Addr): string;
    class function StringToAddress(const AddrStr: string; out Addr: TIn6Addr): Boolean;
    class function IsLinkLocal(const AddrStr: string): Boolean;
    class function NormalizeAddress(const AddrStr: string): string;
    class function AddressToPresentation(const Addr: TIn6Addr): string;
    class function PresentationToAddress(const Present: string; var Addr: TIn6Addr): Boolean;
  end;

{$IFDEF POSIX}
  function getifaddrs(var ifap: pifaddrs): Integer; cdecl; external libc name _PU + 'getifaddrs';
  procedure freeifaddrs(ifap: pifaddrs); cdecl; external libc name _PU + 'freeifaddrs';
{$ENDIF}

implementation

uses
  System.Generics.Collections;

class function TncIPUtils.DetectIPFamily(const S: string): TIPFamily;
begin
  if S.Contains(':') then Exit(ipfIPv6);
  if S.Contains('.') then Exit(ipfIPv4);
  Result := ipfUnknown;
end;

function SockAddrToIPString(const SA: PSockAddr; SALen: Integer): string;
{$IFDEF MSWINDOWS}
var
  Buf: array[0..1024] of WideChar;
  BufLen: DWORD;
begin
  Result := '';
  if (SA = nil) or (SALen <= 0) then Exit;

  BufLen := Length(Buf); // number of WideChar slots
  if WSAAddressToStringW(TSockAddr(SA^), SALen, nil, @Buf[0], BufLen) = 0 then
    Result := string(Buf);
{$ELSE}
var
  Buf: array[0..INET6_ADDRSTRLEN - 1] of AnsiChar;
  P: PAnsiChar;
begin
  Result := '';
  FillChar(Buf, SizeOf(Buf), 0);

  if Family = AF_INET then
    P := inet_ntop(AF_INET, @Psockaddr_in(SA).sin_addr, Buf, INET_ADDRSTRLEN)
  else if Family = AF_INET6 then
    P := inet_ntop(AF_INET6, @Psockaddr_in6(SA).sin6_addr, Buf, INET6_ADDRSTRLEN)
  else
    Exit;

  if P <> nil then
    Result := string(AnsiString(Buf));
{$ENDIF}
end;


{$IFDEF MSWINDOWS}
var
  Ws2_32DllHandle: THandle;


class function TncIPUtils.LoadIPv6Functions: Boolean;
begin
  Result := False;

  if Ws2_32DllHandle = 0 then
    Ws2_32DllHandle := LoadLibrary('ws2_32.dll');

  if Ws2_32DllHandle <> 0 then
  begin
    InetPton := GetProcAddress(Ws2_32DllHandle, 'inet_pton');
    InetNtop := GetProcAddress(Ws2_32DllHandle, 'inet_ntop');
    Result := Assigned(InetPton) and Assigned(InetNtop);
  end;
end;
{$ENDIF}


class function TncIPUtils.StripPortFromAddressString(const S: string): string;
var
  P: Integer;
begin
  Result := S;

  if Result = '' then
    Exit;

  // IPv6 form: "[addr]:port"
  if Result.StartsWith('[') then
  begin
    P := Result.IndexOf(']');
    if P > 0 then
      Result := Result.Substring(1, P - 1);
    Exit;
  end;

  // IPv4 form: "a.b.c.d:port"
  P := Result.LastIndexOf(':');
  if (P > 0) and (Result.IndexOf(':') = P) then
    Result := Result.Substring(0, P);
end;

class function TncIPUtils.LocalIPForDestinationIP(
  DestinationIP: AnsiString): string;
{$IFDEF MSWINDOWS}
var
  Fam: TIPFamily;
  S: TSocket;
  SA4: TSockAddrIn;
  SA4_SA: TSockAddr absolute SA4;
  SA6: TSockAddrIn6;
  SA6_SA: TSockAddr absolute SA6;
  LocalSS: TSockAddrStorage;
  LocalSS_SA : TSockAddr absolute LocalSS;
  LocalLen: Integer;
begin
  Result := '';

  Fam := DetectIPFamily(DestinationIP);
  if Fam = ipfUnknown then Exit;

  if Fam = ipfIPv4 then
  begin
    S := socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if S = INVALID_SOCKET then Exit;
    try
      ZeroMemory(@SA4, SizeOf(SA4));
      SA4.sin_family := AF_INET;
      SA4.sin_port := htons(53);
      if InetPton(AF_INET, PAnsiChar(DestinationIP), @SA4.sin_addr) <> 1 then
        Exit;

      // UDP "connect" forces route/interface selection
      connect(S, SA4_SA, SizeOf(SA4));

      ZeroMemory(@LocalSS, SizeOf(LocalSS));
      LocalLen := SizeOf(LocalSS);
      if getsockname(S, LocalSS_SA, LocalLen) = 0 then
        Result := SockAddrToIPString(@LocalSS_SA, LocalLen);
    finally
      closesocket(S);
    end;
  end
  else
  begin
    S := socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if S = INVALID_SOCKET then Exit;
    try
      ZeroMemory(@SA6, SizeOf(SA6));
      SA6.sin6_family := AF_INET6;
      SA6.sin6_port := htons(53);
      if InetPton(AF_INET6, PAnsiChar(DestinationIP), @SA6.sin6_addr) <> 1 then Exit;

      connect(S, SA6_SA, SizeOf(SA6));

      ZeroMemory(@LocalSS, SizeOf(LocalSS));
      LocalLen := SizeOf(LocalSS);
      if getsockname(S, LocalSS_SA, LocalLen) = 0 then
        Result := SockAddrToIPString(@LocalSS_SA, LocalLen);
    finally
      closesocket(S);
    end;
  end;
end;
{$ELSE}
var
  Fam: TIPFamily;
  S: Integer;
  SA4: sockaddr_in;
  SA6: sockaddr_in6;
  LocalSS: sockaddr_storage;
  LocalLen: socklen_t;
begin
  Result := '';

  Fam := DetectIPFamily(DestinationIP);
  if Fam = ipfUnknown then Exit;

  if Fam = ipfIPv4 then
  begin
    S := Posix.SysSocket.socket(AF_INET, SOCK_DGRAM, 0);
    if S < 0 then Exit;
    try
      FillChar(SA4, SizeOf(SA4), 0);
      SA4.sin_family := AF_INET;
      SA4.sin_port := htons(53);
      if inet_pton(AF_INET, PAnsiChar(AnsiString(DestinationIP)), @SA4.sin_addr) <> 1 then Exit;

      Posix.SysSocket.connect(S, sockaddr(SA4), SizeOf(SA4));

      FillChar(LocalSS, SizeOf(LocalSS), 0);
      LocalLen := SizeOf(LocalSS);
      if Posix.SysSocket.getsockname(S, Psockaddr(@LocalSS)^, LocalLen) = 0 then
        Result := SockAddrToIPStringPosix(Psockaddr(@LocalSS), AF_INET);
    finally
      __close(S);
    end;
  end
  else
  begin
    S := Posix.SysSocket.socket(AF_INET6, SOCK_DGRAM, 0);
    if S < 0 then Exit;
    try
      FillChar(SA6, SizeOf(SA6), 0);
      SA6.sin6_family := AF_INET6;
      SA6.sin6_port := htons(53);
      if inet_pton(AF_INET6, PAnsiChar(AnsiString(DestinationIP)), @SA6.sin6_addr) <> 1 then Exit;

      Posix.SysSocket.connect(S, sockaddr(SA6), SizeOf(SA6));

      FillChar(LocalSS, SizeOf(LocalSS), 0);
      LocalLen := SizeOf(LocalSS);
      if Posix.SysSocket.getsockname(S, Psockaddr(@LocalSS)^, LocalLen) = 0 then
        Result := SockAddrToIPStringPosix(Psockaddr(@LocalSS), AF_INET6);
    finally
      __close(S);
    end;
  end;
end;
{$ENDIF}



class constructor TncIPUtils.Create;
begin
  {$IFDEF MSWINDOWS}
  if not LoadIPv6Functions then
    raise EIPError.Create('Failed to load IPv6 functions from ws2_32.dll');
  {$ENDIF}
end;

class function TncIPUtils.StorageToString(const Storage: TSockAddrStorage): string;
begin
  case Storage.ss_family of
    AF_INET:
      begin
        var addr_in := PSockAddrIn(@Storage)^;
        with addr_in.sin_addr.S_un_b do
          Result := Format('%d.%d.%d.%d', [s_b1, s_b2, s_b3, s_b4]);
      end;

    AF_INET6:
      begin
        var addr_in6 := PSockAddrIn6(@Storage)^;
        Result := AddressToString(addr_in6.sin6_addr);
        if IsLinkLocal(Result) then
          Result := Format('%s%%%d', [Result, addr_in6.sin6_scope_id]);
      end;
  else
    Result := '';
  end;
end;

class function TncIPUtils.IsIPv6Storage(const Storage: TSockAddrStorage): Boolean;
begin
  Result := Storage.ss_family = AF_INET6;
end;

class function TncIPUtils.GetStorageFamily(const Storage: TSockAddrStorage): Word;
begin
  Result := Storage.ss_family;
end;

class function TncIPUtils.StorageToIPv6Address(const Storage: TSockAddrStorage;
  out Addr: TSockAddrIn6): Boolean;
begin
  Result := Storage.ss_family = AF_INET6;
  if Result then
    Addr := PSockAddrIn6(@Storage)^;
end;

class function TncIPUtils.GetIPFromStorage(const Storage: TSockAddrStorage): string;
begin
  Result := StorageToString(Storage);
end;

class function TncIPUtils.GetPortFromStorage(const Storage: TSockAddrStorage): Word;
begin
  case Storage.ss_family of
    AF_INET: Result := ntohs(PSockAddrIn(@Storage)^.sin_port);
    AF_INET6: Result := ntohs(PSockAddrIn6(@Storage)^.sin6_port);
  else
    Result := 0;
  end;
end;

class function TncIPUtils.IsIPv6ValidAddress(const AddrStr: string): Boolean;
var
  Addr: TIn6Addr;
begin
  Result := StringToAddress(AddrStr, Addr);
end;

class function TncIPUtils.AddressToString(const Addr: TIn6Addr): string;
var
  StringBuffer: array[0..IPV6_STR_MAX_LEN-1] of AnsiChar;
begin
  {$IFDEF MSWINDOWS}
  if InetNtop(AF_INET6, @Addr, StringBuffer, IPV6_STR_MAX_LEN) = nil then
    raise EIPError.Create('Failed to convert IPv6 address to string: ' +
      SysErrorMessage(WSAGetLastError));
  {$ELSE}
  if Posix.ArpaInet.inet_ntop(AF_INET6, @Addr, StringBuffer, IPV6_STR_MAX_LEN) = nil then
    raise EIPError.Create('Failed to convert IPv6 address to string: ' +
      SysErrorMessage(GetLastError));
  {$ENDIF}

  Result := string(AnsiString(StringBuffer));
end;

class function TncIPUtils.AllLocalIPs: TArray<string>;
type
  Psockaddr_in  = ^TSockAddrIn;
  Psockaddr_in6 = ^TSockAddrIn6;
  function SockAddrToIPStringPosix(const SA: Psockaddr; Family: Integer): string;
  var
    Buf: array[0..45] of AnsiChar;
    P: PAnsiChar;
  begin
    Result := '';
    FillChar(Buf, SizeOf(Buf), 0);

    if Family = AF_INET then
      P := inet_ntop(AF_INET, @Psockaddr_in(SA).sin_addr, Buf, 16)
    else if Family = AF_INET6 then
      P := inet_ntop(AF_INET6, @Psockaddr_in6(SA).sin6_addr, Buf, 46)
    else
      Exit;

    if P <> nil then
      Result := string(AnsiString(Buf));
  end;
var
  L: TList<string>;
begin
  L := TList<string>.Create;
  try
{$IFDEF MSWINDOWS}

    // Windows: GetAdaptersAddresses
    var BufLen: ULONG := 15 * 1024;
    var Adapters: PIP_ADAPTER_ADDRESSES := nil;
    GetMem(Adapters, BufLen);
    try
      var Flags: ULONG :=
        GAA_FLAG_SKIP_ANYCAST or
        GAA_FLAG_SKIP_MULTICAST or
        GAA_FLAG_SKIP_DNS_SERVER;

      if GetAdaptersAddresses(AF_UNSPEC, Flags, nil, Adapters, @BufLen) = NO_ERROR then
      begin
        var Cur := Adapters;
        while Cur <> nil do
        begin
          var Uni := Cur.FirstUnicastAddress;
          while Uni <> nil do
          begin
            var S := SockAddrToIPString(Uni.Address.lpSockaddr, Uni.Address.iSockaddrLength);
            if (S <> '') and (L.IndexOf(S) < 0) then
              L.Add(S);
            Uni := Uni.Next;
          end;
          Cur := Cur.Next;
        end;
      end;
    finally
      FreeMem(Adapters);
    end;
{$ENDIF}

{$IFDEF POSIX}
    // POSIX: getifaddrs
    var IfAddrs: Pifaddrs := nil;
    if getifaddrs(IfAddrs) = 0 then
    try
      var Cur: Pifaddrs := IfAddrs;
      while Cur <> nil do
      begin
        if (Cur.ifa_addr <> nil) then
        begin
          var Family := Cur.ifa_addr.sa_family;
          if (Family = AF_INET) or (Family = AF_INET6) then
          begin
            var S := SockAddrToIPStringPosix(Cur.ifa_addr, Family);
            if (S <> '') and (L.IndexOf(S) < 0) then
              L.Add(S);
          end;
        end;
        Cur := Cur.ifa_next;
      end;
    finally
      freeifaddrs(IfAddrs);
    end;
{$ENDIF}

    Result := L.ToArray;
  finally
    L.Free;
  end;
end;

class function TncIPUtils.StringToAddress(const AddrStr: string; out Addr: TIn6Addr): Boolean;
var
  AnsiAddr: AnsiString;
begin
  AnsiAddr := AnsiString(AddrStr);
  {$IFDEF MSWINDOWS}
  Result := InetPton(AF_INET6, PAnsiChar(AnsiAddr), @Addr) = 1;
  {$ELSE}
  Result := Posix.ArpaInet.inet_pton(AF_INET6, PAnsiChar(AnsiAddr), @Addr) = 1;
  {$ENDIF}
end;

class function TncIPUtils.IsLinkLocal(const AddrStr: string): Boolean;
begin
  // Link-local addresses start with fe80::/10
  Result := (Length(AddrStr) >= 4) and
            (LowerCase(Copy(AddrStr, 1, 4)) = 'fe80');
end;

class function TncIPUtils.IsLocalIP(IP: string): boolean;
begin
  Result := False;
  var ary := AllLocalIPs;
  for var lip in ary do
    if lip = IP then
      exit(True);
end;

class function TncIPUtils.NormalizeAddress(const AddrStr: string): string;
var
  Addr: TIn6Addr;
begin
  if StringToAddress(AddrStr, Addr) then
    Result := AddressToString(Addr)
  else
    raise EIPError.CreateFmt('Invalid IPv6 address: %s', [AddrStr]);
end;

class function TncIPUtils.AddressToPresentation(const Addr: TIn6Addr): string;
var
  i: Integer;
  NonZeroFound: Boolean;
begin
  Result := '';
  NonZeroFound := False;

  // Convert words to hex representation
  for i := 0 to 7 do
  begin
    if (Addr.s6_words[i] <> 0) or NonZeroFound then
    begin
      if Result <> '' then
        Result := Result + ':';
      Result := Result + IntToHex(Addr.s6_words[i], 1);
      NonZeroFound := True;
    end;
  end;

  // Handle all-zero case
  if Result = '' then
    Result := '::'
  else if not NonZeroFound then
    Result := Result + ':';
end;

class function TncIPUtils.PresentationToAddress(const Present: string;
  var Addr: TIn6Addr): Boolean;
begin
  FillChar(Addr, SizeOf(Addr), 0);
  Result := StringToAddress(Present, Addr);
end;

initialization
  {$IFDEF MSWINDOWS}
  Ws2_32DllHandle := 0;
  {$ENDIF}

finalization
  {$IFDEF MSWINDOWS}
  if Ws2_32DllHandle <> 0 then
    FreeLibrary(Ws2_32DllHandle);
  {$ENDIF}

end.


