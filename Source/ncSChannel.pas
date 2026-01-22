unit ncSChannel;

// /////////////////////////////////////////////////////////////////////////////
//
// NetCom7 Package
//
// This unit implements TLS/SSL support for NetCom7 through Windows SChannel
// (Secure Channel) API integration. Provides secure communication capabilities
// for both TCP servers and clients using native Windows cryptographic services.
//
// 13/07/2025 - by J.Pauwels
// - Initial creation
//
// Written by J.Pauwels
//
// /////////////////////////////////////////////////////////////////////////////

interface

uses
  SysUtils,
  Classes,
  Windows;

//******************************************************************************
// CryptoAPI
//******************************************************************************
const
  CERT_STORE_PROV_FILENAME = 8;
  CERT_STORE_PROV_MEMORY = 2;
  CERT_STORE_OPEN_EXISTING_FLAG = $00004000;
  CERT_STORE_READONLY_FLAG = $00008000;
  PKCS12_NO_PERSIST_KEY = $00008000;
  PKCS12_INCLUDE_EXTENDED_PROPERTIES = $00000010;

  CERT_FIND_ANY = 0;
  // no check is made to determine whether memory for contexts remains allocated
  CERT_CLOSE_STORE_DEFAULT = 0;
  // force freeing all contexts associated with the store
  CERT_CLOSE_STORE_FORCE_FLAG = 1;
  // checks for nonfreed certificate, CRL, and CTL context to report an error on leak
  CERT_CLOSE_STORE_CHECK_FLAG = 2;

  CRYPT_ASN_ENCODING = $00000001;
  CRYPT_NDR_ENCODING = $00000002;
  X509_ASN_ENCODING = $00000001;
  X509_NDR_ENCODING = $00000002;
  PKCS_7_ASN_ENCODING = $00010000;
  PKCS_7_NDR_ENCODING = $00020000;
                                          // TCryptCertUsage mormot.crypt.secure
  CERT_OFFLINE_CRL_SIGN_KEY_USAGE  = $02; // cuCrlSign
  CERT_KEY_CERT_SIGN_KEY_USAGE     = $04; // cuKeyCertSign
  CERT_KEY_AGREEMENT_KEY_USAGE     = $08; // cuKeyAgreement
  CERT_DATA_ENCIPHERMENT_KEY_USAGE = $10; // cuDataEncipherment
  CERT_KEY_ENCIPHERMENT_KEY_USAGE  = $20; // cuKeyEncipherment
  CERT_NON_REPUDIATION_KEY_USAGE   = $40; // cuNonRepudiation
  CERT_DIGITAL_SIGNATURE_KEY_USAGE = $80; // cuDigitalSignature

  CERT_KEY_PROV_INFO_PROP_ID = 2;
  CERT_HASH_PROP_ID          = 3;
  CERT_FRIENDLY_NAME_PROP_ID = 11;

  CERT_SIMPLE_NAME_STR = 1;
  CERT_OID_NAME_STR    = 2;
  CERT_X500_NAME_STR   = 3;

  CRYPT_OID_INFO_OID_KEY   = 1;

type
  HCRYPTPROV = pointer;
  HCRYPTKEY = pointer;
  HCRYPTHASH = pointer;
  HCERTSTORE = pointer;

  CRYPTOAPI_BLOB = record
    cbData: DWORD;
    pbData: PByteArray;
  end;
  CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB;
  CERT_NAME_BLOB     = CRYPTOAPI_BLOB;
  CRYPT_OBJID_BLOB   = CRYPTOAPI_BLOB;
  CRYPT_DATA_BLOB    = CRYPTOAPI_BLOB;
  PCRYPT_DATA_BLOB   = ^CRYPT_DATA_BLOB;

  CRYPT_BIT_BLOB = record
    cbData: DWORD;
    pbData: PByteArray;
    cUnusedBits: DWORD;
  end;

  CRYPT_ALGORITHM_IDENTIFIER = record
    pszObjId: PAnsiChar;
    Parameters: CRYPT_OBJID_BLOB;
  end;

  CERT_PUBLIC_KEY_INFO = record
    Algorithm: CRYPT_ALGORITHM_IDENTIFIER;
    PublicKey: CRYPT_BIT_BLOB;
  end;

  CERT_EXTENSION = record
    pszObjId: PAnsiChar;
    fCritical: BOOL;
    Blob: CRYPT_OBJID_BLOB;
  end;
  PCERT_EXTENSION = ^CERT_EXTENSION;
  CERT_EXTENSIONS = array[word] of CERT_EXTENSION;
  PCERT_EXTENSIONS = ^CERT_EXTENSIONS;

  CERT_INFO = record
    dwVersion: DWORD;
    SerialNumber: CRYPT_INTEGER_BLOB;
    SignatureAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    Issuer: CERT_NAME_BLOB;
    NotBefore: TFileTime;
    NotAfter: TFileTime;
    Subject: CERT_NAME_BLOB;
    SubjectPublicKeyInfo: CERT_PUBLIC_KEY_INFO;
    IssuerUniqueId: CRYPT_BIT_BLOB;
    SubjectUniqueId: CRYPT_BIT_BLOB;
    cExtension: DWORD;
    rgExtension: PCERT_EXTENSIONS;
  end;
  PCERT_INFO = ^CERT_INFO;

  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    pCertInfo: PCERT_INFO;
    hCertStore: HCERTSTORE;
  end;
  PCCERT_CONTEXT = ^CERT_CONTEXT;
  PPCCERT_CONTEXT = ^PCCERT_CONTEXT;

CRYPT_KEY_PROV_PARAM = record
    dwParam: DWORD;
    pbData: PByte;
    cbData: DWORD;
    dwFlags: DWORD;
  end;
  PCRYPT_KEY_PROV_PARAM = ^CRYPT_KEY_PROV_PARAM;

  CRYPT_KEY_PROV_INFO = record
    pwszContainerName: PWideChar;
    pwszProvName: PWideChar;
    dwProvType: DWORD;
    dwFlags: DWORD;
    cProvParam: DWORD;
    rgProvParam: PCRYPT_KEY_PROV_PARAM;
    dwKeySpec: DWORD;
  end;
  PCRYPT_KEY_PROV_INFO = ^CRYPT_KEY_PROV_INFO;

  CRYPT_OID_INFO = record
    cbSize: DWORD;
    pszOID: PAnsiChar;
    pwszName: PWideChar;
    dwGroupId: DWORD;
    Union: record
      case integer of
        0: (dwValue: DWORD);
        1: (Algid: DWORD);
        2: (dwLength: DWORD);
    end;
    ExtraInfo: CRYPTOAPI_BLOB;
  end;
  PCRYPT_OID_INFO = ^CRYPT_OID_INFO;

  PCCRL_CONTEXT = pointer;
  PPCCRL_CONTEXT = ^PCCRL_CONTEXT;
  PCRYPT_ATTRIBUTE = pointer;

  CRYPT_SIGN_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgEncodingType: DWORD;
    pSigningCert: PCCERT_CONTEXT;
    HashAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    pvHashAuxInfo: pointer;
    cMsgCert: DWORD;
    rgpMsgCert: PPCCERT_CONTEXT;
    cMsgCrl: DWORD;
    rgpMsgCrl: PPCCRL_CONTEXT;
    cAuthAttr: DWORD;
    rgAuthAttr: PCRYPT_ATTRIBUTE;
    cUnauthAttr: DWORD;
    rgUnauthAttr: PCRYPT_ATTRIBUTE;
    dwFlags: DWORD;
    dwInnerContentType: DWORD;
    HashEncryptionAlgorithm: CRYPT_ALGORITHM_IDENTIFIER;
    pvHashEncryptionAuxInfo: pointer;
  end;

  PFN_CRYPT_GET_SIGNER_CERTIFICATE = function(pvGetArg: pointer;
    dwCertEncodingType: DWORD; pSignerId: PCERT_INFO;
    hMsgCertStore: HCERTSTORE): PCCERT_CONTEXT; stdcall;
  CRYPT_VERIFY_MESSAGE_PARA = record
    cbSize: DWORD;
    dwMsgAndCertEncodingType: DWORD;
    hCryptProv: HCRYPTPROV;
    pfnGetSignerCertificate: PFN_CRYPT_GET_SIGNER_CERTIFICATE;
    pvGetArg: pointer;
  end;

//******************************************************************************
// Low-Level SSPI/SChannel
//******************************************************************************
const
  SECBUFFER_VERSION = 0;

  SECBUFFER_EMPTY          = 0;
  SECBUFFER_DATA           = 1;
  SECBUFFER_TOKEN          = 2;
  SECBUFFER_EXTRA          = 5;
  SECBUFFER_STREAM_TRAILER = 6;
  SECBUFFER_STREAM_HEADER  = 7;
  SECBUFFER_PADDING        = 9;
  SECBUFFER_STREAM         = 10;
  SECBUFFER_ALERT          = 17;

  SECPKG_CRED_INBOUND  = 1;
  SECPKG_CRED_OUTBOUND = 2;

  SECPKG_ATTR_SIZES               = 0;
  SECPKG_ATTR_NAMES               = 1;
  SECPKG_ATTR_STREAM_SIZES        = 4;
  SECPKG_ATTR_NEGOTIATION_INFO    = 12;
  SECPKG_ATTR_ACCESS_TOKEN        = 13;
  SECPKG_ATTR_REMOTE_CERT_CONTEXT = $53;
  SECPKG_ATTR_CONNECTION_INFO     = $5a;
  SECPKG_ATTR_CIPHER_INFO         = $64; // Vista+ new API
  SECPKG_ATTR_C_ACCESS_TOKEN      = $80000012;
  SECPKG_ATTR_C_FULL_ACCESS_TOKEN = $80000082;

  SECPKGCONTEXT_CIPHERINFO_V1 = 1;

  SECURITY_NETWORK_DREP = 0;
  SECURITY_NATIVE_DREP  = $10;

  ISC_REQ_DELEGATE               = $00000001;
  ISC_REQ_MUTUAL_AUTH            = $00000002;
  ISC_REQ_REPLAY_DETECT          = $00000004;
  ISC_REQ_SEQUENCE_DETECT        = $00000008;
  ISC_REQ_CONFIDENTIALITY        = $00000010;
  ISC_REQ_USE_SESSION_KEY        = $00000020;
  ISC_REQ_PROMPT_FOR_CREDS       = $00000040;
  ISC_REQ_USE_SUPPLIED_CREDS     = $00000080;
  ISC_REQ_ALLOCATE_MEMORY        = $00000100;
  ISC_REQ_USE_DCE_STYLE          = $00000200;
  ISC_REQ_DATAGRAM               = $00000400;
  ISC_REQ_CONNECTION             = $00000800;
  ISC_REQ_CALL_LEVEL             = $00001000;
  ISC_REQ_FRAGMENT_SUPPLIED      = $00002000;
  ISC_REQ_EXTENDED_ERROR         = $00004000;
  ISC_REQ_STREAM                 = $00008000;
  ISC_REQ_INTEGRITY              = $00010000;
  ISC_REQ_IDENTIFY               = $00020000;
  ISC_REQ_NULL_SESSION           = $00040000;
  ISC_REQ_MANUAL_CRED_VALIDATION = $00080000;
  ISC_REQ_RESERVED1              = $00100000;
  ISC_REQ_FRAGMENT_TO_FIT        = $00200000;
  ISC_REQ_FLAGS = ISC_REQ_SEQUENCE_DETECT or
                  ISC_REQ_REPLAY_DETECT or
                  ISC_REQ_CONFIDENTIALITY or
                  ISC_REQ_EXTENDED_ERROR or
                  ISC_REQ_ALLOCATE_MEMORY or
                  ISC_REQ_STREAM;

  ASC_REQ_REPLAY_DETECT   = $00000004;
  ASC_REQ_SEQUENCE_DETECT = $00000008;
  ASC_REQ_CONFIDENTIALITY = $00000010;
  ASC_REQ_ALLOCATE_MEMORY = $00000100;
  ASC_REQ_EXTENDED_ERROR  = $00008000;
  ASC_REQ_STREAM          = $00010000;
  ASC_REQ_FLAGS = ASC_REQ_SEQUENCE_DETECT or
                  ASC_REQ_REPLAY_DETECT or
                  ASC_REQ_CONFIDENTIALITY or
                  ASC_REQ_EXTENDED_ERROR or
                  ASC_REQ_ALLOCATE_MEMORY or
                  ASC_REQ_STREAM;

  SEC_E_OK = 0;

  SEC_I_CONTINUE_NEEDED        = $00090312;
  SEC_I_COMPLETE_NEEDED        = $00090313;
  SEC_I_COMPLETE_AND_CONTINUE  = $00090314;
  SEC_I_CONTEXT_EXPIRED	       = $00090317;
  SEC_I_INCOMPLETE_CREDENTIALS = $00090320;
  SEC_I_RENEGOTIATE            = $00090321;

  SEC_E_UNSUPPORTED_FUNCTION   = $80090302;
  SEC_E_INVALID_TOKEN          = $80090308;
  SEC_E_MESSAGE_ALTERED        = $8009030F;
  SEC_E_CONTEXT_EXPIRED        = $80090317;
  SEC_E_INCOMPLETE_MESSAGE     = $80090318;
  SEC_E_BUFFER_TOO_SMALL       = $80090321;
  SEC_E_ILLEGAL_MESSAGE        = $80090326;
  SEC_E_CERT_UNKNOWN           = $80090327;
  SEC_E_CERT_EXPIRED           = $80090328;
  SEC_E_ENCRYPT_FAILURE        = $80090329;
  SEC_E_DECRYPT_FAILURE        = $80090330;
  SEC_E_ALGORITHM_MISMATCH     = $80090331;

  SEC_WINNT_AUTH_IDENTITY_UNICODE = $02;

  SCHANNEL_SHUTDOWN = 1;

  SCHANNEL_CRED_VERSION = 4;
  SCH_CREDENTIALS_VERSION = 5;

  SCH_CRED_NO_SYSTEM_MAPPER                    = $00000002;
  SCH_CRED_NO_SERVERNAME_CHECK                 = $00000004;
  SCH_CRED_MANUAL_CRED_VALIDATION              = $00000008;
  SCH_CRED_NO_DEFAULT_CREDS                    = $00000010;
  SCH_CRED_AUTO_CRED_VALIDATION                = $00000020;
  SCH_CRED_USE_DEFAULT_CREDS                   = $00000040;
  SCH_CRED_DISABLE_RECONNECTS                  = $00000080;
  SCH_CRED_REVOCATION_CHECK_END_CERT           = $00000100;
  SCH_CRED_REVOCATION_CHECK_CHAIN              = $00000200;
  SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = $00000400;
  SCH_CRED_IGNORE_NO_REVOCATION_CHECK          = $00000800;
  SCH_CRED_IGNORE_REVOCATION_OFFLINE           = $00001000;
  SCH_CRED_RESTRICTED_ROOTS                    = $00002000;
  SCH_CRED_REVOCATION_CHECK_CACHE_ONLY         = $00004000;
  SCH_CRED_CACHE_ONLY_URL_RETRIEVAL            = $00008000;
  SCH_CRED_MEMORY_STORE_CERT                   = $00010000;
  SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE  = $00020000;
  SCH_SEND_ROOT_CERT                           = $00040000;
  SCH_USE_STRONG_CRYPTO                        = $00400000;

  UNISP_NAME = 'Microsoft Unified Security Protocol Provider';

  SP_PROT_TLS1_0_SERVER = $0040;
  SP_PROT_TLS1_0_CLIENT = $0080;
  SP_PROT_TLS1_1_SERVER = $0100;
  SP_PROT_TLS1_1_CLIENT = $0200;
  SP_PROT_TLS1_2_SERVER = $0400; // first SP_PROT_TLS_SAFE protocol
  SP_PROT_TLS1_2_CLIENT = $0800;
  SP_PROT_TLS1_3_SERVER = $1000; // Windows 11 or Windows Server 2022 ;)
  SP_PROT_TLS1_3_CLIENT = $2000;
  // SSL 2/3 protocols ($04,$08,$10,$20) are just not defined at all
  SP_PROT_TLS1_0 = SP_PROT_TLS1_0_CLIENT or SP_PROT_TLS1_0_SERVER;
  SP_PROT_TLS1_1 = SP_PROT_TLS1_1_CLIENT or SP_PROT_TLS1_1_SERVER;
  SP_PROT_TLS1_2 = SP_PROT_TLS1_2_CLIENT or SP_PROT_TLS1_2_SERVER;
  SP_PROT_TLS1_3 = SP_PROT_TLS1_3_CLIENT or SP_PROT_TLS1_3_SERVER;
  // TLS 1.0 and TLS 1.1 are universally deprecated
  SP_PROT_TLS_SAFE   = SP_PROT_TLS1_2 or SP_PROT_TLS1_3;
  SP_PROT_TLS_UNSAFE = pred(SP_PROT_TLS1_2_SERVER);


type
  {$ifdef WIN64}
  LONG_PTR = Int64;
  {$else}
  LONG_PTR = integer;
  {$endif}

  ALG_ID = cardinal;
  TALG_IDs = array[word] of ALG_ID;
  PALG_IDs = ^TALG_IDs;

  _HMAPPER = pointer;

  /// SSPI context handle
  TSecHandle = record
    dwLower: LONG_PTR;
    dwUpper: LONG_PTR;
  end;
  PSecHandle = ^TSecHandle;

  // some context aliases, as defined in SSPI headers
  TCredHandle = type TSecHandle;
  PCredHandle = type PSecHandle;
  TCtxtHandle = type TSecHandle;
  PCtxtHandle = type PSecHandle;

  TSChannelCred = record
    dwVersion: cardinal;
    cCreds: cardinal;
    paCred: PPCCERT_CONTEXT;
    hRootStore: HCERTSTORE;
    cMappers: cardinal;
    aphMappers: _HMAPPER;
    cSupportedAlgs: cardinal;
    palgSupportedAlgs: PALG_IDs;
    grbitEnabledProtocols: cardinal;
    dwMinimumCipherStrength: cardinal;
    dwMaximumCipherStrength: cardinal;
    dwSessionLifespan: cardinal;
    dwFlags: cardinal;
    dwCredFormat: cardinal;
  end;
  PSChannelCred = ^TSChannelCred;

  TSecBuffer = record
    cbBuffer: cardinal;
    BufferType: cardinal;
    pvBuffer: pointer;
  end;
  PSecBuffer = ^TSecBuffer;

  TSecBufferDesc = record
    ulVersion: cardinal;
    cBuffers: cardinal;
    pBuffers: PSecBuffer;
  end;
  PSecBufferDesc = ^TSecBufferDesc;

  TTimeStamp = record
    dwLowDateTime: cardinal;
    dwHighDateTime: cardinal;
  end;
  PTimeStamp = ^TTimeStamp;

  TSecPkgContextStreamSizes = record
    cbHeader: cardinal;
    cbTrailer: cardinal;
    cbMaximumMessage: cardinal;
    cBuffers: cardinal;
    cbBlockSize: cardinal;
  end;
  PSecPkgContextStreamSizes = ^TSecPkgContextStreamSizes;

  /// store information about a SSPI package
  TSecPkgInfoW = record
    fCapabilities: Cardinal;
    wVersion: Word;
    wRPCID: Word;
    cbMaxToken: Cardinal;
    Name: PWideChar;
    Comment: PWideChar;
  end;
  /// pointer to information about a SSPI package
  PSecPkgInfoW = ^TSecPkgInfoW;

  ESChannel = class(Exception);


  {$ifdef USERECORDWITHMETHODS}TSChannelClient = record
    {$else}TSChannelClient = object{$endif}
  private
    Cred: TCredHandle;
    Ctxt: TCtxtHandle;
    Sizes: TSecPkgContextStreamSizes;
    Data, Input: AnsiString;
    InputSize, DataPos, DataCount, InputCount: integer;
    procedure HandshakeLoop(aLine: TObject);
    procedure AppendData(const aBuffer: TSecBuffer);
  public
    Initialized: boolean;
    SessionClosed: boolean;
    procedure AfterConnection(aLine: TObject; const aTargetHost: AnsiString; aIgnoreCertificateErrors: boolean);
    procedure BeforeDisconnection(aLine: TObject);
    function Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
    function Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
  end;

  // Server-side SChannel implementation
  {$ifdef USERECORDWITHMETHODS}TSChannelServer = record
    {$else}TSChannelServer = object{$endif}
  private
    Cred: TCredHandle;
    Ctxt: TCtxtHandle;
    Sizes: TSecPkgContextStreamSizes;
    Data, Input: AnsiString;
    InputSize, DataPos, DataCount, InputCount: integer;
    procedure HandshakeLoop(aLine: TObject);
    procedure AppendData(const aBuffer: TSecBuffer);
  public
    Initialized: boolean;
    HandshakeCompleted: boolean;
    SessionClosed: boolean;
    procedure AfterConnection(aLine: TObject; const aCertificateFile, aPrivateKeyPassword: AnsiString);
    procedure BeforeDisconnection(aLine: TObject);
    function Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
    function Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
  end;


// crypt32.dll API calls

function CertOpenStore(lpszStoreProvider: PAnsiChar; dwEncodingType: cardinal;
  hCryptProv: HCRYPTPROV; dwFlags: cardinal; pvPara: pointer): HCERTSTORE; stdcall;
  external 'crypt32.dll';

function CertCloseStore(hCertStore: HCERTSTORE; dwFlags: cardinal): BOOL; stdcall;
  external 'crypt32.dll';

function CertEnumCertificatesInStore(hCertStore: HCERTSTORE;
  pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT; stdcall;
  external 'crypt32.dll';

function CertFreeCertificateContext(pCertContext: PCCERT_CONTEXT): BOOL; stdcall;
  external 'crypt32.dll';

function PFXImportCertStore(pPFX: pointer; szPassword: PWideChar;
  dwFlags: cardinal): HCERTSTORE; stdcall;
  external 'crypt32.dll';

// secur32.dll API calls

function AcquireCredentialsHandleW(pszPrincipal, pszPackage: PWideChar;
  fCredentialUse: cardinal; pvLogonId: pointer; pAuthData: PSChannelCred;
  pGetKeyFn: pointer; pvGetKeyArgument: pointer; phCredential: PCredHandle;
  ptsExpiry: PTimeStamp): cardinal; stdcall;
  external 'secur32.dll';

function QuerySecurityPackageInfoW(pszPackageName: PWideChar;
  var ppPackageInfo: PSecPkgInfoW): cardinal; stdcall;
  external 'secur32.dll';

function FreeCredentialsHandle(phCredential: PCredHandle): cardinal; stdcall;
  external 'secur32.dll';

function InitializeSecurityContextW(phCredential: PCredHandle; phContext: PCtxtHandle;
  pszTargetName: PWideChar; fContextReq, Reserved1, TargetDataRep: cardinal;
  pInput: PSecBufferDesc; Reserved2: cardinal; phNewContext: PCtxtHandle;
  pOutput: PSecBufferDesc; var pfContextAttr: cardinal;
  ptsExpiry: PTimeStamp): cardinal; stdcall;
  external 'secur32.dll';

function AcceptSecurityContext(phCredential: PCredHandle; phContext: PCtxtHandle;
  pInput: PSecBufferDesc; fContextReq, TargetDataRep: cardinal;
  phNewContext: PCtxtHandle; pOutput: PSecBufferDesc; var pfContextAttr: cardinal;
  ptsExpiry: PTimeStamp): cardinal; stdcall;
  external 'secur32.dll';

function DeleteSecurityContext(phContext: PCtxtHandle): cardinal; stdcall;
  external 'secur32.dll';

function ApplyControlToken(phContext: PCtxtHandle;
  pInput: PSecBufferDesc): cardinal; stdcall;
  external 'secur32.dll';

function QueryContextAttributesW(phContext: PCtxtHandle; ulAttribute: cardinal;
  pBuffer: pointer): cardinal; stdcall;
  external 'secur32.dll';

function FreeContextBuffer(pvContextBuffer: pointer): cardinal; stdcall;
  external 'secur32.dll';

function EncryptMessage(phContext: PCtxtHandle; fQOP: cardinal;
  pMessage: PSecBufferDesc; MessageSeqNo: cardinal): cardinal; stdcall;
  external 'secur32.dll';

function DecryptMessage(phContext: PCtxtHandle; pMessage: PSecBufferDesc;
  MessageSeqNo: cardinal; pfQOP: PCardinal): cardinal; stdcall;
  external 'secur32.dll';

implementation

// Add reference to NetCom7 lines unit
uses ncLines;

// We make a descendant of TncLine so that we can access the protected methods
type
  TncLineInternal = class(TncLine);

{ Certificate Loading Functions }

function LoadCertificateFromPFX(const FileName: AnsiString; const Password: AnsiString): PCCERT_CONTEXT;
var
  FileHandle: THandle;
  FileSize: DWORD;
  PFXData: array of Byte;
  BytesRead: DWORD;
  PFXBlob: CRYPT_DATA_BLOB;
  CertStore: HCERTSTORE;
  PasswordW: WideString;
begin
  Result := nil;

  // Read PFX file
  FileHandle := CreateFileA(PAnsiChar(FileName), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if FileHandle = INVALID_HANDLE_VALUE then
  begin
    // Failed to open file
    Exit;
  end;

  try
    FileSize := GetFileSize(FileHandle, nil);
    if FileSize = INVALID_FILE_SIZE then
    begin
      // Invalid file size
      Exit;
    end;

    SetLength(PFXData, FileSize);
    if not ReadFile(FileHandle, PFXData[0], FileSize, BytesRead, nil) or (BytesRead <> FileSize) then
    begin
      // Failed to read file data
      Exit;
    end;
  finally
    CloseHandle(FileHandle);
  end;

  // Import PFX
  PFXBlob.cbData := FileSize;
  PFXBlob.pbData := @PFXData[0];
  PasswordW := WideString(string(Password)); // Convert AnsiString to WideString

  // Import with no flags to allow full private key access for TLS operations
  CertStore := PFXImportCertStore(@PFXBlob, PWideChar(PasswordW), 0);
  if CertStore = nil then
  begin
    // PFXImportCertStore failed
    Exit;
  end;

  try
    // Get first certificate from store
    Result := CertEnumCertificatesInStore(CertStore, nil);
  finally
    CertCloseStore(CertStore, 0);
  end;
end;

{ SChannel Simplified Cleanup Functions}

/// Simplified cleanup for security context handles
procedure FreeSecurityContextSafe(var handle: TCtxtHandle);
begin
  if (handle.dwLower <> 0) or (handle.dwUpper <> 0) then begin
    DeleteSecurityContext(@handle);
    FillChar(handle, SizeOf(handle), 0);
  end;
end;

/// Simplified cleanup for credential handles
procedure FreeCredentialsHandleSafe(var handle: TCredHandle);
begin
  if (handle.dwLower <> 0) or (handle.dwUpper <> 0) then begin
    FreeCredentialsHandle(@handle);
    FillChar(handle, SizeOf(handle), 0);
  end;
end;

/// Check if credential handle is in uninitialized state
function IsCredHandleInvalid(const handle: TCredHandle): Boolean;
begin
  Result := (handle.dwLower = 0) and (handle.dwUpper = 0);
end;

{ TSChannel Helper Functions }

procedure RaiseLastError; // not defined e.g. with Delphi 5
var
  LastError: Integer;
begin
  LastError := GetLastError;
  if LastError <> 0 then
    raise ESChannel.CreateFmt('System Error %d [%s]', [LastError, SysErrorMessage(LastError)])
  else
    raise ESChannel.Create('Unknown SChannel error');
end;

function CheckSEC_E_OK(res: cardinal): cardinal;
begin
  if res <> SEC_E_OK then
  begin
    case res of
      $80090318: raise ESChannel.Create('SEC_E_INCOMPLETE_MESSAGE');
      $80090308: raise ESChannel.Create('SEC_E_INVALID_TOKEN');
      $00090312: raise ESChannel.Create('SEC_I_CONTINUE_NEEDED (unexpected)');
      $00090320: raise ESChannel.Create('SEC_I_INCOMPLETE_CREDENTIALS (unexpected)');
      $00090321: raise ESChannel.Create('SEC_I_RENEGOTIATE (unexpected)');
      $00090317: raise ESChannel.Create('SEC_I_CONTEXT_EXPIRED (unexpected)');
      else
        raise ESChannel.CreateFmt('SChannel error: 0x%08X', [res]);
    end;
  end;
  result := res;
end;

function CheckSocket(res: integer): cardinal;
begin
  if res <= 0 then
    raise ESChannel.CreateFmt('Socket Error %d', [res]);
  result := res;
end;

const
  TLSRECMAXSIZE = 19000; // stack buffers for TSChannelClient.Receive/Send

type
  {$ifdef USERECORDWITHMETHODS}THandshakeBuf = record
    {$else}THandshakeBuf = object{$endif}
  public
    buf: array[0..4] of TSecBuffer;
    input, output: TSecBufferDesc;
    procedure Init;
  end;

procedure THandshakeBuf.Init;
begin
  input.ulVersion := SECBUFFER_VERSION;
  input.cBuffers := 2;
  input.pBuffers := @buf[0];
  buf[0].cbBuffer := 0;
  buf[0].BufferType := SECBUFFER_TOKEN;
  buf[0].pvBuffer := nil;
  buf[1].cbBuffer := 0;
  buf[1].BufferType := SECBUFFER_EMPTY;
  buf[1].pvBuffer := nil;
  output.ulVersion := SECBUFFER_VERSION;
  output.cBuffers := 1;
  output.pBuffers := @buf[2];
  buf[2].cbBuffer := 0;
  buf[2].BufferType := SECBUFFER_TOKEN;
  buf[2].pvBuffer := nil;
end;

{ TSChannelClient - Client-side SChannel implementation }

procedure TSChannelClient.AppendData(const aBuffer: TSecBuffer);
var
  newlen: integer;
begin
  newlen := DataCount + integer(aBuffer.cbBuffer);
  if newlen > Length(Data) then
    SetLength(Data, newlen);
  Move(aBuffer.pvBuffer^, PByteArray(Data)[DataCount], aBuffer.cbBuffer);
  inc(DataCount, aBuffer.cbBuffer);
end;

procedure TSChannelClient.AfterConnection(aLine: TObject; const aTargetHost: AnsiString; aIgnoreCertificateErrors: boolean);
var
  TargetHostString: WideString;
  f: cardinal;
  res: cardinal;
  schannelCred: TSChannelCred;
  buf: THandshakeBuf;
  trial: integer;
  lastError: cardinal;

begin
  trial := 0;

  // Retry loop for Windows 7/8 TLS bugs
  while true do
  try
    // Clean up any existing TLS context from previous connection
    if Initialized then
    begin
      FreeSecurityContextSafe(Ctxt);
      FreeCredentialsHandleSafe(Cred);
      Initialized := false;
      SessionClosed := false;
      DataCount := 0;
      DataPos := 0;
    end;

    // Setup target host for handshake
    TargetHostString := WideString(string(aTargetHost));

    // Setup SChannel credentials
    FillChar(schannelCred, SizeOf(schannelCred), 0);
    schannelCred.dwVersion := SCHANNEL_CRED_VERSION;
    if aIgnoreCertificateErrors then
      schannelCred.dwFlags := SCH_CRED_MANUAL_CRED_VALIDATION or SCH_CRED_NO_DEFAULT_CREDS
    else
      schannelCred.dwFlags := SCH_CRED_REVOCATION_CHECK_CHAIN or SCH_CRED_IGNORE_REVOCATION_OFFLINE;

    // Direct credential acquisition
    res := AcquireCredentialsHandleW(
      nil, UNISP_NAME, SECPKG_CRED_OUTBOUND, nil, @schannelCred, nil, nil, @Cred, nil);
    if res <> SEC_E_OK then
      raise ESChannel.CreateFmt('AcquireCredentialsHandleW failed: 0x%08X', [res]);

    // Initialize data buffers
    DataPos := 0;
    DataCount := 0;
    SetLength(Data, TLSRECMAXSIZE);

    // Setup handshake flags - simplified approach
    f := ISC_REQ_FLAGS;
    if aIgnoreCertificateErrors then
      f := f or ISC_REQ_MANUAL_CRED_VALIDATION or ISC_REQ_USE_SUPPLIED_CREDS;

    // Initialize handshake buffer
    buf.Init;

    // Initiate client handshake
    res := InitializeSecurityContextW(@Cred, nil, PWideChar(TargetHostString),
      f, 0, SECURITY_NATIVE_DREP, nil, 0, @Ctxt, @buf.output, f, nil);

    if res <> SEC_I_CONTINUE_NEEDED then
      raise ESChannel.CreateFmt('InitializeSecurityContext failed: 0x%08X', [res]);

    // Send initial handshake data
    if (buf.buf[2].cbBuffer = 0) or (buf.buf[2].pvBuffer = nil) then
      raise ESChannel.CreateFmt('Void Hello answer to %s', [string(aTargetHost)]);

    try
      TncLineInternal(TncLine(aLine)).SendBuffer(buf.buf[2].pvBuffer^, buf.buf[2].cbBuffer);
    finally
      FreeContextBuffer(buf.buf[2].pvBuffer);
    end;

    // Complete the handshake
    HandshakeLoop(aLine);

    // Query stream sizes after successful handshake
    res := QueryContextAttributesW(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes);
    if res <> SEC_E_OK then
      raise ESChannel.CreateFmt('QueryContextAttributes failed: 0x%08X', [res]);

    InputSize := Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
    if InputSize > TLSRECMAXSIZE then
      raise ESChannel.CreateFmt('InputSize=%d>%d', [InputSize, TLSRECMAXSIZE]);

    SetLength(Input, InputSize);
    InputCount := 0;
    Initialized := true;

    break; // Success - exit retry loop

  except
    // Retry for known Windows 7/8 TLS bugs
    on E: ESChannel do
    begin
      lastError := GetLastError;
      if (trial = 0) and
         ((res = SEC_E_BUFFER_TOO_SMALL) or (res = SEC_E_MESSAGE_ALTERED)) then
      begin
        // Cleanup and retry once for Windows TLS bug
        FreeSecurityContextSafe(Ctxt);
        FreeCredentialsHandleSafe(Cred);
        inc(trial);
        // Continue retry loop
      end
      else
        raise; // Re-raise if not a retryable error or already tried
    end;
  end;
end;

procedure TSChannelClient.HandshakeLoop(aLine: TObject);
var
  buf: THandshakeBuf;
  res, f: cardinal;
  Line: TncLine;
  LoopCount: Integer;
  RecvResult: Integer;
begin
  Line := TncLine(aLine);
  res := SEC_I_CONTINUE_NEEDED;
  LoopCount := 0;

  while (res = SEC_I_CONTINUE_NEEDED) or (res = SEC_E_INCOMPLETE_MESSAGE) do begin
    Inc(LoopCount);

    RecvResult := TncLineInternal(Line).RecvBuffer(PByteArray(Data)[DataCount], length(Data) - DataCount);

    inc(DataCount, CheckSocket(RecvResult));

    buf.Init;
    buf.buf[0].cbBuffer := DataCount;
    buf.buf[0].BufferType := SECBUFFER_TOKEN;
    buf.buf[0].pvBuffer := pointer(Data);

    res := InitializeSecurityContextW(@Cred, @Ctxt, nil, ISC_REQ_FLAGS, 0,
      SECURITY_NATIVE_DREP, @buf.input, 0, @Ctxt, @buf.output, f, nil);

    if res = SEC_I_INCOMPLETE_CREDENTIALS then
    begin
      // check https://stackoverflow.com/a/47479968/458259
      res := InitializeSecurityContextW(@Cred, @Ctxt, nil, ISC_REQ_FLAGS, 0,
        SECURITY_NATIVE_DREP, @buf.input, 0, @Ctxt, @buf.output, f, nil);
    end;

    if (res = SEC_E_OK) or (res = SEC_I_CONTINUE_NEEDED) or
       ((f and ISC_REQ_EXTENDED_ERROR) <> 0) then begin
      if (buf.buf[2].cbBuffer <> 0) and (buf.buf[2].pvBuffer <> nil) then begin
        CheckSocket(TncLineInternal(Line).SendBuffer(buf.buf[2].pvBuffer^, buf.buf[2].cbBuffer));
        CheckSEC_E_OK(FreeContextBuffer(buf.buf[2].pvBuffer));
      end;
    end;

    if buf.buf[1].BufferType = SECBUFFER_EXTRA then begin
      // reuse pending Data bytes to avoid SEC_E_INVALID_TOKEN
      Move(PByteArray(Data)[cardinal(DataCount) - buf.buf[1].cbBuffer],
           PByteArray(Data)[0], buf.buf[1].cbBuffer);
      DataCount := buf.buf[1].cbBuffer;
    end else
    if res <> SEC_E_INCOMPLETE_MESSAGE then
      DataCount := 0;
  end;

  CheckSEC_E_OK(res);
end;

procedure TSChannelClient.BeforeDisconnection(aLine: TObject);
var
  desc: TSecBufferDesc;
  buf: TSecBuffer;
  dt, f: cardinal;
  Line: TncLine;
begin
  if Initialized then
  try
    Line := TncLine(aLine);
    if (Line <> nil) and Line.Active then begin
      // Send TLS shutdown notification
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 1;
      desc.pBuffers := @buf;
      buf.cbBuffer := 4;
      buf.BufferType := SECBUFFER_TOKEN;
      dt := SCHANNEL_SHUTDOWN;
      buf.pvBuffer := @dt;
      if ApplyControlToken(@Ctxt, @desc) = SEC_E_OK then begin
        buf.cbBuffer := 0;
        buf.BufferType := SECBUFFER_TOKEN;
        buf.pvBuffer := nil;
        if InitializeSecurityContextW(@Cred, @Ctxt, nil, ISC_REQ_FLAGS, 0,
           SECURITY_NATIVE_DREP, nil, 0, @Ctxt, @desc, f, nil) = SEC_E_OK then begin
          TncLineInternal(Line).SendBuffer(buf.pvBuffer^, buf.cbBuffer);
          FreeContextBuffer(buf.pvBuffer);
        end;
      end;
    end;
    // Simple cleanup with zero-fill
    FreeSecurityContextSafe(Ctxt);
    FreeCredentialsHandleSafe(Cred);
  finally
    // Simple zero-fill
    FillChar(Cred, SizeOf(Cred), 0);
    FillChar(Ctxt, SizeOf(Ctxt), 0);
    Initialized := false;
  end;
end;

function TSChannelClient.Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res: cardinal;
  read, i: integer;
  needsRenegotiate: boolean;
  Line: TncLine;

  function DecryptInput: cardinal;
  begin
    buf[0].cbBuffer := InputCount;
    buf[0].BufferType := SECBUFFER_DATA;
    buf[0].pvBuffer := pointer(Input);
    buf[1].cbBuffer := 0;
    buf[1].BufferType := SECBUFFER_EMPTY;
    buf[1].pvBuffer := nil;
    buf[2].cbBuffer := 0;
    buf[2].BufferType := SECBUFFER_EMPTY;
    buf[2].pvBuffer := nil;
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    result := DecryptMessage(@Ctxt, @desc, 0, nil);
  end;
begin
  Line := TncLine(aLine);

  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).RecvBuffer(aBuffer^, aLength);
    exit;
  end;
  result := 0;
  if not SessionClosed then
    while DataCount = 0 do
    try
      DataPos := 0;
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 4;
      desc.pBuffers := @buf[0];
      repeat
        read := TncLineInternal(Line).RecvBuffer(PByteArray(Input)[InputCount], InputSize - InputCount);
        if read <= 0 then begin
          SessionClosed := true; // Mark session as closed when recv returns <= 0
          result := read; // return socket error
          exit;
        end;
        inc(InputCount, read);
        res := DecryptInput;
      until res <> SEC_E_INCOMPLETE_MESSAGE;
      needsRenegotiate := false;
      repeat
        case res of
          SEC_I_RENEGOTIATE:
            needsRenegotiate := true;
          SEC_I_CONTEXT_EXPIRED:
            SessionClosed := true;
          SEC_E_INCOMPLETE_MESSAGE:
            break;
          else CheckSEC_E_OK(res);
        end;
        InputCount := 0;
        for i := 1 to 3 do
          case buf[i].BufferType of
            SECBUFFER_DATA:
              AppendData(buf[i]);
            SECBUFFER_EXTRA:
              begin
                Move(buf[i].pvBuffer^, pointer(Input)^, buf[i].cbBuffer);
                InputCount := buf[i].cbBuffer;
              end;
          end;
        if InputCount = 0 then
          break;
        res := DecryptInput;
      until false;
      if needsRenegotiate then
        HandshakeLoop(aLine);
    except
      on E: Exception do
      begin
        // CRITICAL FIX: Reset InputCount to clear corrupted TLS data from buffer
        // Without this, corrupted data accumulates and causes repeated decryption failures
        InputCount := 0;
        SessionClosed := true; // Mark session as closed on exception
        exit; // shutdown the connection on ESChannel fatal error
      end;
    end;
  result := DataCount;
  if aLength < result then
    result := aLength;
  Move(PByteArray(Data)[DataPos], aBuffer^, result);
  inc(DataPos, result);
  dec(DataCount, result);
end;

function TSChannelClient.Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res, sent, s, len, trailer, pending, templen: cardinal;
  temp: array[0..TLSRECMAXSIZE] of byte;
  Line: TncLine;

begin
  Line := TncLine(aLine);
  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).SendBuffer(aBuffer^, aLength);
    exit;
  end;

  // Check if Sizes has been initialized
  if Sizes.cbMaximumMessage = 0 then
  begin
    if QueryContextAttributesW(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes) <> SEC_E_OK then
    begin
      result := -1;
      exit;
    end;
  end;

  result := 0;
  desc.ulVersion := SECBUFFER_VERSION;
  desc.cBuffers := 4;
  desc.pBuffers := @buf[0];
  pending := aLength;
  while pending > 0 do begin
    templen := pending;
    if templen > Sizes.cbMaximumMessage then
      templen := Sizes.cbMaximumMessage;
    Move(aBuffer^, temp[Sizes.cbHeader], templen);
    inc(PByte(aBuffer), templen);
    dec(pending, templen);
    trailer := Sizes.cbHeader + templen;
    buf[0].cbBuffer := Sizes.cbHeader;
    buf[0].BufferType := SECBUFFER_STREAM_HEADER;
    buf[0].pvBuffer := @temp;
    buf[1].cbBuffer := templen;
    buf[1].BufferType := SECBUFFER_DATA;
    buf[1].pvBuffer := @temp[Sizes.cbHeader];
    buf[2].cbBuffer := Sizes.cbTrailer;
    buf[2].BufferType := SECBUFFER_STREAM_TRAILER;
    buf[2].pvBuffer := @temp[trailer];
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    if EncryptMessage(@Ctxt, 0, @desc, 0) <> SEC_E_OK then
    begin
      exit; // shutdown the connection on SChannel error
    end;
    len := buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer;
    sent := 0;
    repeat
      s := TncLineInternal(Line).SendBuffer(PByteArray(@temp)[sent], len);
      if s = len then
        break; // whole message sent
      if s = 0 then
      begin
        exit;  // report connection closed
      end;
      if integer(s) < 0 then begin
        result := s;
        exit; // report socket fatal error
      end
      else begin
        dec(len, s);
        inc(sent, s);
      end;
      Sleep(1); // try again
    until false;
  end;
  result := aLength;
end;

{ TSChannelServer - Server-side SChannel implementation }

procedure TSChannelServer.AppendData(const aBuffer: TSecBuffer);
var
  newlen: integer;
begin
  newlen := DataCount + integer(aBuffer.cbBuffer);
  if newlen > Length(Data) then
    SetLength(Data, newlen);
  Move(aBuffer.pvBuffer^, PByteArray(Data)[DataCount], aBuffer.cbBuffer);
  inc(DataCount, aBuffer.cbBuffer);
end;

procedure TSChannelServer.AfterConnection(aLine: TObject; const aCertificateFile, aPrivateKeyPassword: AnsiString);
var
  res: cardinal;
  Line: TncLine;
  SchannelCred: TSChannelCred;
  pCertContext: PCCERT_CONTEXT;
  pCertArray: PCCERT_CONTEXT; // Array of one certificate context for paCred

begin
  // Clean up any existing TLS context from previous connection
  if Initialized then
  begin
    FreeSecurityContextSafe(Ctxt);
    FreeCredentialsHandleSafe(Cred);
    Initialized := false;
    HandshakeCompleted := false;
    SessionClosed := false;
    DataCount := 0;
    DataPos := 0;
  end;

  Line := TncLine(aLine);

  // Initialize server credentials with certificate
  FillChar(SchannelCred, SizeOf(SchannelCred), 0);
  SchannelCred.dwVersion := SCHANNEL_CRED_VERSION;
  SchannelCred.grbitEnabledProtocols := SP_PROT_TLS1_2_SERVER or SP_PROT_TLS1_3_SERVER;
  SchannelCred.dwFlags := 0; // No special flags for server

  // Load certificate from PFX file
  pCertContext := nil;
  if aCertificateFile <> '' then
  begin
    pCertContext := LoadCertificateFromPFX(aCertificateFile, aPrivateKeyPassword);
    if pCertContext <> nil then
    begin
      pCertArray := pCertContext; // Create array element
      SchannelCred.cCreds := 1;
      SchannelCred.paCred := @pCertArray; // Point to the array
    end
    else
      raise ESChannel.CreateFmt('Failed to load certificate from: %s', [string(aCertificateFile)]);
  end
  else
    raise ESChannel.Create('Certificate file required for TLS server');

  try
    // Direct credential acquisition
    res := AcquireCredentialsHandleW(
      nil, UNISP_NAME, SECPKG_CRED_INBOUND, nil, @SchannelCred, nil, nil, @Cred, nil);
    if res <> SEC_E_OK then
      raise ESChannel.CreateFmt('AcquireCredentialsHandleW failed: 0x%08X', [res]);

    // Initialize buffers
    DataPos := 0;
    DataCount := 0;
    SetLength(Data, TLSRECMAXSIZE);
    SetLength(Input, TLSRECMAXSIZE);
    InputCount := 0;
    Initialized := true; // Mark as initialized but handshake not yet completed
    HandshakeCompleted := false; // Handshake will be triggered when first TLS data arrives

  finally
    // Free certificate context
    if pCertContext <> nil then
      CertFreeCertificateContext(pCertContext);
  end;
end;

procedure TSChannelServer.HandshakeLoop(aLine: TObject);
var
  buf: THandshakeBuf;
  res, f: cardinal;
  Line: TncLine;
  fDone: boolean;
  fInitContext: boolean;
  LoopCount: Integer;
  RecvResult: Integer;

begin
  Line := TncLine(aLine);
  fDone := false;
  fInitContext := true;
  LoopCount := 0;

  try
    while not fDone do
    begin
      Inc(LoopCount);

      // Read client data
      try
        RecvResult := TncLineInternal(Line).RecvBuffer(PByteArray(Data)[DataCount], length(Data) - DataCount);
        inc(DataCount, CheckSocket(RecvResult));
      except
        on E: Exception do
        begin
          raise ESChannel.CreateFmt('Failed to receive client data: %s', [E.Message]);
        end;
      end;

      buf.Init;
      buf.buf[0].cbBuffer := DataCount;
      buf.buf[0].BufferType := SECBUFFER_TOKEN;
      buf.buf[0].pvBuffer := pointer(Data);

      // Server-side handshake using AcceptSecurityContext
      if fInitContext then
      begin
        // CRITICAL: Server must use AcceptSecurityContext, not InitializeSecurityContext
        res := AcceptSecurityContext(@Cred, nil, @buf.input,
          ASC_REQ_FLAGS, SECURITY_NATIVE_DREP, @Ctxt, @buf.output, f, nil);
        fInitContext := false;
      end
      else
      begin
        res := AcceptSecurityContext(@Cred, @Ctxt, @buf.input,
          ASC_REQ_FLAGS, SECURITY_NATIVE_DREP, @Ctxt, @buf.output, f, nil);
      end;

      case res of
        SEC_E_OK:
          begin
            fDone := true;
          end;
        SEC_I_CONTINUE_NEEDED:
          begin
            // Continue handshake
          end;
        SEC_I_INCOMPLETE_CREDENTIALS:
          begin
            // Continue with current data
          end;
        SEC_E_INCOMPLETE_MESSAGE:
          begin
            // Need more data from client
            continue;
          end;
        else
        begin
          raise ESChannel.CreateFmt('AcceptSecurityContext failed: 0x%08X', [res]);
        end;
      end;

      // Send response to client if needed
      if (buf.buf[2].cbBuffer <> 0) and (buf.buf[2].pvBuffer <> nil) then
      begin
        try
          CheckSocket(TncLineInternal(Line).SendBuffer(buf.buf[2].pvBuffer^, buf.buf[2].cbBuffer));
          CheckSEC_E_OK(FreeContextBuffer(buf.buf[2].pvBuffer));
        except
          on E: Exception do
          begin
            raise ESChannel.CreateFmt('Failed to send server response: %s', [E.Message]);
          end;
        end;
      end;

      // Handle extra data
      if buf.buf[1].BufferType = SECBUFFER_EXTRA then
      begin
        Move(PByteArray(Data)[cardinal(DataCount) - buf.buf[1].cbBuffer],
             PByteArray(Data)[0], buf.buf[1].cbBuffer);
        DataCount := buf.buf[1].cbBuffer;
      end
      else if not fDone then
      begin
        DataCount := 0;
      end;
    end;

  except
    on E: Exception do
    begin
      raise ESChannel.CreateFmt('TLS handshake failed: %s', [E.Message]);
    end;
  end;
end;

procedure TSChannelServer.BeforeDisconnection(aLine: TObject);
var
  desc: TSecBufferDesc;
  buf: TSecBuffer;
  dt, f: cardinal;
  Line: TncLine;
begin
  if Initialized then
  try
    Line := TncLine(aLine);
    if (Line <> nil) and Line.Active then begin
      // Send TLS shutdown notification
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 1;
      desc.pBuffers := @buf;
      buf.cbBuffer := 4;
      buf.BufferType := SECBUFFER_TOKEN;
      dt := SCHANNEL_SHUTDOWN;
      buf.pvBuffer := @dt;
      if ApplyControlToken(@Ctxt, @desc) = SEC_E_OK then begin
        buf.cbBuffer := 0;
        buf.BufferType := SECBUFFER_TOKEN;
        buf.pvBuffer := nil;
        if AcceptSecurityContext(@Cred, @Ctxt, nil, ASC_REQ_FLAGS,
           SECURITY_NATIVE_DREP, @Ctxt, @desc, f, nil) = SEC_E_OK then begin
          TncLineInternal(Line).SendBuffer(buf.pvBuffer^, buf.cbBuffer);
          FreeContextBuffer(buf.pvBuffer);
        end;
      end;
    end;
    // Simple cleanup with zero-fill
    FreeSecurityContextSafe(Ctxt);
    FreeCredentialsHandleSafe(Cred);
  finally
    // Simple zero-fill
    FillChar(Cred, SizeOf(Cred), 0);
    FillChar(Ctxt, SizeOf(Ctxt), 0);
    Initialized := false;
    HandshakeCompleted := false;
  end;
end;

function TSChannelServer.Receive(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res: cardinal;
  read, i: integer;
  needsRenegotiate: boolean;
  Line: TncLine;

  function DecryptInput: cardinal;
  begin
    buf[0].cbBuffer := InputCount;
    buf[0].BufferType := SECBUFFER_DATA;
    buf[0].pvBuffer := pointer(Input);
    buf[1].cbBuffer := 0;
    buf[1].BufferType := SECBUFFER_EMPTY;
    buf[1].pvBuffer := nil;
    buf[2].cbBuffer := 0;
    buf[2].BufferType := SECBUFFER_EMPTY;
    buf[2].pvBuffer := nil;
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    result := DecryptMessage(@Ctxt, @desc, 0, nil);
  end;
begin
  Line := TncLine(aLine);

  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).RecvBuffer(aBuffer^, aLength);
    exit;
  end;

  // Check if handshake needs to be performed
  if not HandshakeCompleted then
  begin
    try
      HandshakeLoop(aLine);
      CheckSEC_E_OK(QueryContextAttributesW(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes));
      InputSize := Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
      if InputSize > TLSRECMAXSIZE then
        raise ESChannel.CreateFmt('InputSize=%d>%d', [InputSize, TLSRECMAXSIZE]);
      SetLength(Input, InputSize);
      HandshakeCompleted := true;

      // CRITICAL FIX: Clear any leftover handshake data to prevent it from being returned as application data
      DataCount := 0;
      DataPos := 0;
      InputCount := 0;

      // CRITICAL: Return immediately to trigger handshake completion callback
      // We'll return 0 to indicate no application data was received,
      // but set a special result to indicate handshake completion
      result := 0;
      exit;
    except
      on E: Exception do
      begin
        result := -1; // Return error
        exit;
      end;
    end;
  end;

  result := 0;
  if not SessionClosed then
    while DataCount = 0 do
    try
      DataPos := 0;
      desc.ulVersion := SECBUFFER_VERSION;
      desc.cBuffers := 4;
      desc.pBuffers := @buf[0];
      repeat
        read := TncLineInternal(Line).RecvBuffer(PByteArray(Input)[InputCount], InputSize - InputCount);
        if read <= 0 then begin
          SessionClosed := true; // Mark session as closed when recv returns <= 0
          result := read; // return socket error
          exit;
        end;
        inc(InputCount, read);
        res := DecryptInput;
      until res <> SEC_E_INCOMPLETE_MESSAGE;
      needsRenegotiate := false;
      repeat
        case res of
          SEC_I_RENEGOTIATE:
            needsRenegotiate := true;
          SEC_I_CONTEXT_EXPIRED:
            SessionClosed := true;
          SEC_E_INCOMPLETE_MESSAGE:
            break;
          else CheckSEC_E_OK(res);
        end;
        InputCount := 0;
        for i := 1 to 3 do
          case buf[i].BufferType of
            SECBUFFER_DATA:
              AppendData(buf[i]);
            SECBUFFER_EXTRA:
              begin
                Move(buf[i].pvBuffer^, pointer(Input)^, buf[i].cbBuffer);
                InputCount := buf[i].cbBuffer;
              end;
          end;
        if InputCount = 0 then
          break;
        res := DecryptInput;
      until false;
      if needsRenegotiate then
        HandshakeLoop(aLine);
    except
      on E: Exception do
      begin
        // CRITICAL FIX: Reset InputCount to clear corrupted TLS data from buffer
        // Without this, corrupted data accumulates and causes repeated decryption failures
        InputCount := 0;
        SessionClosed := true; // Mark session as closed on exception
        exit; // shutdown the connection on ESChannel fatal error
      end;
    end;
  result := DataCount;
  if aLength < result then
    result := aLength;
  Move(PByteArray(Data)[DataPos], aBuffer^, result);
  inc(DataPos, result);
  dec(DataCount, result);
end;

function TSChannelServer.Send(aLine: TObject; aBuffer: pointer; aLength: integer): integer;
var
  desc: TSecBufferDesc;
  buf: array[0..3] of TSecBuffer;
  res, sent, s, len, trailer, pending, templen: cardinal;
  temp: array[0..TLSRECMAXSIZE] of byte;
  Line: TncLine;

begin
  Line := TncLine(aLine);
  if not Initialized then begin // use plain socket API
    result := TncLineInternal(Line).SendBuffer(aBuffer^, aLength);
    exit;
  end;

  // Check if Sizes has been initialized
  if Sizes.cbMaximumMessage = 0 then
  begin
    if QueryContextAttributesW(@Ctxt, SECPKG_ATTR_STREAM_SIZES, @Sizes) <> SEC_E_OK then
    begin
      result := -1;
      exit;
    end;
  end;

  result := 0;
  desc.ulVersion := SECBUFFER_VERSION;
  desc.cBuffers := 4;
  desc.pBuffers := @buf[0];
  pending := aLength;
  while pending > 0 do begin
    templen := pending;
    if templen > Sizes.cbMaximumMessage then
      templen := Sizes.cbMaximumMessage;
    Move(aBuffer^, temp[Sizes.cbHeader], templen);
    inc(PByte(aBuffer), templen);
    dec(pending, templen);
    trailer := Sizes.cbHeader + templen;
    buf[0].cbBuffer := Sizes.cbHeader;
    buf[0].BufferType := SECBUFFER_STREAM_HEADER;
    buf[0].pvBuffer := @temp;
    buf[1].cbBuffer := templen;
    buf[1].BufferType := SECBUFFER_DATA;
    buf[1].pvBuffer := @temp[Sizes.cbHeader];
    buf[2].cbBuffer := Sizes.cbTrailer;
    buf[2].BufferType := SECBUFFER_STREAM_TRAILER;
    buf[2].pvBuffer := @temp[trailer];
    buf[3].cbBuffer := 0;
    buf[3].BufferType := SECBUFFER_EMPTY;
    buf[3].pvBuffer := nil;
    if EncryptMessage(@Ctxt, 0, @desc, 0) <> SEC_E_OK then
    begin
      exit; // shutdown the connection on SChannel error
    end;
    len := buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer;
    sent := 0;
    repeat
      s := TncLineInternal(Line).SendBuffer(PByteArray(@temp)[sent], len);
      if s = len then
        break; // whole message sent
      if s = 0 then
      begin
        exit;  // report connection closed
      end;
      if integer(s) < 0 then begin
        result := s;
        exit; // report socket fatal error
      end
      else begin
        dec(len, s);
        inc(sent, s);
      end;
      Sleep(1); // try again
    until false;
  end;
  result := aLength;
end;


end.
