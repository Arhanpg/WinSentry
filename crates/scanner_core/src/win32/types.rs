//! Win32 Types, Constants, and FFI Declarations
//!
//! Hand-crafted, zero-overhead Win32 bindings targeting Kernel32, Advapi32,
//! Version, Wintrust, Rstrtmgr, and AMSI.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals, dead_code)]

use std::ffi::c_void;

pub type BOOL = i32;
pub type DWORD = u32;
pub type ULONG = u32;
pub type USHORT = u16;
pub type HANDLE = *mut c_void;
pub type HRESULT = i32;
pub type LPCWSTR = *const u16;
pub type LPWSTR = *mut u16;
pub type LPVOID = *mut c_void;
pub type LPCVOID = *const c_void;
pub type LPDWORD = *mut u32;
pub type PSECURITY_DESCRIPTOR = *mut c_void;
pub type PACL = *mut c_void;
pub type PSID = *mut c_void;

pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

// File Attribute Constants
pub const FILE_ATTRIBUTE_READONLY: DWORD = 0x00000001;
pub const FILE_ATTRIBUTE_HIDDEN: DWORD = 0x00000002;
pub const FILE_ATTRIBUTE_SYSTEM: DWORD = 0x00000004;
pub const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x00000010;
pub const FILE_ATTRIBUTE_ARCHIVE: DWORD = 0x00000020;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;
pub const FILE_ATTRIBUTE_TEMPORARY: DWORD = 0x00000100;
pub const FILE_ATTRIBUTE_SPARSE_FILE: DWORD = 0x00000200;
pub const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x00000400;
pub const FILE_ATTRIBUTE_COMPRESSED: DWORD = 0x00000800;
pub const FILE_ATTRIBUTE_OFFLINE: DWORD = 0x00001000;
pub const FILE_ATTRIBUTE_ENCRYPTED: DWORD = 0x00004000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: DWORD = 0x00040000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: DWORD = 0x00400000;

// FindFirstFileEx Flags
pub const FIND_FIRST_EX_LARGE_FETCH: DWORD = 0x00000002;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum FINDEX_INFO_LEVELS {
    FindExInfoStandard = 0,
    FindExInfoBasic = 1,
    FindExInfoMaxInfoLevel = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum FINDEX_SEARCH_OPS {
    FindExSearchNameMatch = 0,
    FindExSearchLimitToDirectories = 1,
    FindExSearchLimitToDevices = 2,
    FindExSearchMaxSearchOp = 3,
}

// Reparse Point Tags & Macros
pub const IO_REPARSE_TAG_MOUNT_POINT: DWORD = 0xA0000003;
pub const IO_REPARSE_TAG_SYMLINK: DWORD = 0xA000000C;
pub const IO_REPARSE_TAG_APPEXECLINK: DWORD = 0x8000001B;

#[inline]
pub fn is_reparse_tag_name_surrogate(tag: DWORD) -> bool {
    (tag & 0x20000000) != 0
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

#[repr(C)]
pub struct WIN32_FIND_DATAW {
    pub dwFileAttributes: DWORD,
    pub ftCreationTime: FILETIME,
    pub ftLastAccessTime: FILETIME,
    pub ftLastWriteTime: FILETIME,
    pub nFileSizeHigh: DWORD,
    pub nFileSizeLow: DWORD,
    pub dwReserved0: DWORD,
    pub dwReserved1: DWORD,
    pub cFileName: [u16; 260],
    pub cAlternateFileName: [u16; 14],
}

// Alternate Data Streams
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum STREAM_INFO_LEVELS {
    FindStreamInfoStandard = 0,
    FindStreamInfoMaxInfoLevel = 1,
}

#[repr(C)]
pub struct WIN32_FIND_STREAM_DATA {
    pub StreamSize: i64,
    pub cStreamName: [u16; 296],
}

// Generic and File Access Rights
pub const GENERIC_READ: DWORD = 0x80000000;
pub const GENERIC_WRITE: DWORD = 0x40000000;
pub const GENERIC_EXECUTE: DWORD = 0x20000000;
pub const GENERIC_ALL: DWORD = 0x10000000;

pub const FILE_READ_DATA: DWORD = 0x0001;
pub const FILE_WRITE_DATA: DWORD = 0x0002;
pub const FILE_APPEND_DATA: DWORD = 0x0004;
pub const FILE_READ_EA: DWORD = 0x0008;
pub const FILE_WRITE_EA: DWORD = 0x0010;
pub const FILE_READ_ATTRIBUTES: DWORD = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: DWORD = 0x0100;
pub const DELETE: DWORD = 0x00010000;
pub const READ_CONTROL: DWORD = 0x00020000;
pub const WRITE_DAC: DWORD = 0x00040000;
pub const WRITE_OWNER: DWORD = 0x00080000;
pub const SYNCHRONIZE: DWORD = 0x00100000;

// File Creation / Deletion Flags
pub const FILE_SHARE_READ: DWORD = 0x00000001;
pub const FILE_SHARE_WRITE: DWORD = 0x00000002;
pub const FILE_SHARE_DELETE: DWORD = 0x00000004;
pub const OPEN_EXISTING: DWORD = 3;
pub const FILE_FLAG_BACKUP_SEMANTICS: DWORD = 0x02000000;
pub const FILE_FLAG_DELETE_ON_CLOSE: DWORD = 0x04000000;
pub const SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE: DWORD = 0x2;

// Security Info Constants
pub const OWNER_SECURITY_INFORMATION: DWORD = 0x00000001;
pub const GROUP_SECURITY_INFORMATION: DWORD = 0x00000002;
pub const DACL_SECURITY_INFORMATION: DWORD = 0x00000004;
pub const SACL_SECURITY_INFORMATION: DWORD = 0x00000008;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum SE_OBJECT_TYPE {
    SE_UNKNOWN_OBJECT_TYPE = 0,
    SE_FILE_OBJECT,
    SE_SERVICE,
    SE_PRINTER,
    SE_REGISTRY_KEY,
    SE_LMSHARE,
    SE_KERNEL_OBJECT,
    SE_WINDOW_OBJECT,
    SE_DS_OBJECT,
    SE_DS_OBJECT_ALL,
    SE_PROVIDER_DEFINED_OBJECT,
    SE_WMIGUID_OBJECT,
    SE_REGISTRY_WOW64_32KEY,
}

// Restart Manager Constants
pub const CCH_RM_MAX_APP_NAME: usize = 255;
pub const CCH_RM_MAX_SVC_NAME: usize = 63;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum RM_APP_TYPE {
    RmUnknownApp = 0,
    RmMainWindow = 1,
    RmOtherWindow = 2,
    RmService = 3,
    RmExplorer = 4,
    RmConsole = 5,
    RmCritical = 1000,
}

#[repr(C)]
pub struct RM_UNIQUE_PROCESS {
    pub dwProcessId: DWORD,
    pub ProcessStartTime: FILETIME,
}

#[repr(C)]
pub struct RM_PROCESS_INFO {
    pub Process: RM_UNIQUE_PROCESS,
    pub strAppName: [u16; CCH_RM_MAX_APP_NAME + 1],
    pub strServiceShortName: [u16; CCH_RM_MAX_SVC_NAME + 1],
    pub ApplicationType: RM_APP_TYPE,
    pub AppStatus: ULONG,
    pub TSSessionId: DWORD,
    pub bRestartable: BOOL,
}

// AMSI Constants
pub type HAMSICONTEXT = *mut c_void;
pub type HAMSISESSION = *mut c_void;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AMSI_RESULT {
    AMSI_RESULT_CLEAN = 0,
    AMSI_RESULT_NOT_DETECTED = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
    AMSI_RESULT_DETECTED = 32768,
}

#[inline]
pub fn amsi_result_is_malware(r: AMSI_RESULT) -> bool {
    (r as u32) >= (AMSI_RESULT::AMSI_RESULT_DETECTED as u32)
}

// WinVerifyTrust Constants
pub const WTD_UI_NONE: DWORD = 2;
pub const WTD_REVOKE_NONE: DWORD = 0;
pub const WTD_CHOICE_FILE: DWORD = 1;
pub const WTD_STATEACTION_IGNORE: DWORD = 0;

#[repr(C)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

pub const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    Data1: 0x00aac56b,
    Data2: 0xcd44,
    Data3: 0x11d0,
    Data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
};

#[repr(C)]
pub struct WINTRUST_FILE_INFO {
    pub cbStruct: DWORD,
    pub pcwszFilePath: LPCWSTR,
    pub hFile: HANDLE,
    pub pgKnownSubject: *mut GUID,
}

#[repr(C)]
pub struct WINTRUST_DATA {
    pub cbStruct: DWORD,
    pub pPolicyCallbackData: LPVOID,
    pub pSIPClientData: LPVOID,
    pub dwUIChoice: DWORD,
    pub fdwRevocationChecks: DWORD,
    pub dwUnionChoice: DWORD,
    pub pFile: *mut WINTRUST_FILE_INFO,
    pub dwStateAction: DWORD,
    pub hWVTStateData: HANDLE,
    pub pwszURLReference: LPWSTR,
    pub dwProvFlags: DWORD,
    pub dwUIContext: DWORD,
    pub pSignatureSettings: LPVOID,
}

#[repr(C)]
pub struct VS_FIXEDFILEINFO {
    pub dwSignature: DWORD,
    pub dwStrucVersion: DWORD,
    pub dwFileVersionMS: DWORD,
    pub dwFileVersionLS: DWORD,
    pub dwProductVersionMS: DWORD,
    pub dwProductVersionLS: DWORD,
    pub dwFileFlagsMask: DWORD,
    pub dwFileFlags: DWORD,
    pub dwFileOS: DWORD,
    pub dwFileType: DWORD,
    pub dwFileSubtype: DWORD,
    pub dwFileDateMS: DWORD,
    pub dwFileDateLS: DWORD,
}

// FFI External Function Declarations
extern "system" {
    // Kernel32
    pub fn FindFirstFileExW(
        lpFileName: LPCWSTR,
        fInfoLevelId: FINDEX_INFO_LEVELS,
        lpFindFileData: *mut WIN32_FIND_DATAW,
        fSearchOp: FINDEX_SEARCH_OPS,
        lpSearchFilter: LPVOID,
        dwAdditionalFlags: DWORD,
    ) -> HANDLE;

    pub fn FindNextFileW(hFindFile: HANDLE, lpFindFileData: *mut WIN32_FIND_DATAW) -> BOOL;
    pub fn FindClose(hFindFile: HANDLE) -> BOOL;

    pub fn GetDiskFreeSpaceW(
        lpRootPathName: LPCWSTR,
        lpSectorsPerCluster: LPDWORD,
        lpBytesPerSector: LPDWORD,
        lpNumberOfFreeClusters: LPDWORD,
        lpTotalNumberOfClusters: LPDWORD,
    ) -> BOOL;

    pub fn GetCompressedFileSizeW(lpFileName: LPCWSTR, lpFileSizeHigh: LPDWORD) -> DWORD;

    pub fn FindFirstStreamW(
        lpFileName: LPCWSTR,
        InfoLevel: STREAM_INFO_LEVELS,
        lpFindStreamData: *mut WIN32_FIND_STREAM_DATA,
        dwFlags: DWORD,
    ) -> HANDLE;

    pub fn FindNextStreamW(hFindStream: HANDLE, lpFindStreamData: *mut WIN32_FIND_STREAM_DATA) -> BOOL;

    pub fn CreateFileW(
        lpFileName: LPCWSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: LPVOID,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE,
    ) -> HANDLE;

    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn DeleteFileW(lpFileName: LPCWSTR) -> BOOL;
    pub fn RemoveDirectoryW(lpPathName: LPCWSTR) -> BOOL;
    pub fn CreateHardLinkW(lpFileName: LPCWSTR, lpExistingFileName: LPCWSTR, lpSecurityAttributes: LPVOID) -> BOOL;
    pub fn CreateSymbolicLinkW(lpSymlinkFileName: LPCWSTR, lpTargetFileName: LPCWSTR, dwFlags: DWORD) -> BOOL;

    pub fn GetLogicalDrives() -> DWORD;
    pub fn QueryDosDeviceW(lpDeviceName: LPCWSTR, lpTargetPath: LPWSTR, ucchMax: DWORD) -> DWORD;
    pub fn GetVolumePathNameW(lpszFileName: LPCWSTR, lpszVolumePathName: LPWSTR, cchBufferLength: DWORD) -> BOOL;

    // Advapi32
    pub fn GetNamedSecurityInfoW(
        pObjectName: LPCWSTR,
        ObjectType: SE_OBJECT_TYPE,
        SecurityInfo: DWORD,
        ppsidOwner: *mut PSID,
        ppsidGroup: *mut PSID,
        ppDacl: *mut PACL,
        ppSacl: *mut PACL,
        ppSecurityDescriptor: *mut PSECURITY_DESCRIPTOR,
    ) -> DWORD;

    pub fn ConvertSidToStringSidW(Sid: PSID, StringSid: *mut LPWSTR) -> BOOL;
    pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;

    // Version.dll
    pub fn GetFileVersionInfoSizeW(lptstrFilename: LPCWSTR, lpdwHandle: LPDWORD) -> DWORD;
    pub fn GetFileVersionInfoW(lptstrFilename: LPCWSTR, dwHandle: DWORD, dwLen: DWORD, lpData: LPVOID) -> BOOL;
    pub fn VerQueryValueW(pBlock: LPCVOID, lpSubBlock: LPCWSTR, lplpBuffer: *mut LPVOID, puLen: *mut u32) -> BOOL;

    // Wintrust.dll
    pub fn WinVerifyTrust(hwnd: HANDLE, pgActionID: *const GUID, pWVTData: *mut WINTRUST_DATA) -> i32;

    // Rstrtmgr.dll (Restart Manager)
    pub fn RmStartSession(pSessionHandle: *mut DWORD, dwSessionFlags: DWORD, strSessionKey: LPWSTR) -> DWORD;
    pub fn RmRegisterResources(
        dwSessionHandle: DWORD,
        nFiles: u32,
        rgsFilenames: *const LPCWSTR,
        nApplications: u32,
        rgApplications: *const RM_UNIQUE_PROCESS,
        nServices: u32,
        rgsServiceNames: *const LPCWSTR,
    ) -> DWORD;
    pub fn RmGetList(
        dwSessionHandle: DWORD,
        pnProcInfoNeeded: *mut u32,
        pnProcInfo: *mut u32,
        rgAffectedApps: *mut RM_PROCESS_INFO,
        lpdwRebootReasons: *mut u32,
    ) -> DWORD;
    pub fn RmEndSession(dwSessionHandle: DWORD) -> DWORD;
}
