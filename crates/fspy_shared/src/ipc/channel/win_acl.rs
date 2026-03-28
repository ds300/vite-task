//! Windows ACL helpers for granting AppContainer access to IPC resources.

use std::{ffi::c_void, io, os::windows::ffi::OsStrExt, ptr};

// Access mask bits
const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
const GENERIC_ALL: u32 = 0x1000_0000;
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;
const SET_ACCESS: u32 = 2; // GRANT_ACCESS

#[repr(C)]
#[allow(non_snake_case)]
struct ExplicitAccessW {
    grfAccessPermissions: u32,
    grfAccessMode: u32,
    grfInheritance: u32,
    Trustee: TrusteeW,
}

#[repr(C)]
#[allow(non_snake_case)]
struct TrusteeW {
    pMultipleTrustee: *mut TrusteeW,
    MultipleTrusteeOperation: u32,
    TrusteeForm: u32,
    TrusteeType: u32,
    ptstrName: *mut c_void,
}

// TRUSTEE_FORM::TRUSTEE_IS_SID = 0
const TRUSTEE_IS_SID: u32 = 0;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenFileMappingW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn GetLastError() -> u32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        security_info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        security_descriptor: *mut *mut c_void,
    ) -> u32;

    fn SetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        security_info: u32,
        owner: *const c_void,
        group: *const c_void,
        dacl: *const c_void,
        sacl: *const c_void,
    ) -> u32;

    fn SetEntriesInAclW(
        count: u32,
        entries: *const ExplicitAccessW,
        old_acl: *mut c_void,
        new_acl: *mut *mut c_void,
    ) -> u32;

    fn SetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_info: u32,
        owner: *const c_void,
        group: *const c_void,
        dacl: *const c_void,
        sacl: *const c_void,
    ) -> u32;

    fn GetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        security_descriptor: *mut *mut c_void,
    ) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

// SE_KERNEL_OBJECT = 6, SE_FILE_OBJECT = 1
const SE_KERNEL_OBJECT: u32 = 6;
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const FILE_MAP_ALL_ACCESS: u32 = 0x000F_001F;

/// Grant an AppContainer SID access to a named shared memory section.
pub fn grant_section_access(
    os_id: &str,
    sid: *mut c_void,
) -> io::Result<()> {
    let name_wide: Vec<u16> = os_id.encode_utf16().chain(std::iter::once(0)).collect();

    let handle = unsafe { OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, name_wide.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "OpenFileMappingW failed for '{}': error {}",
                os_id,
                unsafe { GetLastError() }
            ),
        ));
    }

    let result = grant_kernel_object_access(handle, sid, SECTION_ALL_ACCESS);
    unsafe { CloseHandle(handle) };
    result
}

/// Grant an AppContainer SID access to a file or directory by path.
///
/// Reads the existing DACL and adds an ACE for the given SID, preserving
/// all existing permissions.
pub fn grant_file_access(
    path: &std::ffi::OsStr,
    sid: *mut c_void,
) -> io::Result<()> {
    grant_file_access_with_mask(path, sid, GENERIC_ALL)
}

pub fn grant_file_access_with_mask(
    path: &std::ffi::OsStr,
    sid: *mut c_void,
    access_mask: u32,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let path_wide: Vec<u16> = path.encode_wide().chain(std::iter::once(0)).collect();

    // Read existing DACL so we merge rather than replace.
    let mut old_dacl: *mut c_void = ptr::null_mut();
    let mut sd: *mut c_void = ptr::null_mut();
    let err = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("GetNamedSecurityInfoW: error {err}"),
        ));
    }

    let ea = ExplicitAccessW {
        grfAccessPermissions: access_mask,
        grfAccessMode: SET_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TrusteeW {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: 0,
            ptstrName: sid,
        },
    };

    let mut new_dacl: *mut c_void = ptr::null_mut();
    let err = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) };
    if err != 0 {
        unsafe { LocalFree(sd) };
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let err = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null(),
            ptr::null(),
            new_dacl,
            ptr::null(),
        )
    };

    if !new_dacl.is_null() {
        unsafe { LocalFree(new_dacl) };
    }
    unsafe { LocalFree(sd) };

    if err != 0 {
        Err(io::Error::from_raw_os_error(err as i32))
    } else {
        Ok(())
    }
}

fn grant_kernel_object_access(
    handle: *mut c_void,
    sid: *mut c_void,
    access_mask: u32,
) -> io::Result<()> {
    let mut old_dacl: *mut c_void = ptr::null_mut();
    let mut sd: *mut c_void = ptr::null_mut();

    let err = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let ea = ExplicitAccessW {
        grfAccessPermissions: access_mask,
        grfAccessMode: SET_ACCESS,
        grfInheritance: 0,
        Trustee: TrusteeW {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: 0,
            ptstrName: sid,
        },
    };

    let mut new_dacl: *mut c_void = ptr::null_mut();
    let err = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) };
    if err != 0 {
        unsafe { LocalFree(sd) };
        return Err(io::Error::from_raw_os_error(err as i32));
    }

    let err = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null(),
            ptr::null(),
            new_dacl,
            ptr::null(),
        )
    };

    if !new_dacl.is_null() {
        unsafe { LocalFree(new_dacl) };
    }
    unsafe { LocalFree(sd) };

    if err != 0 {
        Err(io::Error::from_raw_os_error(err as i32))
    } else {
        Ok(())
    }
}
