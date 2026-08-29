//! Owns the access boundary for Nah-managed state under the user's home directory.

use std::fs::File;
use std::path::PathBuf;

use nah_proto::ctx::{AbsolutePath, Platform};

pub(crate) fn ensure_nah_state_directory(
    home: &AbsolutePath,
    _platform: Platform,
) -> Result<(), StateProtectionError> {
    let directory = PathBuf::from(home.as_str()).join(".nah");
    std::fs::create_dir_all(&directory).map_err(|_| StateProtectionError)?;
    #[cfg(windows)]
    windows::protect_directory(&directory)?;
    Ok(())
}

pub(crate) fn validate_private_file(file: &File) -> Result<(), StateProtectionError> {
    #[cfg(not(windows))]
    let _ = file;
    #[cfg(windows)]
    windows::validate_private_file(file)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StateProtectionError;

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, SE_FILE_OBJECT, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
        EqualSid, GetAce, GetAclInformation, GetLengthSid, GetTokenInformation, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::StateProtectionError;

    const INHERIT_TO_DESCENDANTS: u32 =
        windows_sys::Win32::Security::CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

    pub(super) fn protect_directory(path: &Path) -> Result<(), StateProtectionError> {
        if is_reparse_point(path)? {
            return Err(StateProtectionError);
        }
        let mut user = current_user_sid()?;
        let mut system = well_known_sid(WinLocalSystemSid)?;
        let mut administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        let entries = [
            grant_access(&mut user, TRUSTEE_IS_USER),
            grant_access(&mut system, TRUSTEE_IS_USER),
            grant_access(&mut administrators, TRUSTEE_IS_GROUP),
        ];
        let mut dacl = null_mut();
        if unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_ptr(), null(), &mut dacl) }
            != 0
        {
            return Err(StateProtectionError);
        }
        let path = wide_path(path)?;
        let result = if unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                user.as_mut_ptr().cast(),
                null_mut(),
                dacl,
                null(),
            )
        } == 0
        {
            Ok(())
        } else {
            Err(StateProtectionError)
        };
        unsafe {
            LocalFree(dacl.cast());
        }
        result
    }

    pub(super) fn validate_private_file(file: &File) -> Result<(), StateProtectionError> {
        let user = current_user_sid()?;
        let system = well_known_sid(WinLocalSystemSid)?;
        let administrators = well_known_sid(WinBuiltinAdministratorsSid)?;
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        if unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        } != 0
        {
            return Err(StateProtectionError);
        }
        let result = validate_owner_and_dacl(owner, dacl, &user, &system, &administrators);
        unsafe {
            LocalFree(descriptor);
        }
        result
    }

    fn validate_owner_and_dacl(
        owner: PSID,
        dacl: *mut windows_sys::Win32::Security::ACL,
        user: &[u8],
        system: &[u8],
        administrators: &[u8],
    ) -> Result<(), StateProtectionError> {
        if owner.is_null() || unsafe { EqualSid(owner, user.as_ptr().cast_mut().cast()) } == 0 {
            return Err(StateProtectionError);
        }
        if dacl.is_null() {
            return Err(StateProtectionError);
        }
        let mut information = ACL_SIZE_INFORMATION::default();
        if unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(StateProtectionError);
        }
        for index in 0..information.AceCount {
            let mut ace = null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(StateProtectionError);
            }
            let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
            if header.AceType != 0 {
                return Err(StateProtectionError);
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
            if [user, system, administrators]
                .iter()
                .all(|expected| unsafe { EqualSid(sid, expected.as_ptr().cast_mut().cast()) } == 0)
            {
                return Err(StateProtectionError);
            }
        }
        Ok(())
    }

    fn grant_access(sid: &mut [u8], trustee_type: i32) -> EXPLICIT_ACCESS_W {
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: INHERIT_TO_DESCENDANTS,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: trustee_type,
                ptstrName: sid.as_mut_ptr().cast(),
            },
        }
    }

    fn current_user_sid() -> Result<Vec<u8>, StateProtectionError> {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(StateProtectionError);
        }
        let result = (|| {
            let mut length: u32 = 0;
            unsafe {
                GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length);
            }
            if length == 0 {
                return Err(StateProtectionError);
            }
            let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } == 0
            {
                return Err(StateProtectionError);
            }
            let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
            sid_bytes(sid)
        })();
        unsafe {
            CloseHandle(token);
        }
        result
    }

    fn well_known_sid(kind: i32) -> Result<Vec<u8>, StateProtectionError> {
        let mut length = 0;
        unsafe {
            windows_sys::Win32::Security::CreateWellKnownSid(
                kind,
                null_mut(),
                null_mut(),
                &mut length,
            );
        }
        if length == 0 {
            return Err(StateProtectionError);
        }
        let mut sid = vec![0; length as usize];
        if unsafe {
            windows_sys::Win32::Security::CreateWellKnownSid(
                kind,
                null_mut(),
                sid.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
        {
            return Err(StateProtectionError);
        }
        Ok(sid)
    }

    fn sid_bytes(sid: PSID) -> Result<Vec<u8>, StateProtectionError> {
        if sid.is_null() {
            return Err(StateProtectionError);
        }
        let length = unsafe { GetLengthSid(sid) } as usize;
        if length == 0 {
            return Err(StateProtectionError);
        }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
    }

    fn is_reparse_point(path: &Path) -> Result<bool, StateProtectionError> {
        let path = wide_path(path)?;
        let attributes = unsafe { GetFileAttributesW(path.as_ptr()) };
        if attributes == u32::MAX {
            return Err(StateProtectionError);
        }
        Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, StateProtectionError> {
        let mut path = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if path.contains(&0) {
            return Err(StateProtectionError);
        }
        path.push(0);
        Ok(path)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn state_directory_dacl_is_inherited_by_private_files() {
        let temporary = tempfile::tempdir().unwrap();
        let home =
            AbsolutePath::new(Platform::Windows, temporary.path().to_str().unwrap()).unwrap();
        ensure_nah_state_directory(&home, Platform::Windows).unwrap();
        let file = File::create(temporary.path().join(".nah/nap.key")).unwrap();
        validate_private_file(&file).unwrap();
    }
}
