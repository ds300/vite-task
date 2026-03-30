use std::{
    ffi::{CStr, c_char},
    io,
    os::windows::{ffi::OsStrExt, io::AsRawHandle, process::ChildExt as _},
    path::Path,
    sync::Arc,
};

use const_format::formatcp;
use fspy_detours_sys::{DetourCopyPayloadToProcess, DetourUpdateProcessWithDll};
use fspy_shared::{
    ipc::{BINCODE_CONFIG, PathAccess, channel::channel},
    windows::{PAYLOAD_ID, Payload},
};
use futures_util::FutureExt;
use tokio_util::sync::CancellationToken;
use winapi::{
    shared::minwindef::TRUE,
    um::{processthreadsapi::ResumeThread, winbase::CREATE_SUSPENDED},
};
use winsafe::co::{CP, WC};
use xxhash_rust::const_xxh3::xxh3_128;

use crate::{
    ChildTermination, TrackedChild,
    artifact::Artifact,
    command::Command,
    error::SpawnError,
    ipc::{OwnedReceiverLockGuard, SHM_CAPACITY},
};

const PRELOAD_CDYLIB_BINARY: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_FSPY_PRELOAD_WINDOWS"));
const INTERPOSE_CDYLIB: Artifact = Artifact::new(
    "fsyp_preload",
    PRELOAD_CDYLIB_BINARY,
    formatcp!("{:x}", xxh3_128(PRELOAD_CDYLIB_BINARY)),
);

pub struct PathAccessIterable {
    ipc_receiver_lock_guard: OwnedReceiverLockGuard,
}

impl PathAccessIterable {
    pub fn iter(&self) -> impl Iterator<Item = PathAccess<'_>> {
        self.ipc_receiver_lock_guard.iter_path_accesses()
    }
}

// pub struct TracedProcess {
//     pub child: Child,
//     pub path_access_stream: PathAccessIter,
// }

#[derive(Debug, Clone)]
pub struct SpyImpl {
    ansi_dll_path_with_nul: Arc<CStr>,
}

impl SpyImpl {
    pub fn init_in(path: &Path) -> io::Result<Self> {
        let dll_path = INTERPOSE_CDYLIB.write_to(path, ".dll").unwrap();

        let wide_dll_path = dll_path.as_os_str().encode_wide().collect::<Vec<u16>>();
        let mut ansi_dll_path =
            winsafe::WideCharToMultiByte(CP::ACP, WC::NoValue, &wide_dll_path, None, None)
                .map_err(|err| io::Error::from_raw_os_error(err.raw().cast_signed()))?;

        ansi_dll_path.push(0);

        // SAFETY: we just pushed a NUL byte, so the slice is NUL-terminated
        let ansi_dll_path_with_nul =
            unsafe { CStr::from_bytes_with_nul_unchecked(ansi_dll_path.as_slice()) };
        Ok(Self { ansi_dll_path_with_nul: ansi_dll_path_with_nul.into() })
    }

    #[expect(clippy::unused_async, reason = "async signature required by SpyImpl trait")]
    pub(crate) async fn spawn(
        &self,
        mut command: Command,
        cancellation_token: CancellationToken,
    ) -> Result<TrackedChild, SpawnError> {
        let ansi_dll_path_with_nul = Arc::clone(&self.ansi_dll_path_with_nul);
        let raw_token = command.raw_token.take();
        command.env("FSPY", "1");
        let mut command = command.into_tokio_command();

        command.creation_flags(CREATE_SUSPENDED);

        let (channel_conf, receiver) =
            channel(SHM_CAPACITY).map_err(SpawnError::ChannelCreation)?;

        let mut spawn_success = false;
        let spawn_success = &mut spawn_success;
        let mut child = command
            .spawn_with(|std_command| {
                let std_child = std_command.spawn()?;
                *spawn_success = true;

                // If a token was provided, swap the process's primary token
                // BEFORE resuming the main thread. NtSetInformationProcess with
                // ProcessAccessToken works only when no threads have run yet
                // (the process is CREATE_SUSPENDED).
                if let Some(token) = raw_token {
                    set_process_token(&std_child, token)?;
                }

                inject_and_resume(&std_child, &ansi_dll_path_with_nul, &channel_conf)?;

                Ok(std_child)
            })
            .map_err(|err| {
                if *spawn_success { SpawnError::OsSpawn(err) } else { SpawnError::Injection(err) }
            })?;

        // Duplicate the process handle before the child is moved into the background
        // task. The duplicate is independently owned (its own ref count), so it stays
        // valid even after tokio closes its copy when the process exits.
        let process_handle = {
            use std::os::windows::io::BorrowedHandle;
            // SAFETY: The child was just spawned and hasn't been moved yet, so its
            // raw handle is valid. `borrow_raw` creates a temporary borrow.
            let borrowed = unsafe { BorrowedHandle::borrow_raw(child.raw_handle().unwrap()) };
            borrowed.try_clone_to_owned().map_err(SpawnError::OsSpawn)?
        };

        Ok(TrackedChild {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            process_handle,
            // Keep polling for the child to exit in the background even if `wait_handle` is not awaited,
            // because we need to stop the supervisor and lock the channel as soon as the child exits.
            wait_handle: tokio::spawn(async move {
                let status = tokio::select! {
                    status = child.wait() => status?,
                    () = cancellation_token.cancelled() => {
                        child.start_kill()?;
                        child.wait().await?
                    }
                };
                // Lock the ipc channel after the child has exited.
                // We are not interested in path accesses from descendants after the main child has exited.
                let ipc_receiver_lock_guard = OwnedReceiverLockGuard::lock_async(receiver).await?;
                let path_accesses = PathAccessIterable { ipc_receiver_lock_guard };

                io::Result::Ok(ChildTermination { status, path_accesses })
            })
            .map(|f| f?) // flatten JoinError and io::Result
            .boxed(),
        })
    }
}

/// Inject the Detours DLL, copy the IPC payload, and resume the main thread.
fn inject_and_resume(
    std_child: &std::process::Child,
    ansi_dll_path_with_nul: &CStr,
    channel_conf: &fspy_shared::ipc::channel::ChannelConf,
) -> io::Result<()> {
    let mut dll_paths = ansi_dll_path_with_nul.as_ptr().cast::<c_char>();
    let process_handle = std_child.as_raw_handle().cast::<winapi::ctypes::c_void>();

    let success =
        unsafe { DetourUpdateProcessWithDll(process_handle, &raw mut dll_paths, 1) };
    if success != TRUE {
        return Err(io::Error::last_os_error());
    }

    let payload = Payload {
        channel_conf: channel_conf.clone(),
        ansi_dll_path_with_nul: ansi_dll_path_with_nul.to_bytes(),
    };
    let payload_bytes = bincode::encode_to_vec(payload, BINCODE_CONFIG).unwrap();
    let success = unsafe {
        DetourCopyPayloadToProcess(
            process_handle,
            &PAYLOAD_ID,
            payload_bytes.as_ptr().cast(),
            payload_bytes.len().try_into().unwrap(),
        )
    };
    if success != TRUE {
        return Err(io::Error::last_os_error());
    }

    let main_thread_handle = std_child.main_thread_handle();
    let resume_thread_ret =
        unsafe { ResumeThread(main_thread_handle.as_raw_handle().cast()) }
            .cast_signed();
    if resume_thread_ret == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Replace a suspended process's primary token using `NtSetInformationProcess`.
///
/// This must be called BEFORE any thread in the process has been resumed.
/// `NtSetInformationProcess(ProcessAccessToken)` is the only way to change
/// a process's primary token after creation — `SetTokenInformation` doesn't
/// support this.
fn set_process_token(
    child: &std::process::Child,
    token: std::os::windows::io::RawHandle,
) -> io::Result<()> {
    // ProcessAccessToken = 9
    const PROCESS_ACCESS_TOKEN: u32 = 9;

    #[repr(C)]
    struct ProcessAccessTokenInfo {
        token: *mut core::ffi::c_void,
        thread: *mut core::ffi::c_void, // must be NULL
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationProcess(
            ProcessHandle: *mut core::ffi::c_void,
            ProcessInformationClass: u32,
            ProcessInformation: *const core::ffi::c_void,
            ProcessInformationLength: u32,
        ) -> i32; // NTSTATUS
    }

    let info = ProcessAccessTokenInfo {
        token: token.cast(),
        thread: std::ptr::null_mut(),
    };

    let process_handle = child.as_raw_handle().cast();
    let status = unsafe {
        NtSetInformationProcess(
            process_handle,
            PROCESS_ACCESS_TOKEN,
            &info as *const _ as *const _,
            std::mem::size_of::<ProcessAccessTokenInfo>() as u32,
        )
    };

    if status < 0 {
        Err(io::Error::from_raw_os_error(
            winapi::shared::ntstatus::STATUS_ACCESS_DENIED, // approximate
        ))
    } else {
        Ok(())
    }
}
