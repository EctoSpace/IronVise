//! Windows Job Objects: every child process dies with the supervisor.

use super::*;

/// Static holder for the Windows Job Object handle.
/// Must remain open for the lifetime of the process;
/// when the last handle closes, all processes in the job are terminated.
#[cfg(target_os = "windows")]
pub(super) struct SyncHandle(#[allow(dead_code)] pub(super) windows::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
// SAFETY: The handle is only written once during initialisation (via OnceLock)
// and is never closed or mutated afterwards, so sharing it across threads is safe.
unsafe impl Send for SyncHandle {}
#[cfg(target_os = "windows")]
unsafe impl Sync for SyncHandle {}

#[cfg(target_os = "windows")]
pub(super) static JOB_OBJECT_HANDLE: std::sync::OnceLock<SyncHandle> = std::sync::OnceLock::new();

/// Creates a Windows Job Object, configures it with `KILL_ON_JOB_CLOSE` and
/// full UI restrictions, then assigns the current process to it.
///
/// The Job Object ensures that if the supervisor process exits (or is killed) the
/// child processes it spawned are automatically terminated - preventing orphan LLM
/// tool processes from persisting on the host.
///
/// **CRITICAL**: The job handle must be stored statically; if it's dropped,
/// all processes in the job are immediately terminated.
#[cfg(target_os = "windows")]
pub(super) fn apply_windows_job_object() -> Result<(), SandboxError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
        JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let job: HANDLE = CreateJobObjectW(None, None).map_err(SandboxError::Windows)?;

        // Kill all processes in the job when the last handle to the job object closes.
        // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE requires the *extended* limit struct;
        // using JOBOBJECT_BASIC_LIMIT_INFORMATION returns ERROR_INVALID_PARAMETER.
        let mut ext_limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        ext_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &ext_limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .map_err(SandboxError::Windows)?;

        // Prevent UI escalation vectors (desktop switching, clipboard theft, etc.).
        let ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            &ui_limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
        .map_err(SandboxError::Windows)?;

        AssignProcessToJobObject(job, GetCurrentProcess()).map_err(SandboxError::Windows)?;

        // Store the handle statically so it remains open for the lifetime of the process.
        // If this handle is dropped, kernel immediately terminates all processes in the job.
        JOB_OBJECT_HANDLE.get_or_init(|| SyncHandle(job));
    }

    tracing::info!("Windows Job Object sandbox applied (KILL_ON_JOB_CLOSE + UI restrictions).");
    Ok(())
}
