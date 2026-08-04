//! Minimal hand-rolled PKCS#11 signer, shared by the ledger's sealing key and
//! the gateway's identity key.
//!
//! PKCS#11 is the interface the target deployments actually have: on-prem
//! HSMs (Trustway, Luna, YubiHSM), smartcard middleware, and the software
//! token (SoftHSM) used in tests all expose the same C API from a vendor
//! `.so`. It is a local library call. The module may talk to a network HSM
//! internally, but this process makes no network call, like every other
//! component. Cloud KMS SDKs would break both that rule and the air-gapped
//! story; if one is ever wanted, it is another implementation wrapping this.
//!
//! The bindings are hand-rolled over `dlopen`, in the spirit of the HTTP and
//! DER code: the seven calls signing needs, not a binding crate that drags
//! in the other sixty-one. The function-list layout is frozen by the OASIS
//! standard (pkcs11f.h inclusion order, stable since v2.01), which is what
//! makes a partial binding safe: offsets cannot drift.
//!
//! Trust model note: the HSM signs what it is handed. It cannot know whether
//! the message honestly summarizes anything; that stays the caller's job.
//! What the HSM buys is that a compromised host can sign *now* but cannot
//! exfiltrate the key and sign *later, offline, at leisure*.

use std::ffi::{c_void, CString};
use std::path::Path;

/// Anything the HSM side refuses or garbles, vendor return code included.
/// One variant suffices: the operator's next step is the same (read the
/// message, check the token).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("pkcs#11: {0}")]
    Pkcs11(String),
}

// ---------------------------------------------------------------------------
// Types and constants, transcribed from the OASIS headers. CK_ULONG is
// `unsigned long` — pointer-sized on every Unix ABI this project targets.
// ---------------------------------------------------------------------------

type CkRv = libc::c_ulong;
type CkUlong = libc::c_ulong;
type CkSession = libc::c_ulong;
type CkObject = libc::c_ulong;
type CkSlotId = libc::c_ulong;

const CKR_OK: CkRv = 0;
const CKF_SERIAL_SESSION: CkUlong = 0x0004;
const CKF_OS_LOCKING_OK: CkUlong = 0x0002;
const CKF_TOKEN_PRESENT: u8 = 1;
const CKF_TOKEN_INITIALIZED: CkUlong = 0x0400;
const CKU_USER: CkUlong = 1;

const CKA_CLASS: CkUlong = 0x0000;
const CKA_LABEL: CkUlong = 0x0003;
const CKA_KEY_TYPE: CkUlong = 0x0100;
const CKA_EC_POINT: CkUlong = 0x0181;

const CKO_PUBLIC_KEY: CkUlong = 0x0002;
const CKO_PRIVATE_KEY: CkUlong = 0x0003;
const CKK_EC_EDWARDS: CkUlong = 0x0040;
const CKM_EDDSA: CkUlong = 0x1057;

#[repr(C)]
#[derive(Clone, Copy)]
struct CkVersion {
    major: u8,
    minor: u8,
}

#[repr(C)]
struct CkAttribute {
    attr_type: CkUlong,
    value: *mut c_void,
    value_len: CkUlong,
}

#[repr(C)]
struct CkMechanism {
    mechanism: CkUlong,
    parameter: *mut c_void,
    parameter_len: CkUlong,
}

#[repr(C)]
struct CkCInitializeArgs {
    create_mutex: *mut c_void,
    destroy_mutex: *mut c_void,
    lock_mutex: *mut c_void,
    unlock_mutex: *mut c_void,
    flags: CkUlong,
    reserved: *mut c_void,
}

/// Only `label` and `flags` are read; the rest exists so the struct has the
/// size and offsets `C_GetTokenInfo` writes into.
#[repr(C)]
struct CkTokenInfo {
    label: [u8; 32],
    manufacturer_id: [u8; 32],
    model: [u8; 16],
    serial_number: [u8; 16],
    flags: CkUlong,
    session_pin_memory: [CkUlong; 10],
    hardware_version: CkVersion,
    firmware_version: CkVersion,
    utc_time: [u8; 16],
}

type FnUntyped = Option<unsafe extern "C" fn()>;

/// CK_FUNCTION_LIST. The order is normative (pkcs11f.h inclusion order);
/// only the entries sealing uses are typed, the rest are opaque placeholders
/// that exist to keep the offsets right.
#[repr(C)]
struct CkFunctionList {
    version: CkVersion,
    c_initialize: Option<unsafe extern "C" fn(*mut c_void) -> CkRv>,
    c_finalize: Option<unsafe extern "C" fn(*mut c_void) -> CkRv>,
    c_get_info: FnUntyped,
    c_get_function_list: FnUntyped,
    c_get_slot_list:
        Option<unsafe extern "C" fn(u8, *mut CkSlotId, *mut CkUlong) -> CkRv>,
    c_get_slot_info: FnUntyped,
    c_get_token_info: Option<unsafe extern "C" fn(CkSlotId, *mut CkTokenInfo) -> CkRv>,
    c_get_mechanism_list: FnUntyped,
    c_get_mechanism_info: FnUntyped,
    c_init_token: FnUntyped,
    c_init_pin: FnUntyped,
    c_set_pin: FnUntyped,
    c_open_session: Option<
        unsafe extern "C" fn(CkSlotId, CkUlong, *mut c_void, *mut c_void, *mut CkSession) -> CkRv,
    >,
    c_close_session: Option<unsafe extern "C" fn(CkSession) -> CkRv>,
    c_close_all_sessions: FnUntyped,
    c_get_session_info: FnUntyped,
    c_get_operation_state: FnUntyped,
    c_set_operation_state: FnUntyped,
    c_login: Option<unsafe extern "C" fn(CkSession, CkUlong, *const u8, CkUlong) -> CkRv>,
    c_logout: Option<unsafe extern "C" fn(CkSession) -> CkRv>,
    c_create_object: FnUntyped,
    c_copy_object: FnUntyped,
    c_destroy_object: FnUntyped,
    c_get_object_size: FnUntyped,
    c_get_attribute_value:
        Option<unsafe extern "C" fn(CkSession, CkObject, *mut CkAttribute, CkUlong) -> CkRv>,
    c_set_attribute_value: FnUntyped,
    c_find_objects_init:
        Option<unsafe extern "C" fn(CkSession, *mut CkAttribute, CkUlong) -> CkRv>,
    c_find_objects: Option<
        unsafe extern "C" fn(CkSession, *mut CkObject, CkUlong, *mut CkUlong) -> CkRv,
    >,
    c_find_objects_final: Option<unsafe extern "C" fn(CkSession) -> CkRv>,
    c_encrypt_init: FnUntyped,
    c_encrypt: FnUntyped,
    c_encrypt_update: FnUntyped,
    c_encrypt_final: FnUntyped,
    c_decrypt_init: FnUntyped,
    c_decrypt: FnUntyped,
    c_decrypt_update: FnUntyped,
    c_decrypt_final: FnUntyped,
    c_digest_init: FnUntyped,
    c_digest: FnUntyped,
    c_digest_update: FnUntyped,
    c_digest_key: FnUntyped,
    c_digest_final: FnUntyped,
    c_sign_init: Option<unsafe extern "C" fn(CkSession, *mut CkMechanism, CkObject) -> CkRv>,
    c_sign: Option<
        unsafe extern "C" fn(CkSession, *const u8, CkUlong, *mut u8, *mut CkUlong) -> CkRv,
    >,
    c_sign_update: FnUntyped,
    c_sign_final: FnUntyped,
    c_sign_recover_init: FnUntyped,
    c_sign_recover: FnUntyped,
    c_verify_init: FnUntyped,
    c_verify: FnUntyped,
    c_verify_update: FnUntyped,
    c_verify_final: FnUntyped,
    c_verify_recover_init: FnUntyped,
    c_verify_recover: FnUntyped,
    c_digest_encrypt_update: FnUntyped,
    c_decrypt_digest_update: FnUntyped,
    c_sign_encrypt_update: FnUntyped,
    c_decrypt_verify_update: FnUntyped,
    c_generate_key: FnUntyped,
    c_generate_key_pair: FnUntyped,
    c_wrap_key: FnUntyped,
    c_unwrap_key: FnUntyped,
    c_derive_key: FnUntyped,
    c_seed_random: FnUntyped,
    c_generate_random: FnUntyped,
    c_get_function_status: FnUntyped,
    c_cancel_function: FnUntyped,
    c_wait_for_slot_event: FnUntyped,
}

/// Return codes worth naming: the ones an operator will actually hit while
/// bringing a token up. Everything else stays numeric, since the vendor
/// manual indexes by that number anyway.
fn rv_name(rv: CkRv) -> String {
    let known = match rv {
        0x0005 => "CKR_GENERAL_ERROR",
        0x0007 => "CKR_ARGUMENTS_BAD",
        0x0070 => "CKR_MECHANISM_INVALID",
        0x00A0 => "CKR_PIN_INCORRECT",
        0x00A2 => "CKR_PIN_LEN_RANGE",
        0x00A4 => "CKR_PIN_LOCKED",
        0x00E0 => "CKR_TOKEN_NOT_PRESENT",
        0x00E1 => "CKR_TOKEN_NOT_RECOGNIZED",
        0x0101 => "CKR_USER_NOT_LOGGED_IN",
        0x0102 => "CKR_USER_PIN_NOT_INITIALIZED",
        0x0113 => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        0x01B0 => "CKR_SLOT_ID_INVALID",
        _ => return format!("CKR 0x{rv:04X}"),
    };
    format!("{known} (0x{rv:04X})")
}

fn err(what: &str, rv: CkRv) -> Error {
    Error::Pkcs11(format!("{what}: {}", rv_name(rv)))
}

// ---------------------------------------------------------------------------
// Sealer
// ---------------------------------------------------------------------------

/// Which token to seal with, when the module exposes several.
pub enum TokenSelector {
    /// Sole token present. Errors if the module exposes more than one.
    Only,
    /// By slot id, for setups where labels are not unique.
    Slot(u64),
    /// By token label, the stable name across module restarts.
    Label(String),
}

/// [`Sealer`] over a PKCS#11 module: the key never enters this process.
///
/// One login, one session, held for the process lifetime: `run` mode must
/// not re-authenticate every pass, because each wrong PIN presented in a
/// retry loop walks the token toward `CKR_PIN_LOCKED`. Construction is where
/// credentials are checked; a failure there is fatal by design, never
/// retried.
pub struct Pkcs11Signer {
    funcs: &'static CkFunctionList,
    session: CkSession,
    private_key: CkObject,
    public_key_bytes: [u8; 32],
    key_id: String,
    /// Serializes the C_SignInit/C_Sign pair: a PKCS#11 session is not safe
    /// for two concurrent operations, and the gateway's identity signer is
    /// shared across session threads. The module itself is initialized with
    /// `CKF_OS_LOCKING_OK`; this guards the per-session operation sequence
    /// that OS locking does not.
    sign_lock: std::sync::Mutex<()>,
    // dlopen handle, never dlclosed: several vendor modules crash on
    // unload/reload cycles, and the process exits right after sealing anyway.
    _module: *mut c_void,
}

// Safety: the only non-`Send`/`Sync` field is `_module`, a dlopen handle that
// is never dereferenced after `open` (it is held solely to keep the module
// mapped). `funcs` is a `&'static` view of function pointers, `session` and
// `private_key` are integers, and every signing operation is serialized by
// `sign_lock`. Sharing across threads is therefore sound, and required: the
// HTTP gateway hands one identity signer to every session thread.
unsafe impl Send for Pkcs11Signer {}
unsafe impl Sync for Pkcs11Signer {}

impl Pkcs11Signer {
    /// Loads the vendor module, logs into the token and locates the key pair
    /// labelled `key_label`.
    ///
    /// Everything that can be misconfigured fails here, with the vendor's
    /// error code in clear text: wrong module path, wrong token, wrong PIN,
    /// absent key, or a key of the wrong type (sealing is Ed25519, and a
    /// P-256 key under the right label must not "work" by accident).
    pub fn open(
        module: &Path,
        token: &TokenSelector,
        pin: &str,
        key_label: &str,
        key_id: &str,
    ) -> Result<Self, Error> {
        let (handle, funcs) = load_module(module)?;

        let mut init_args = CkCInitializeArgs {
            create_mutex: std::ptr::null_mut(),
            destroy_mutex: std::ptr::null_mut(),
            lock_mutex: std::ptr::null_mut(),
            unlock_mutex: std::ptr::null_mut(),
            flags: CKF_OS_LOCKING_OK,
            reserved: std::ptr::null_mut(),
        };
        let rv = unsafe {
            (funcs.c_initialize.ok_or_else(|| missing("C_Initialize"))?)(
                &mut init_args as *mut _ as *mut c_void,
            )
        };
        // CKR_CRYPTOKI_ALREADY_INITIALIZED (0x0191): fine, someone in this
        // process already did it (tests share a module).
        if rv != CKR_OK && rv != 0x0191 {
            return Err(err("C_Initialize", rv));
        }

        let slot = select_slot(funcs, token)?;

        let mut session: CkSession = 0;
        let rv = unsafe {
            (funcs.c_open_session.ok_or_else(|| missing("C_OpenSession"))?)(
                slot,
                CKF_SERIAL_SESSION, // read-only: sealing never writes to the token
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut session,
            )
        };
        if rv != CKR_OK {
            return Err(err("C_OpenSession", rv));
        }
        // From here every failure must close the session: PKCS#11 login
        // state is per token per process, so a session leaked half-open
        // ("no such key" during bring-up, say) would bleed into the next
        // attempt.
        let guard = SessionGuard { funcs, session };

        let rv = unsafe {
            (funcs.c_login.ok_or_else(|| missing("C_Login"))?)(
                session,
                CKU_USER,
                pin.as_ptr(),
                pin.len() as CkUlong,
            )
        };
        // CKR_USER_ALREADY_LOGGED_IN (0x0100): another session of this
        // process already authenticated this token. The state we need is
        // there; who established it does not matter.
        if rv != CKR_OK && rv != 0x0100 {
            return Err(err("C_Login", rv));
        }

        let private_key = find_key(funcs, session, CKO_PRIVATE_KEY, key_label)?
            .ok_or_else(|| {
                Error::Pkcs11(format!(
                    "no private key labelled \"{key_label}\" on this token"
                ))
            })?;
        check_is_ed25519(funcs, session, private_key, key_label)?;

        // The public half comes from the token too — pasting it from config
        // would let a config editor decide which key seals "verify". The
        // private object usually hides its attributes, so read the point off
        // the public object of the same label, falling back to the private
        // one for tokens that do expose it.
        let public_object = find_key(funcs, session, CKO_PUBLIC_KEY, key_label)?
            .unwrap_or(private_key);
        let point = read_attribute(funcs, session, public_object, CKA_EC_POINT)
            .map_err(|_| {
                Error::Pkcs11(format!(
                    "cannot read the public key for \"{key_label}\": the token \
                     holds no public key object under that label. Import or \
                     regenerate the pair so both halves share the label."
                ))
            })?;
        let public_key_bytes = parse_ec_point(&point)?;

        std::mem::forget(guard); // the session now belongs to the signer
        Ok(Pkcs11Signer {
            funcs,
            session,
            private_key,
            public_key_bytes,
            key_id: key_id.to_string(),
            sign_lock: std::sync::Mutex::new(()),
            _module: handle,
        })
    }
}

/// Closes the session if construction bails after `C_OpenSession`.
struct SessionGuard {
    funcs: &'static CkFunctionList,
    session: CkSession,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(f) = self.funcs.c_close_session {
                f(self.session);
            }
        }
    }
}

impl std::fmt::Debug for Pkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Signer")
            .field("key_id", &self.key_id)
            .field("public_key", &hex::encode(self.public_key_bytes))
            .finish_non_exhaustive()
    }
}

impl Pkcs11Signer {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The raw public key, 32 bytes. Callers wrap it in a role-specific
    /// `PublicKeyEntry` (a sealing key for the ledger, an identity key for the
    /// gateway), so this crate stays free of the obsign-audit-core role type.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key_bytes
    }

    /// Ed25519 signature over the message. The private key never leaves the
    /// token.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        // One operation at a time on this session; released when this returns.
        let _guard = self.sign_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut mech = CkMechanism {
            mechanism: CKM_EDDSA, // no params: pure Ed25519, matching the verifier
            parameter: std::ptr::null_mut(),
            parameter_len: 0,
        };
        let rv = unsafe {
            (self.funcs.c_sign_init.ok_or_else(|| missing("C_SignInit"))?)(
                self.session,
                &mut mech,
                self.private_key,
            )
        };
        if rv != CKR_OK {
            return Err(err("C_SignInit", rv));
        }

        let mut sig = [0u8; 64];
        let mut sig_len: CkUlong = 64;
        let rv = unsafe {
            (self.funcs.c_sign.ok_or_else(|| missing("C_Sign"))?)(
                self.session,
                message.as_ptr(),
                message.len() as CkUlong,
                sig.as_mut_ptr(),
                &mut sig_len,
            )
        };
        if rv != CKR_OK {
            return Err(err("C_Sign", rv));
        }
        if sig_len != 64 {
            return Err(Error::Pkcs11(format!(
                "the token produced a {sig_len}-byte signature, Ed25519 makes 64"
            )));
        }
        Ok(sig)
    }
}

impl Drop for Pkcs11Signer {
    fn drop(&mut self) {
        // Close, do not C_Logout: login state is shared by every session of
        // this token in this process, so an explicit logout here would
        // de-authenticate any other live sealer. Closing the last session
        // resets the login state anyway (PKCS#11 §C_CloseSession).
        // No C_Finalize either: same sharing argument, and the OS reclaims
        // everything at exit.
        unsafe {
            if let Some(f) = self.funcs.c_close_session {
                f(self.session);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Module plumbing
// ---------------------------------------------------------------------------

fn missing(name: &str) -> Error {
    Error::Pkcs11(format!("the module does not provide {name}"))
}

fn load_module(path: &Path) -> Result<(*mut c_void, &'static CkFunctionList), Error> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        Error::Pkcs11(format!("module path contains a NUL byte: {}", path.display()))
    })?;
    let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let reason = unsafe {
            let e = libc::dlerror();
            if e.is_null() {
                "unknown dlopen error".to_string()
            } else {
                std::ffi::CStr::from_ptr(e).to_string_lossy().into_owned()
            }
        };
        return Err(Error::Pkcs11(format!(
            "cannot load {}: {reason}",
            path.display()
        )));
    }

    let sym = unsafe { libc::dlsym(handle, c"C_GetFunctionList".as_ptr()) };
    if sym.is_null() {
        return Err(Error::Pkcs11(format!(
            "{} exports no C_GetFunctionList: not a PKCS#11 module",
            path.display()
        )));
    }
    let get_list: unsafe extern "C" fn(*mut *mut CkFunctionList) -> CkRv =
        unsafe { std::mem::transmute(sym) };

    let mut list: *mut CkFunctionList = std::ptr::null_mut();
    let rv = unsafe { get_list(&mut list) };
    if rv != CKR_OK || list.is_null() {
        return Err(err("C_GetFunctionList", rv));
    }
    let funcs: &'static CkFunctionList = unsafe { &*list };

    // v3 modules answer here with their v2.40-compatible list, so both major
    // versions are fine; anything else means the offsets cannot be trusted.
    if funcs.version.major != 2 && funcs.version.major != 3 {
        return Err(Error::Pkcs11(format!(
            "unsupported Cryptoki version {}.{}",
            funcs.version.major, funcs.version.minor
        )));
    }
    Ok((handle, funcs))
}

fn select_slot(funcs: &CkFunctionList, token: &TokenSelector) -> Result<CkSlotId, Error> {
    if let TokenSelector::Slot(id) = token {
        return Ok(*id as CkSlotId);
    }

    let get_slot_list = funcs.c_get_slot_list.ok_or_else(|| missing("C_GetSlotList"))?;
    let mut count: CkUlong = 0;
    let rv = unsafe { get_slot_list(CKF_TOKEN_PRESENT, std::ptr::null_mut(), &mut count) };
    if rv != CKR_OK {
        return Err(err("C_GetSlotList", rv));
    }
    let mut slots = vec![0 as CkSlotId; count as usize];
    let rv = unsafe { get_slot_list(CKF_TOKEN_PRESENT, slots.as_mut_ptr(), &mut count) };
    if rv != CKR_OK {
        return Err(err("C_GetSlotList", rv));
    }
    slots.truncate(count as usize);

    let get_token_info = funcs.c_get_token_info.ok_or_else(|| missing("C_GetTokenInfo"))?;
    let mut labelled: Vec<(CkSlotId, String)> = Vec::new();
    for slot in slots {
        let mut info: CkTokenInfo = unsafe { std::mem::zeroed() };
        let rv = unsafe { get_token_info(slot, &mut info) };
        if rv != CKR_OK {
            return Err(err("C_GetTokenInfo", rv));
        }
        // SoftHSM (and some HSMs) always advertise a blank, uninitialized
        // spare slot; a token nobody provisioned cannot be the sealing token.
        if info.flags & CKF_TOKEN_INITIALIZED == 0 {
            continue;
        }
        labelled.push((slot, token_label(&info.label)));
    }

    match token {
        TokenSelector::Slot(_) => unreachable!("handled above"),
        TokenSelector::Only => match labelled.as_slice() {
            [] => Err(Error::Pkcs11("no token present".to_string())),
            [(slot, _)] => Ok(*slot),
            many => Err(Error::Pkcs11(format!(
                "several tokens present ({}): pick one with --hsm-token-label \
                 or --hsm-slot",
                many.iter()
                    .map(|(s, l)| format!("slot {s} \"{l}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        },
        TokenSelector::Label(wanted) => labelled
            .iter()
            .find(|(_, l)| l == wanted)
            .map(|(s, _)| *s)
            .ok_or_else(|| {
                Error::Pkcs11(format!(
                    "no token labelled \"{wanted}\" (present: {})",
                    labelled
                        .iter()
                        .map(|(s, l)| format!("slot {s} \"{l}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }),
    }
}

/// Token labels are 32 bytes, space-padded, never NUL-terminated.
fn token_label(raw: &[u8; 32]) -> String {
    String::from_utf8_lossy(raw).trim_end().to_string()
}

/// Finds the object of `class` labelled `label`. `Ok(None)` when absent, and
/// two candidates is an error. Sealing must never sign with "whichever".
fn find_key(
    funcs: &CkFunctionList,
    session: CkSession,
    class: CkUlong,
    label: &str,
) -> Result<Option<CkObject>, Error> {
    let mut class_val = class;
    let mut template = [
        CkAttribute {
            attr_type: CKA_CLASS,
            value: &mut class_val as *mut _ as *mut c_void,
            value_len: std::mem::size_of::<CkUlong>() as CkUlong,
        },
        CkAttribute {
            attr_type: CKA_LABEL,
            value: label.as_ptr() as *mut c_void,
            value_len: label.len() as CkUlong,
        },
    ];

    let rv = unsafe {
        (funcs.c_find_objects_init.ok_or_else(|| missing("C_FindObjectsInit"))?)(
            session,
            template.as_mut_ptr(),
            template.len() as CkUlong,
        )
    };
    if rv != CKR_OK {
        return Err(err("C_FindObjectsInit", rv));
    }

    let mut handles = [0 as CkObject; 2];
    let mut found: CkUlong = 0;
    let rv = unsafe {
        (funcs.c_find_objects.ok_or_else(|| missing("C_FindObjects"))?)(
            session,
            handles.as_mut_ptr(),
            handles.len() as CkUlong,
            &mut found,
        )
    };
    unsafe {
        if let Some(f) = funcs.c_find_objects_final {
            f(session);
        }
    }
    if rv != CKR_OK {
        return Err(err("C_FindObjects", rv));
    }

    match found {
        0 => Ok(None),
        1 => Ok(Some(handles[0])),
        _ => Err(Error::Pkcs11(format!(
            "several objects labelled \"{label}\" on this token: relabel so \
             the sealing key is unambiguous"
        ))),
    }
}

fn read_attribute(
    funcs: &CkFunctionList,
    session: CkSession,
    object: CkObject,
    attr: CkUlong,
) -> Result<Vec<u8>, Error> {
    let get = funcs
        .c_get_attribute_value
        .ok_or_else(|| missing("C_GetAttributeValue"))?;

    let mut probe = CkAttribute {
        attr_type: attr,
        value: std::ptr::null_mut(),
        value_len: 0,
    };
    let rv = unsafe { get(session, object, &mut probe, 1) };
    // CK_UNAVAILABLE_INFORMATION comes back as length !0.
    if rv != CKR_OK || probe.value_len == CkUlong::MAX {
        return Err(err("C_GetAttributeValue", rv));
    }

    let mut buf = vec![0u8; probe.value_len as usize];
    let mut fetch = CkAttribute {
        attr_type: attr,
        value: buf.as_mut_ptr() as *mut c_void,
        value_len: buf.len() as CkUlong,
    };
    let rv = unsafe { get(session, object, &mut fetch, 1) };
    if rv != CKR_OK {
        return Err(err("C_GetAttributeValue", rv));
    }
    buf.truncate(fetch.value_len as usize);
    Ok(buf)
}

/// Refuses to seal with anything but an Ed25519 key. A P-256 key under the
/// right label would fail signature self-check anyway, but "wrong key type"
/// beats "signature verification failed" as an error message.
fn check_is_ed25519(
    funcs: &CkFunctionList,
    session: CkSession,
    key: CkObject,
    label: &str,
) -> Result<(), Error> {
    let raw = read_attribute(funcs, session, key, CKA_KEY_TYPE)
        .map_err(|e| Error::Pkcs11(format!("cannot read the type of \"{label}\": {e}")))?;
    let mut bytes = [0u8; std::mem::size_of::<CkUlong>()];
    if raw.len() != bytes.len() {
        return Err(Error::Pkcs11(format!(
            "malformed CKA_KEY_TYPE for \"{label}\" ({} bytes)",
            raw.len()
        )));
    }
    bytes.copy_from_slice(&raw);
    let key_type = CkUlong::from_ne_bytes(bytes);
    if key_type != CKK_EC_EDWARDS {
        return Err(Error::Pkcs11(format!(
            "\"{label}\" is not an Ed25519 key (CKK 0x{key_type:04X}): sealing \
             signs Ed25519 only"
        )));
    }
    Ok(())
}

/// CKA_EC_POINT for Edwards keys: the standard says DER OCTET STRING around
/// the 32-byte compressed point; some tokens hand back the bare point.
/// Anything else is refused, because guessing at key material is not an
/// option.
fn parse_ec_point(der: &[u8]) -> Result<[u8; 32], Error> {
    let raw: &[u8] = match der {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        bare if bare.len() == 32 => bare,
        other => {
            return Err(Error::Pkcs11(format!(
                "unrecognized CKA_EC_POINT encoding ({} bytes): {}",
                other.len(),
                hex::encode(&other[..other.len().min(8)])
            )))
        }
    };
    let mut point = [0u8; 32];
    point.copy_from_slice(raw);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_point_wrapped_in_octet_string() {
        let mut der = vec![0x04, 0x20];
        der.extend_from_slice(&[7u8; 32]);
        assert_eq!(parse_ec_point(&der).unwrap(), [7u8; 32]);
    }

    #[test]
    fn ec_point_bare() {
        assert_eq!(parse_ec_point(&[9u8; 32]).unwrap(), [9u8; 32]);
    }

    #[test]
    fn ec_point_wrong_size_refused() {
        assert!(parse_ec_point(&[1u8; 33]).is_err());
        assert!(parse_ec_point(&[0x04, 0x21, 0x00]).is_err());
        assert!(parse_ec_point(&[]).is_err());
    }

    #[test]
    fn token_label_trims_padding_only_on_the_right() {
        let mut raw = [b' '; 32];
        raw[..11].copy_from_slice(b"obsign-seal");
        assert_eq!(token_label(&raw), "obsign-seal");
        let mut raw = [b' '; 32];
        raw[1..5].copy_from_slice(b"abcd");
        assert_eq!(token_label(&raw), " abcd");
    }

    #[test]
    fn rv_names_the_operator_facing_codes() {
        assert_eq!(rv_name(0x00A0), "CKR_PIN_INCORRECT (0x00A0)");
        assert_eq!(rv_name(0xDEAD), "CKR 0xDEAD");
    }
}
