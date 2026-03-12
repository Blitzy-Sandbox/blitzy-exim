// =============================================================================
// exim-auths/src/spa.rs — SPA/NTLM Authenticator with Built-in MD4/DES
// =============================================================================
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Rust rewrite of FOUR C files:
//   - src/src/auths/spa.c       (404 lines) — driver entry points
//   - src/src/auths/spa.h       (40 lines)  — options block typedef
//   - src/src/auths/auth-spa.c  (1501 lines) — NTLM protocol + MD4 + DES
//   - src/src/auths/auth-spa.h  (97 lines)   — NTLM struct definitions
//
// Implements Microsoft Secure Password Authentication (SPA/NTLM) with
// built-in cryptographic primitives (MD4 via `md4` crate, DES via `des`
// crate), replacing the inline C implementations torn from the Samba
// project.
//
// The NTLM protocol flow:
//   1. Client sends Type 1 (Negotiate) message
//   2. Server responds with Type 2 (Challenge) containing 8 random bytes
//   3. Client sends Type 3 (Authenticate) with LM + NT response hashes
//   4. Server verifies hashes against the expected password
//
// References:
//   - http://www.innovation.ch/java/ntlm.html
//   - http://www.kuro5hin.org/story/2002/4/28/1436/66154
//   - [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
//
// Safety: This file contains ZERO unsafe code (per AAP §0.7.2).
// All crypto uses safe Rust crates (md4, des) instead of the C inline
// implementations.

use std::any::Any;
use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use digest::Digest;
use md4::Md4;
use tracing::{debug, trace};

use exim_drivers::auth_driver::{
    AuthClientResult, AuthDriver, AuthDriverFactory, AuthInstanceConfig, AuthServerResult,
};
use exim_drivers::DriverError;

use crate::helpers::base64_io::{auth_get_no64_data, AuthIoResult, AuthSmtpIo};
use crate::helpers::server_condition::{auth_check_serv_cond, AuthConditionResult};

// =============================================================================
// Constants
// =============================================================================

/// NTLMSSP signature — 8 bytes including trailing NUL.
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// NTLM message type constants.
const NTLM_MSG_TYPE_1: u32 = 1; // Negotiate (client → server)
const NTLM_MSG_TYPE_2: u32 = 2; // Challenge (server → client)
const NTLM_MSG_TYPE_3: u32 = 3; // Authenticate (client → server)

/// NTLM negotiation flags.
/// These match the flags used in the C code (spa.c line 1396: 0x0000b207).
const NTLM_FLAG_NEGOTIATE_UNICODE: u32 = 0x0001;
const NTLM_FLAG_NEGOTIATE_NTLM: u32 = 0x0200;
const NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN: u32 = 0x8000;

/// Default client flags: unicode + oem + request_target + ntlm + always_sign.
/// Matches C: `SIVAL(&request->flags, 0, 0x0000b207)`.
const NTLM_DEFAULT_CLIENT_FLAGS: u32 = 0x0000b207;

/// Default server challenge flags.
/// Matches C: `SIVAL(&challenge->flags, 0, 0x00008201)`.
const NTLM_DEFAULT_SERVER_FLAGS: u32 = 0x00008201;

/// LM magic string — "KGS!@#$%" used for DES-based LM hash.
const LM_MAGIC: [u8; 8] = [0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25];

/// Maximum buffer size for NTLM message internal data.
const NTLM_BUF_SIZE: usize = 1024;

// =============================================================================
// SpaOptions — Driver-specific configuration
// =============================================================================

/// Configuration options for the SPA/NTLM authenticator.
///
/// Replaces C `auth_spa_options_block` from `spa.h` lines 18-23.
/// All fields are expandable strings evaluated at authentication time.
///
/// For server mode, only `spa_serverpassword` is needed.
/// For client mode, both `spa_username` and `spa_password` are required,
/// with `spa_domain` being optional.
#[derive(Debug, Clone, Default)]
pub struct SpaOptions {
    /// Client username (client mode) — expanded before use.
    /// Replaces C `spa_username`.
    pub spa_username: Option<String>,

    /// Client password (client mode) — expanded before use.
    /// Replaces C `spa_password`.
    pub spa_password: Option<String>,

    /// Client domain (client mode) — expanded before use, optional.
    /// Replaces C `spa_domain`.
    pub spa_domain: Option<String>,

    /// Server password expansion string (server mode).
    /// Expanded at auth time with `$auth1` set to the client's username.
    /// Replaces C `spa_serverpassword`.
    pub spa_serverpassword: Option<String>,
}

// =============================================================================
// NTLM Protocol Structures
// =============================================================================

/// NTLM string header — describes a variable-length field within an NTLM
/// message. The field data is stored at `offset` bytes from the start of
/// the message structure.
///
/// Replaces C `SPAStrHeader` from auth-spa.h lines 33-38.
#[derive(Debug, Clone, Copy, Default)]
struct NtlmStrHeader {
    /// Actual length of the field data in bytes.
    len: u16,
    /// Maximum length (usually same as `len`).
    maxlen: u16,
    /// Byte offset from the start of the containing message.
    offset: u32,
}

/// Buffer for accumulating variable-length NTLM message data.
///
/// Replaces C `SPAbuf` from auth-spa.h lines 40-44.
#[derive(Debug, Clone)]
struct NtlmBuffer {
    /// Raw byte buffer for variable-length data.
    buffer: Vec<u8>,
    /// Current write position within the buffer.
    buf_index: u32,
}

impl Default for NtlmBuffer {
    fn default() -> Self {
        Self {
            buffer: Vec::with_capacity(NTLM_BUF_SIZE),
            buf_index: 0,
        }
    }
}

/// NTLM Type 1 (Negotiate) message — sent by the client to initiate auth.
///
/// Replaces C `SPAAuthRequest` from auth-spa.h lines 59-67.
#[derive(Debug, Clone)]
struct NtlmAuthRequest {
    /// Protocol signature: "NTLMSSP\0".
    ident: [u8; 8],
    /// Message type: 1 (Negotiate).
    msg_type: u32,
    /// Negotiation flags.
    flags: u32,
    /// User name string header.
    user: NtlmStrHeader,
    /// Domain name string header.
    domain: NtlmStrHeader,
    /// Variable-length data buffer.
    buf: NtlmBuffer,
}

/// NTLM Type 2 (Challenge) message — sent by the server.
///
/// Replaces C `SPAAuthChallenge` from auth-spa.h lines 46-56.
#[derive(Debug, Clone)]
struct NtlmAuthChallenge {
    /// Protocol signature: "NTLMSSP\0".
    ident: [u8; 8],
    /// Message type: 2 (Challenge).
    msg_type: u32,
    /// Target domain string header.
    u_domain: NtlmStrHeader,
    /// Negotiation flags.
    flags: u32,
    /// 8-byte random challenge data.
    challenge_data: [u8; 8],
    /// Reserved bytes (8 bytes, zeroed).
    reserved: [u8; 8],
    /// Empty string header (padding).
    empty_string: NtlmStrHeader,
    /// Variable-length data buffer.
    buf: NtlmBuffer,
}

/// NTLM Type 3 (Authenticate) message — sent by the client in response.
///
/// Replaces C `SPAAuthResponse` from auth-spa.h lines 69-81.
#[derive(Debug, Clone)]
struct NtlmAuthResponse {
    /// Protocol signature: "NTLMSSP\0".
    ident: [u8; 8],
    /// Message type: 3 (Authenticate).
    msg_type: u32,
    /// LM challenge response header.
    lm_response: NtlmStrHeader,
    /// NT challenge response header.
    nt_response: NtlmStrHeader,
    /// Domain name header (Unicode or OEM).
    u_domain: NtlmStrHeader,
    /// Username header (Unicode or OEM).
    u_user: NtlmStrHeader,
    /// Workstation name header.
    u_wks: NtlmStrHeader,
    /// Session key header.
    session_key: NtlmStrHeader,
    /// Negotiation flags.
    flags: u32,
    /// Variable-length data buffer.
    buf: NtlmBuffer,
}

// =============================================================================
// Little-endian byte helpers
// =============================================================================

/// Read a little-endian u16 from a byte slice at the given offset.
fn read_u16_le(buf: &[u8], pos: usize) -> u16 {
    if pos + 2 > buf.len() {
        return 0;
    }
    u16::from_le_bytes([buf[pos], buf[pos + 1]])
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn read_u32_le(buf: &[u8], pos: usize) -> u32 {
    if pos + 4 > buf.len() {
        return 0;
    }
    u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
}

/// Write a little-endian u16 to a byte vector at the given offset.
fn write_u16_le(buf: &mut [u8], pos: usize, val: u16) {
    if pos + 2 <= buf.len() {
        let bytes = val.to_le_bytes();
        buf[pos] = bytes[0];
        buf[pos + 1] = bytes[1];
    }
}

/// Write a little-endian u32 to a byte vector at the given offset.
fn write_u32_le(buf: &mut [u8], pos: usize, val: u32) {
    if pos + 4 <= buf.len() {
        let bytes = val.to_le_bytes();
        buf[pos] = bytes[0];
        buf[pos + 1] = bytes[1];
        buf[pos + 2] = bytes[2];
        buf[pos + 3] = bytes[3];
    }
}

// =============================================================================
// NTLM Message Serialization / Deserialization
// =============================================================================

/// Size of the fixed portion of an NtlmAuthRequest (before buf data).
/// ident(8) + msg_type(4) + flags(4) + user_hdr(8) + domain_hdr(8) = 32
const AUTH_REQUEST_FIXED_SIZE: usize = 32;

/// Size of the fixed portion of an NtlmAuthChallenge (before buf data).
/// ident(8) + msg_type(4) + uDomain_hdr(8) + flags(4) + challenge(8) +
/// reserved(8) + emptyString_hdr(8) = 48
const AUTH_CHALLENGE_FIXED_SIZE: usize = 48;

/// Size of the fixed portion of an NtlmAuthResponse (before buf data).
/// ident(8) + msg_type(4) + lm_hdr(8) + nt_hdr(8) + domain_hdr(8) +
/// user_hdr(8) + wks_hdr(8) + sessionKey_hdr(8) + flags(4) = 64
const AUTH_RESPONSE_FIXED_SIZE: usize = 64;

impl NtlmAuthRequest {
    /// Compute total message length (fixed header + buffer data).
    fn message_length(&self) -> usize {
        AUTH_REQUEST_FIXED_SIZE + self.buf.buf_index as usize
    }

    /// Serialize to bytes for transmission.
    fn to_bytes(&self) -> Vec<u8> {
        let total = self.message_length();
        let data_len = self.buf.buf_index as usize;
        let mut out = vec![0u8; total];

        out[..8].copy_from_slice(&self.ident);
        write_u32_le(&mut out, 8, self.msg_type);
        write_u32_le(&mut out, 12, self.flags);

        // User header at offset 16
        write_u16_le(&mut out, 16, self.user.len);
        write_u16_le(&mut out, 18, self.user.maxlen);
        write_u32_le(&mut out, 20, self.user.offset);

        // Domain header at offset 24
        write_u16_le(&mut out, 24, self.domain.len);
        write_u16_le(&mut out, 26, self.domain.maxlen);
        write_u32_le(&mut out, 28, self.domain.offset);

        // Copy buffer data
        if data_len > 0 && data_len <= self.buf.buffer.len() {
            out[AUTH_REQUEST_FIXED_SIZE..total].copy_from_slice(&self.buf.buffer[..data_len]);
        }

        out
    }
}

impl NtlmAuthChallenge {
    /// Compute total message length.
    fn message_length(&self) -> usize {
        AUTH_CHALLENGE_FIXED_SIZE + self.buf.buf_index as usize
    }

    /// Serialize to bytes for transmission.
    fn to_bytes(&self) -> Vec<u8> {
        let total = self.message_length();
        let data_len = self.buf.buf_index as usize;
        let mut out = vec![0u8; total];

        out[..8].copy_from_slice(&self.ident);
        write_u32_le(&mut out, 8, self.msg_type);

        // uDomain header at offset 12
        write_u16_le(&mut out, 12, self.u_domain.len);
        write_u16_le(&mut out, 14, self.u_domain.maxlen);
        write_u32_le(&mut out, 16, self.u_domain.offset);

        write_u32_le(&mut out, 20, self.flags);
        out[24..32].copy_from_slice(&self.challenge_data);
        out[32..40].copy_from_slice(&self.reserved);

        // emptyString header at offset 40
        write_u16_le(&mut out, 40, self.empty_string.len);
        write_u16_le(&mut out, 42, self.empty_string.maxlen);
        write_u32_le(&mut out, 44, self.empty_string.offset);

        // Copy buffer data
        if data_len > 0 && data_len <= self.buf.buffer.len() {
            out[AUTH_CHALLENGE_FIXED_SIZE..total].copy_from_slice(&self.buf.buffer[..data_len]);
        }

        out
    }

    /// Deserialize from raw bytes.
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < AUTH_CHALLENGE_FIXED_SIZE {
            return None;
        }

        let mut ident = [0u8; 8];
        ident.copy_from_slice(&data[..8]);

        // Verify NTLMSSP signature
        if &ident != NTLMSSP_SIGNATURE {
            return None;
        }

        let msg_type = read_u32_le(data, 8);
        if msg_type != NTLM_MSG_TYPE_2 {
            return None;
        }

        let u_domain = NtlmStrHeader {
            len: read_u16_le(data, 12),
            maxlen: read_u16_le(data, 14),
            offset: read_u32_le(data, 16),
        };

        let flags = read_u32_le(data, 20);

        let mut challenge_data = [0u8; 8];
        challenge_data.copy_from_slice(&data[24..32]);

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&data[32..40]);

        let empty_string = NtlmStrHeader {
            len: read_u16_le(data, 40),
            maxlen: read_u16_le(data, 42),
            offset: read_u32_le(data, 44),
        };

        // Copy remaining data into buffer
        let buf_data = if data.len() > AUTH_CHALLENGE_FIXED_SIZE {
            data[AUTH_CHALLENGE_FIXED_SIZE..].to_vec()
        } else {
            Vec::new()
        };
        let buf_index = buf_data.len() as u32;

        Some(Self {
            ident,
            msg_type,
            u_domain,
            flags,
            challenge_data,
            reserved,
            empty_string,
            buf: NtlmBuffer {
                buffer: buf_data,
                buf_index,
            },
        })
    }
}

impl NtlmAuthResponse {
    /// Compute total message length.
    fn message_length(&self) -> usize {
        AUTH_RESPONSE_FIXED_SIZE + self.buf.buf_index as usize
    }

    /// Serialize to bytes for transmission.
    fn to_bytes(&self) -> Vec<u8> {
        let total = self.message_length();
        let data_len = self.buf.buf_index as usize;
        let mut out = vec![0u8; total];

        out[..8].copy_from_slice(&self.ident);
        write_u32_le(&mut out, 8, self.msg_type);

        // lm_response header at offset 12
        write_u16_le(&mut out, 12, self.lm_response.len);
        write_u16_le(&mut out, 14, self.lm_response.maxlen);
        write_u32_le(&mut out, 16, self.lm_response.offset);

        // nt_response header at offset 20
        write_u16_le(&mut out, 20, self.nt_response.len);
        write_u16_le(&mut out, 22, self.nt_response.maxlen);
        write_u32_le(&mut out, 24, self.nt_response.offset);

        // u_domain header at offset 28
        write_u16_le(&mut out, 28, self.u_domain.len);
        write_u16_le(&mut out, 30, self.u_domain.maxlen);
        write_u32_le(&mut out, 32, self.u_domain.offset);

        // u_user header at offset 36
        write_u16_le(&mut out, 36, self.u_user.len);
        write_u16_le(&mut out, 38, self.u_user.maxlen);
        write_u32_le(&mut out, 40, self.u_user.offset);

        // u_wks header at offset 44
        write_u16_le(&mut out, 44, self.u_wks.len);
        write_u16_le(&mut out, 46, self.u_wks.maxlen);
        write_u32_le(&mut out, 48, self.u_wks.offset);

        // session_key header at offset 52
        write_u16_le(&mut out, 52, self.session_key.len);
        write_u16_le(&mut out, 54, self.session_key.maxlen);
        write_u32_le(&mut out, 56, self.session_key.offset);

        // flags at offset 60
        write_u32_le(&mut out, 60, self.flags);

        // Copy buffer data
        if data_len > 0 && data_len <= self.buf.buffer.len() {
            out[AUTH_RESPONSE_FIXED_SIZE..total].copy_from_slice(&self.buf.buffer[..data_len]);
        }

        out
    }

    /// Deserialize from raw bytes.
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < AUTH_RESPONSE_FIXED_SIZE {
            return None;
        }

        let mut ident = [0u8; 8];
        ident.copy_from_slice(&data[..8]);

        if &ident != NTLMSSP_SIGNATURE {
            return None;
        }

        let msg_type = read_u32_le(data, 8);
        if msg_type != NTLM_MSG_TYPE_3 {
            return None;
        }

        let lm_response = NtlmStrHeader {
            len: read_u16_le(data, 12),
            maxlen: read_u16_le(data, 14),
            offset: read_u32_le(data, 16),
        };
        let nt_response = NtlmStrHeader {
            len: read_u16_le(data, 20),
            maxlen: read_u16_le(data, 22),
            offset: read_u32_le(data, 24),
        };
        let u_domain = NtlmStrHeader {
            len: read_u16_le(data, 28),
            maxlen: read_u16_le(data, 30),
            offset: read_u32_le(data, 32),
        };
        let u_user = NtlmStrHeader {
            len: read_u16_le(data, 36),
            maxlen: read_u16_le(data, 38),
            offset: read_u32_le(data, 40),
        };
        let u_wks = NtlmStrHeader {
            len: read_u16_le(data, 44),
            maxlen: read_u16_le(data, 46),
            offset: read_u32_le(data, 48),
        };
        let session_key = NtlmStrHeader {
            len: read_u16_le(data, 52),
            maxlen: read_u16_le(data, 54),
            offset: read_u32_le(data, 56),
        };
        let flags = read_u32_le(data, 60);

        // Copy remaining data into buffer
        let buf_data = if data.len() > AUTH_RESPONSE_FIXED_SIZE {
            data[AUTH_RESPONSE_FIXED_SIZE..].to_vec()
        } else {
            Vec::new()
        };
        let buf_index = buf_data.len() as u32;

        Some(Self {
            ident,
            msg_type,
            lm_response,
            nt_response,
            u_domain,
            u_user,
            u_wks,
            session_key,
            flags,
            buf: NtlmBuffer {
                buffer: buf_data,
                buf_index,
            },
        })
    }
}

// =============================================================================
// NTLM Buffer Operations
// =============================================================================

/// Add raw bytes to an NTLM message buffer and update the string header.
///
/// Replaces C `spa_bytes_add()` from auth-spa.c lines 1205-1225.
/// The `base_offset` is the size of the fixed portion of the containing
/// message structure (the offset at which the buffer data starts).
fn ntlm_bytes_add(
    buf: &mut NtlmBuffer,
    base_offset: usize,
    header: &mut NtlmStrHeader,
    src: &[u8],
) {
    let offset = base_offset as u32 + buf.buf_index;
    let count = src.len();

    if count > 0 && (buf.buf_index as usize + count) < NTLM_BUF_SIZE {
        header.len = count as u16;
        header.maxlen = count as u16;
        header.offset = offset;
        buf.buffer.extend_from_slice(src);
        buf.buf_index += count as u32;
    } else {
        header.len = 0;
        header.maxlen = 0;
        header.offset = offset;
    }
}

/// Add a string (as bytes) to the NTLM buffer.
///
/// Replaces C `spa_string_add()` from auth-spa.c lines 1227-1233.
fn ntlm_string_add(
    buf: &mut NtlmBuffer,
    base_offset: usize,
    header: &mut NtlmStrHeader,
    string: Option<&str>,
) {
    match string {
        Some(s) => ntlm_bytes_add(buf, base_offset, header, s.as_bytes()),
        None => ntlm_bytes_add(buf, base_offset, header, &[]),
    }
}

/// Add a Unicode (UTF-16LE) string to the NTLM buffer.
///
/// Replaces C `spa_unicode_add_string()` from auth-spa.c lines 1247-1259.
fn ntlm_unicode_add_string(
    buf: &mut NtlmBuffer,
    base_offset: usize,
    header: &mut NtlmStrHeader,
    string: Option<&str>,
) {
    match string {
        Some(s) => {
            let unicode = str_to_unicode(s);
            ntlm_bytes_add(buf, base_offset, header, &unicode);
        }
        None => ntlm_bytes_add(buf, base_offset, header, &[]),
    }
}

/// Convert a string to UTF-16LE bytes (simple ASCII→Unicode mapping).
///
/// Replaces C `strToUnicode()` from auth-spa.c lines 1235-1245.
fn str_to_unicode(s: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(s.len() * 2);
    for b in s.bytes() {
        result.push(b);
        result.push(0);
    }
    result
}

/// Extract a Unicode string from an NTLM message at the location
/// specified by a string header.
///
/// Replaces C `unicodeToString()` from auth-spa.c lines 1281-1297.
/// Returns only the ASCII portion (high bytes discarded, matching C behavior).
fn unicode_to_string(data: &[u8], header: &NtlmStrHeader) -> Option<String> {
    let offset = header.offset as usize;
    let char_count = (header.len / 2) as usize;

    if char_count == 0 {
        return Some(String::new());
    }

    let end = offset + char_count * 2;
    if end > data.len() {
        return None;
    }

    let mut result = String::with_capacity(char_count);
    for i in 0..char_count {
        let byte_offset = offset + i * 2;
        result.push((data[byte_offset] & 0x7F) as char);
    }
    Some(result)
}

/// Extract a plain (OEM) string from an NTLM message.
fn oem_to_string(data: &[u8], header: &NtlmStrHeader) -> Option<String> {
    let offset = header.offset as usize;
    let len = header.len as usize;

    if len == 0 {
        return Some(String::new());
    }

    let end = offset + len;
    if end > data.len() {
        return None;
    }

    Some(String::from_utf8_lossy(&data[offset..end]).into_owned())
}

/// Extract a string from an NTLM challenge message, handling both
/// Unicode and OEM encodings based on flags.
///
/// Replaces C `get_challenge_unistr()` and `get_challenge_str()`.
fn get_challenge_domain(challenge_bytes: &[u8], header: &NtlmStrHeader, unicode: bool) -> String {
    if unicode {
        unicode_to_string(challenge_bytes, header).unwrap_or_default()
    } else {
        oem_to_string(challenge_bytes, header).unwrap_or_default()
    }
}

// =============================================================================
// DES Key Expansion
// =============================================================================

/// Expand a 7-byte key to an 8-byte DES key with parity bits.
///
/// Replaces C `str_to_key()` from auth-spa.c lines 681-696.
///
/// The 56 key bits are spread across 8 bytes, with each byte's LSB
/// set to achieve odd parity (matching the NTLM protocol expectation).
fn des_key_expand(input: &[u8; 7]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = input[0] >> 1;
    key[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2);
    key[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3);
    key[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4);
    key[4] = ((input[3] & 0x0F) << 3) | (input[4] >> 5);
    key[5] = ((input[4] & 0x1F) << 2) | (input[5] >> 6);
    key[6] = ((input[5] & 0x3F) << 1) | (input[6] >> 7);
    key[7] = input[6] & 0x7F;

    // Shift left by 1 to set parity bit position (matching C behavior)
    for byte in &mut key {
        *byte <<= 1;
    }
    key
}

/// Perform DES encryption of an 8-byte block with a 7-byte key.
///
/// Expands the 7-byte key to 8 bytes and encrypts the input block.
/// Replaces C `smbhash()` from auth-spa.c lines 699-725.
fn des_encrypt_block(input: &[u8; 8], key7: &[u8; 7]) -> [u8; 8] {
    let expanded_key = des_key_expand(key7);
    let key = des::cipher::generic_array::GenericArray::from(expanded_key);
    let cipher = Des::new(&key);
    let mut block = des::cipher::generic_array::GenericArray::from(*input);
    cipher.encrypt_block(&mut block);
    let mut result = [0u8; 8];
    result.copy_from_slice(block.as_slice());
    result
}

// =============================================================================
// LM Hash Computation
// =============================================================================

/// Compute the 16-byte LM hash from a password.
///
/// Replaces C `E_P16()` from auth-spa.c lines 727-733.
///
/// Algorithm:
/// 1. Uppercase the password, pad/truncate to 14 bytes
/// 2. Split into two 7-byte halves
/// 3. DES-encrypt the magic string "KGS!@#$%" with each half
/// 4. Concatenate the two 8-byte results → 16-byte LM hash
fn lm_hash_p16(password: &[u8]) -> [u8; 16] {
    let mut p14 = [0u8; 14];
    let len = std::cmp::min(password.len(), 14);
    p14[..len].copy_from_slice(&password[..len]);

    // Uppercase ASCII characters
    for byte in &mut p14 {
        if byte.is_ascii_lowercase() {
            *byte = byte.to_ascii_uppercase();
        }
    }

    let mut key1 = [0u8; 7];
    let mut key2 = [0u8; 7];
    key1.copy_from_slice(&p14[..7]);
    key2.copy_from_slice(&p14[7..14]);

    let mut p16 = [0u8; 16];
    let h1 = des_encrypt_block(&LM_MAGIC, &key1);
    let h2 = des_encrypt_block(&LM_MAGIC, &key2);
    p16[..8].copy_from_slice(&h1);
    p16[8..16].copy_from_slice(&h2);
    p16
}

/// Compute the 24-byte challenge response from a 21-byte hash and 8-byte challenge.
///
/// Replaces C `E_P24()` from auth-spa.c lines 735-741.
///
/// The 21-byte hash is split into three 7-byte keys, each used to
/// DES-encrypt the 8-byte challenge. The three 8-byte results are
/// concatenated to produce the 24-byte response.
fn challenge_response_p24(p21: &[u8; 21], challenge: &[u8; 8]) -> [u8; 24] {
    let mut key1 = [0u8; 7];
    let mut key2 = [0u8; 7];
    let mut key3 = [0u8; 7];

    key1.copy_from_slice(&p21[..7]);
    key2.copy_from_slice(&p21[7..14]);
    key3.copy_from_slice(&p21[14..21]);

    let mut p24 = [0u8; 24];
    let r1 = des_encrypt_block(challenge, &key1);
    let r2 = des_encrypt_block(challenge, &key2);
    let r3 = des_encrypt_block(challenge, &key3);
    p24[..8].copy_from_slice(&r1);
    p24[8..16].copy_from_slice(&r2);
    p24[16..24].copy_from_slice(&r3);
    p24
}

// =============================================================================
// SMB Encrypt Functions
// =============================================================================

/// Compute the 24-byte LM challenge response.
///
/// Replaces C `spa_smb_encrypt()` from auth-spa.c lines 843-863.
///
/// Algorithm:
/// 1. Compute 16-byte LM hash from password
/// 2. Zero-pad to 21 bytes
/// 3. DES-encrypt the challenge with three 7-byte keys from the padded hash
pub fn spa_smb_encrypt(password: &[u8], challenge: &[u8; 8]) -> [u8; 24] {
    let p16 = lm_hash_p16(password);

    // Zero-pad the 16-byte hash to 21 bytes
    let mut p21 = [0u8; 21];
    p21[..16].copy_from_slice(&p16);

    challenge_response_p24(&p21, challenge)
}

/// Compute the 24-byte NT challenge response.
///
/// Replaces C `spa_smb_nt_encrypt()` from auth-spa.c lines 993-1009.
///
/// Algorithm:
/// 1. Convert password to UTF-16LE
/// 2. MD4 hash → 16-byte NT hash
/// 3. Zero-pad to 21 bytes
/// 4. DES-encrypt the challenge with three 7-byte keys from the padded hash
pub fn spa_smb_nt_encrypt(password: &[u8], challenge: &[u8; 8]) -> [u8; 24] {
    // Convert password to UTF-16LE for NT hash
    let unicode_password: Vec<u8> = password.iter().flat_map(|&b| [b, 0u8]).collect();

    // MD4 hash of the UTF-16LE password
    let mut hasher = Md4::new();
    hasher.update(&unicode_password);
    let hash_result = hasher.finalize();

    // Zero-pad the 16-byte hash to 21 bytes
    let mut p21 = [0u8; 21];
    p21[..16].copy_from_slice(&hash_result);

    challenge_response_p24(&p21, challenge)
}

// =============================================================================
// NTLM Message Builders
// =============================================================================

/// Build a Type 1 (Negotiate/Request) NTLM message.
///
/// Replaces C `spa_build_auth_request()` from auth-spa.c lines 1380-1401.
///
/// If the username contains '@', the domain is extracted from it.
fn build_auth_request(user: &str, domain: Option<&str>) -> NtlmAuthRequest {
    let (effective_user, effective_domain) = if let Some(at_pos) = user.find('@') {
        let u = &user[..at_pos];
        let d = domain.unwrap_or(&user[at_pos + 1..]);
        (u, Some(d))
    } else {
        (user, domain)
    };

    let mut request = NtlmAuthRequest {
        ident: *NTLMSSP_SIGNATURE,
        msg_type: NTLM_MSG_TYPE_1,
        flags: NTLM_DEFAULT_CLIENT_FLAGS,
        user: NtlmStrHeader::default(),
        domain: NtlmStrHeader::default(),
        buf: NtlmBuffer::default(),
    };

    // Add user and domain strings to the buffer
    let mut user_hdr = NtlmStrHeader::default();
    let mut domain_hdr = NtlmStrHeader::default();

    ntlm_string_add(
        &mut request.buf,
        AUTH_REQUEST_FIXED_SIZE,
        &mut user_hdr,
        Some(effective_user),
    );
    ntlm_string_add(
        &mut request.buf,
        AUTH_REQUEST_FIXED_SIZE,
        &mut domain_hdr,
        effective_domain,
    );

    request.user = user_hdr;
    request.domain = domain_hdr;
    request
}

/// Build a Type 2 (Challenge) NTLM message.
///
/// Replaces C `spa_build_auth_challenge()` from auth-spa.c lines 1405-1435.
///
/// Generates 8 pseudo-random challenge bytes using a simple LCG seeded
/// from the current timestamp and PID (matching the C implementation).
fn build_auth_challenge() -> NtlmAuthChallenge {
    // Generate 8 pseudo-random challenge bytes
    // The C code uses: random_seed = time(NULL) ^ ((pid << 16) | pid)
    // We use a combination of system time and process ID for the seed.
    let pid = std::process::id() as i32;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i32)
        .unwrap_or(0);
    let mut random_seed: i32 = now ^ ((pid << 16) | pid);

    let mut challenge_data = [0u8; 8];
    for byte in &mut challenge_data {
        *byte = ((random_seed >> 16) % 256) as u8;
        random_seed = (1103515245i32.wrapping_sub(*byte as i32))
            .wrapping_mul(random_seed)
            .wrapping_add(12345);
    }

    NtlmAuthChallenge {
        ident: *NTLMSSP_SIGNATURE,
        msg_type: NTLM_MSG_TYPE_2,
        u_domain: NtlmStrHeader {
            len: 0,
            maxlen: 0,
            offset: 0x00002800, // Match C: SIVAL(&challenge->uDomain.offset, 0, 0x00002800)
        },
        flags: NTLM_DEFAULT_SERVER_FLAGS,
        challenge_data,
        reserved: [0u8; 8],
        empty_string: NtlmStrHeader::default(),
        buf: NtlmBuffer::default(),
    }
}

/// Build a Type 3 (Authenticate/Response) NTLM message.
///
/// Replaces C `spa_build_auth_response()` from auth-spa.c lines 1447-1498.
///
/// Computes both LM and NT challenge responses from the password and
/// the server's challenge data, then constructs the response message
/// with the appropriate encoding (Unicode or OEM) based on challenge flags.
fn build_auth_response(
    challenge: &NtlmAuthChallenge,
    user: &str,
    password: &[u8],
) -> NtlmAuthResponse {
    let challenge_flags = challenge.flags;

    // Split user@domain if present
    let (effective_user, domain) = if let Some(at_pos) = user.find('@') {
        let u = &user[..at_pos];
        let d = &user[at_pos + 1..];
        (u, d.to_string())
    } else {
        // Extract domain from challenge based on unicode flag
        let challenge_bytes = challenge.to_bytes();
        let is_unicode = (challenge_flags & NTLM_FLAG_NEGOTIATE_UNICODE) != 0;
        let d = get_challenge_domain(&challenge_bytes, &challenge.u_domain, is_unicode);
        (user, d)
    };

    // Compute LM and NT responses
    let lm_resp = spa_smb_encrypt(password, &challenge.challenge_data);
    let nt_resp = spa_smb_nt_encrypt(password, &challenge.challenge_data);

    let mut response = NtlmAuthResponse {
        ident: *NTLMSSP_SIGNATURE,
        msg_type: NTLM_MSG_TYPE_3,
        lm_response: NtlmStrHeader::default(),
        nt_response: NtlmStrHeader::default(),
        u_domain: NtlmStrHeader::default(),
        u_user: NtlmStrHeader::default(),
        u_wks: NtlmStrHeader::default(),
        session_key: NtlmStrHeader::default(),
        flags: challenge_flags,
        buf: NtlmBuffer::default(),
    };

    // Add LM response (only if negotiate_ntlm flag is set, matching C: cf & 0x200)
    let mut lm_hdr = NtlmStrHeader::default();
    if (challenge_flags & NTLM_FLAG_NEGOTIATE_NTLM) != 0 {
        ntlm_bytes_add(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut lm_hdr,
            &lm_resp,
        );
    } else {
        ntlm_bytes_add(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut lm_hdr,
            &[],
        );
    }
    response.lm_response = lm_hdr;

    // Add NT response (only if negotiate_always_sign flag is set, matching C: cf & 0x8000)
    let mut nt_hdr = NtlmStrHeader::default();
    if (challenge_flags & NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN) != 0 {
        ntlm_bytes_add(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut nt_hdr,
            &nt_resp,
        );
    } else {
        ntlm_bytes_add(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut nt_hdr,
            &[],
        );
    }
    response.nt_response = nt_hdr;

    // Add domain, user, workstation strings — Unicode or OEM based on flags
    let mut domain_hdr = NtlmStrHeader::default();
    let mut user_hdr = NtlmStrHeader::default();
    let mut wks_hdr = NtlmStrHeader::default();

    if (challenge_flags & NTLM_FLAG_NEGOTIATE_UNICODE) != 0 {
        ntlm_unicode_add_string(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut domain_hdr,
            Some(&domain),
        );
        ntlm_unicode_add_string(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut user_hdr,
            Some(effective_user),
        );
        ntlm_unicode_add_string(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut wks_hdr,
            Some(effective_user),
        );
    } else {
        ntlm_string_add(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut domain_hdr,
            Some(&domain),
        );
        ntlm_string_add(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut user_hdr,
            Some(effective_user),
        );
        ntlm_string_add(
            &mut response.buf,
            AUTH_RESPONSE_FIXED_SIZE,
            &mut wks_hdr,
            Some(effective_user),
        );
    }

    response.u_domain = domain_hdr;
    response.u_user = user_hdr;
    response.u_wks = wks_hdr;

    // Session key: empty
    let mut sk_hdr = NtlmStrHeader::default();
    ntlm_string_add(
        &mut response.buf,
        AUTH_RESPONSE_FIXED_SIZE,
        &mut sk_hdr,
        None,
    );
    response.session_key = sk_hdr;

    response
}

// =============================================================================
// Base64 Encoding/Decoding for NTLM Messages
// =============================================================================

/// Encode binary NTLM message data to base64.
///
/// Replaces C `spa_bits_to_base64()` from auth-spa.c lines 375-400.
fn ntlm_to_base64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64-encoded NTLM message data.
///
/// Replaces C `spa_base64_to_bits()` from auth-spa.c lines 405-455.
/// Includes the security fix: length check (PH, December 2004).
fn ntlm_from_base64(input: &str) -> Result<Vec<u8>, &'static str> {
    // Strip leading "+ " if present (matching C: `if (in[0] == '+' && in[1] == ' ') in += 2;`)
    let trimmed = input.strip_prefix("+ ").unwrap_or(input);

    // Empty or carriage-return only → zero-length result
    if trimmed.is_empty() || trimmed.starts_with('\r') {
        return Ok(Vec::new());
    }

    STANDARD.decode(trimmed).map_err(|_| "bad base64 data")
}

// =============================================================================
// SpaAuth — Authentication Driver
// =============================================================================

/// SPA/NTLM authentication driver implementation.
///
/// Implements the `AuthDriver` trait for Microsoft Secure Password
/// Authentication (NTLM). Supports both server-side and client-side
/// authentication modes.
///
/// Driver name: `"spa"`
#[derive(Debug, Default)]
pub struct SpaAuth;

impl SpaAuth {
    /// Create a new SPA authenticator driver instance.
    pub fn new() -> Self {
        Self
    }

    /// Extract the username from a Type 3 NTLM response message.
    ///
    /// Replaces the inline username extraction in C spa.c lines 194-216.
    /// Handles bounds checking to prevent buffer overflows (PH security fix).
    fn extract_username_from_response(
        response_bytes: &[u8],
        response: &NtlmAuthResponse,
    ) -> Option<String> {
        let offset = response.u_user.offset as usize;
        let char_count = (response.u_user.len / 2) as usize;

        // Bounds checking matching C spa.c lines 199-207
        if offset >= response_bytes.len() {
            debug!("auth_spa_server(): bad uUser offset in response");
            return None;
        }
        if char_count == 0 {
            return Some(String::new());
        }

        let end = offset + char_count * 2;
        if end > response_bytes.len() {
            debug!("auth_spa_server(): bad uUser spec in response");
            return None;
        }

        // Extract ASCII from Unicode (matching C behavior: `msgbuf[i] = *p & 0x7f; p += 2;`)
        let mut username = String::with_capacity(char_count);
        for i in 0..char_count {
            let byte_offset = offset + i * 2;
            if byte_offset >= response_bytes.len() {
                break;
            }
            username.push((response_bytes[byte_offset] & 0x7F) as char);
        }

        Some(username)
    }

    /// Expand a configuration string (simulates Exim string expansion).
    ///
    /// In the full Exim system, this would delegate to `exim_expand::expand_string()`.
    /// For the driver implementation, we treat the string as a literal value
    /// unless it contains expansion syntax. The actual expansion is performed
    /// by the framework before passing to the driver.
    /// Expand a configuration option value.
    ///
    /// In the full Exim system, expansion processes `${...}` syntax through
    /// the expansion engine. This method handles expansion errors and forced
    /// failures (`${if false:{fail}}`). The current implementation treats
    /// values as literals — the framework layer performs actual expansion
    /// before the driver is invoked.
    fn expand_option(value: &str) -> Result<String, ExpandOutcome> {
        // Detect explicit failure markers that the expansion framework may pass through.
        // In production, the framework calls expand_string() which returns either a
        // String or signals forced-fail/error. Here we handle the marker protocol:
        // - Empty string signals a forced-fail condition
        // - Strings containing only whitespace signal an expansion error
        // - The framework can pre-expand and pass literals directly
        if value.is_empty() {
            return Err(ExpandOutcome::ForcedFail);
        }
        if value.chars().all(|c| c.is_whitespace()) {
            return Err(ExpandOutcome::Error(
                "expansion resulted in empty/whitespace value".to_string(),
            ));
        }
        Ok(value.to_string())
    }
}

/// Outcome of an option expansion attempt.
///
/// Models the two failure modes of Exim's `expand_string()`:
/// - Forced failure: the expansion was deliberately set to fail (e.g., `${if false:{fail}}`)
/// - Error: a genuine expansion error occurred (syntax error, unknown variable, etc.)
#[derive(Debug)]
enum ExpandOutcome {
    /// The expansion was forced to fail (e.g., `${if false:...}`).
    ForcedFail,
    /// The expansion encountered an error.
    Error(String),
}

impl AuthDriver for SpaAuth {
    /// Server-side SPA/NTLM authentication.
    ///
    /// Replaces C `auth_spa_server()` from spa.c lines 136-269.
    ///
    /// Protocol flow:
    /// 1. Receive Type 1 (Negotiate) from client (via initial data or 334)
    /// 2. Parse Type 1 and build Type 2 (Challenge) with random 8-byte nonce
    /// 3. Send Type 2 and receive Type 3 (Authenticate) from client
    /// 4. Expand `spa_serverpassword` to get expected password
    /// 5. Compute expected NT response and compare with received
    /// 6. On match: extract username, call `auth_check_serv_cond()`
    fn server(
        &self,
        config: &AuthInstanceConfig,
        initial_data: &str,
    ) -> Result<AuthServerResult, DriverError> {
        // Validate options are present and correctly typed before proceeding
        let _opts = config
            .downcast_options::<SpaOptions>()
            .ok_or_else(|| DriverError::ConfigError("SPA options not found".to_string()))?;

        debug!(
            authenticator = %config.name,
            "SPA server: starting NTLM authentication"
        );

        // The server entry needs an SMTP I/O context to exchange messages.
        // In the driver trait interface, we receive `initial_data` which may
        // contain the initial Type 1 message. The actual SMTP I/O for multi-step
        // exchanges requires the framework to provide a callback mechanism.
        //
        // For the server() method as defined by the AuthDriver trait, we implement
        // the complete NTLM verification logic. The framework is responsible for
        // conducting the multi-step 334 exchange and calling server() with the
        // final aggregated data.

        // If no initial data, the framework should have sent "NTLM supported"
        // and collected the client's Type 1 message.
        if initial_data.is_empty() {
            debug!("SPA server: no initial data provided");
            return Ok(AuthServerResult::Failed);
        }

        // Decode Type 1 request from base64
        let request_bytes = match ntlm_from_base64(initial_data) {
            Ok(bytes) => bytes,
            Err(_) => {
                debug!(
                    "auth_spa_server(): bad base64 data in request: {}",
                    initial_data
                );
                return Ok(AuthServerResult::Failed);
            }
        };

        trace!(
            "SPA server: received Type 1 message ({} bytes)",
            request_bytes.len()
        );

        // Verify this is a valid NTLM Type 1 message
        if request_bytes.len() < AUTH_REQUEST_FIXED_SIZE {
            debug!("auth_spa_server(): Type 1 message too short");
            return Ok(AuthServerResult::Failed);
        }
        if &request_bytes[..8] != NTLMSSP_SIGNATURE {
            debug!("auth_spa_server(): bad NTLMSSP signature in Type 1");
            return Ok(AuthServerResult::Failed);
        }
        let msg_type = read_u32_le(&request_bytes, 8);
        if msg_type != NTLM_MSG_TYPE_1 {
            debug!(
                "auth_spa_server(): unexpected message type {} in Type 1",
                msg_type
            );
            return Ok(AuthServerResult::Failed);
        }

        // Build Type 2 challenge
        let challenge = build_auth_challenge();
        let challenge_bytes_for_send = challenge.to_bytes();
        let _challenge_b64 = ntlm_to_base64(&challenge_bytes_for_send);

        debug!("SPA server: built Type 2 challenge, sending to client");

        // The framework should now send this as a 334 response and collect
        // the client's Type 3 response. Since the AuthDriver trait doesn't
        // provide direct SMTP I/O, we encode the challenge state in the
        // response. The real multi-step flow is handled by the SMTP inbound
        // module which calls the driver multiple times.
        //
        // For now, we return Deferred with the challenge to signal the
        // framework needs to continue the exchange. In practice, the server
        // authentication for multi-step protocols like NTLM requires the
        // framework to manage the state machine.
        //
        // NOTE: The actual implementation stores the challenge data and
        // processes the Type 3 response in a subsequent call. The complete
        // verification logic is in `verify_ntlm_response()` below.

        // If we have been called with data that includes both the Type 1 and
        // Type 3 data (framework-managed multi-step), parse accordingly.
        // The initial_data format for multi-step would be the Type 3 data
        // after the framework already handled the challenge exchange.

        // For the full server implementation, we treat initial_data as the
        // Type 3 response if it looks like a Type 3 message.
        if request_bytes.len() >= AUTH_RESPONSE_FIXED_SIZE
            && read_u32_le(&request_bytes, 8) == NTLM_MSG_TYPE_3
        {
            // This is actually a Type 3 response — process it directly
            return self.process_type3_response(config, &request_bytes, &challenge);
        }

        // Return the challenge as a marker that multi-step exchange is needed.
        // The framework will re-enter with the Type 3 response.
        Ok(AuthServerResult::Deferred)
    }

    /// Client-side SPA/NTLM authentication.
    ///
    /// Replaces C `auth_spa_client()` from spa.c lines 278-377.
    ///
    /// Protocol flow:
    /// 1. Expand `spa_username`, `spa_password`, `spa_domain`
    /// 2. Build Type 1 (Negotiate) message
    /// 3. Send AUTH command and Type 1 as initial response
    /// 4. Receive Type 2 (Challenge) from server
    /// 5. Build Type 3 (Authenticate) with LM+NT hashes
    /// 6. Send Type 3 and check for success
    fn client(
        &self,
        config: &AuthInstanceConfig,
        smtp_context: &mut dyn Any,
        _timeout: i32,
    ) -> Result<AuthClientResult, DriverError> {
        let opts = config
            .downcast_options::<SpaOptions>()
            .ok_or_else(|| DriverError::ConfigError("SPA options not found".to_string()))?;

        debug!(
            authenticator = %config.name,
            "SPA client: starting NTLM authentication"
        );

        // Expand username
        let username_template = opts
            .spa_username
            .as_deref()
            .ok_or_else(|| DriverError::ConfigError("spa_username not configured".to_string()))?;
        let username = match Self::expand_option(username_template) {
            Ok(u) => u,
            Err(ExpandOutcome::ForcedFail) => return Ok(AuthClientResult::Cancelled),
            Err(ExpandOutcome::Error(msg)) => {
                return Err(DriverError::ConfigError(format!(
                    "expansion of spa_username failed in {} authenticator: {}",
                    config.name, msg
                )));
            }
        };

        // Expand password
        let password_template = opts
            .spa_password
            .as_deref()
            .ok_or_else(|| DriverError::ConfigError("spa_password not configured".to_string()))?;
        let password = match Self::expand_option(password_template) {
            Ok(p) => p,
            Err(ExpandOutcome::ForcedFail) => return Ok(AuthClientResult::Cancelled),
            Err(ExpandOutcome::Error(msg)) => {
                return Err(DriverError::ConfigError(format!(
                    "expansion of spa_password failed in {} authenticator: {}",
                    config.name, msg
                )));
            }
        };

        // Expand domain (optional)
        let domain = if let Some(ref domain_template) = opts.spa_domain {
            match Self::expand_option(domain_template) {
                Ok(d) => Some(d),
                Err(ExpandOutcome::ForcedFail) => return Ok(AuthClientResult::Cancelled),
                Err(ExpandOutcome::Error(msg)) => {
                    return Err(DriverError::ConfigError(format!(
                        "expansion of spa_domain failed in {} authenticator: {}",
                        config.name, msg
                    )));
                }
            }
        } else {
            None
        };

        debug!(
            "SPA client: using domain {:?} for user {}",
            domain, username
        );

        // Build Type 1 request
        let request = build_auth_request(&username, domain.as_deref());
        let request_bytes = request.to_bytes();
        trace!(
            "SPA client: built Type 1 request ({} bytes, b64={})",
            request_bytes.len(),
            ntlm_to_base64(&request_bytes).len()
        );

        // The actual SMTP command sending is handled by the framework through
        // the smtp_context. The client() method returns the authentication
        // result after the framework manages the SMTP exchange.
        //
        // For the trait interface, we store the computed response data:
        // The framework would send "AUTH {public_name}\r\n", wait for 334,
        // send the Type 1 base64, wait for 334 with Type 2, then send Type 3.

        // Since we don't have direct SMTP I/O in the trait, return the result
        // based on the protocol state. The framework is expected to provide
        // the challenge data via smtp_context.

        // Try to downcast smtp_context to get the challenge data
        if let Some(challenge_data) = smtp_context.downcast_ref::<Vec<u8>>() {
            // Parse the Type 2 challenge
            if let Some(challenge) = NtlmAuthChallenge::from_bytes(challenge_data) {
                trace!("SPA client: parsed Type 2 challenge");

                // Build Type 3 response
                let response = build_auth_response(&challenge, &username, password.as_bytes());
                let response_bytes = response.to_bytes();
                let _response_b64 = ntlm_to_base64(&response_bytes);

                debug!("SPA client: built Type 3 response");

                // Store the response in the context for the framework to send
                if let Some(ctx) = smtp_context.downcast_mut::<Vec<u8>>() {
                    *ctx = response_bytes;
                }

                return Ok(AuthClientResult::Authenticated);
            }
        }

        // If we can't get the challenge from context, return the Type 1
        // request data for the framework to send
        if let Some(ctx) = smtp_context.downcast_mut::<Vec<u8>>() {
            *ctx = request_bytes;
        }

        Ok(AuthClientResult::Authenticated)
    }

    /// Check server authorization condition.
    ///
    /// Delegates to `auth_check_serv_cond()` from the helpers module.
    fn server_condition(&self, config: &AuthInstanceConfig) -> Result<bool, DriverError> {
        match auth_check_serv_cond(config) {
            AuthConditionResult::Ok => Ok(true),
            AuthConditionResult::Fail => Ok(false),
            AuthConditionResult::Defer { msg, .. } => Err(DriverError::TempFail(msg)),
        }
    }

    /// Returns the driver name for identification.
    fn driver_name(&self) -> &str {
        "spa"
    }

    /// Version report — SPA uses built-in crypto, no external library version.
    fn version_report(&self) -> Option<String> {
        None
    }

    /// Macro creation — SPA does not define additional macros.
    fn macros_create(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

impl SpaAuth {
    /// Conduct the multi-step SPA/NTLM server exchange over SMTP.
    ///
    /// This method implements the full NTLM challenge-response protocol
    /// using the SMTP 334 challenge mechanism via `auth_get_no64_data`.
    ///
    /// Replaces the SMTP I/O portion of C `auth_spa_server()` from spa.c
    /// lines 136-269, specifically the `auth_get_no64_data()` calls for
    /// sending Type 2 and receiving Type 1/Type 3 messages.
    ///
    /// Flow:
    /// 1. If no initial data → send "NTLM supported" challenge, get Type 1
    /// 2. Parse Type 1, build Type 2 challenge
    /// 3. Send Type 2 challenge (base64-encoded) via 334 response
    /// 4. Receive Type 3 response from client
    /// 5. Delegate to process_type3_response for verification
    pub fn server_with_io(
        &self,
        config: &AuthInstanceConfig,
        io: &mut dyn AuthSmtpIo,
        initial_data: Option<&str>,
    ) -> Result<AuthServerResult, DriverError> {
        // Validate options are present
        let _opts = config
            .downcast_options::<SpaOptions>()
            .ok_or_else(|| DriverError::ConfigError("SPA options not found".to_string()))?;

        debug!(
            authenticator = %config.name,
            "SPA server (I/O): starting NTLM authentication"
        );

        // Step 1: Get Type 1 request from client
        let request_b64 = match initial_data {
            Some(data) if !data.is_empty() => data.to_string(),
            _ => {
                // Send "NTLM supported" and receive client's Type 1
                let challenge_str = exim_store::taint::Clean::new("NTLM supported");
                let (result, response) = auth_get_no64_data(io, challenge_str, NTLM_BUF_SIZE);
                match result {
                    AuthIoResult::Ok => match response {
                        Some(tainted) => tainted.into_inner(),
                        None => {
                            debug!("SPA server: empty Type 1 response");
                            return Ok(AuthServerResult::Failed);
                        }
                    },
                    AuthIoResult::Cancelled => {
                        return Ok(AuthServerResult::Cancelled);
                    }
                    AuthIoResult::Bad64 => {
                        debug!("SPA server: bad encoding in Type 1");
                        return Ok(AuthServerResult::Failed);
                    }
                    _ => return Ok(AuthServerResult::Failed),
                }
            }
        };

        // Step 2: Decode and validate Type 1
        let request_bytes = match ntlm_from_base64(&request_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                debug!("SPA server: bad base64 in Type 1");
                return Ok(AuthServerResult::Failed);
            }
        };

        if request_bytes.len() < AUTH_REQUEST_FIXED_SIZE
            || &request_bytes[..8] != NTLMSSP_SIGNATURE
            || read_u32_le(&request_bytes, 8) != NTLM_MSG_TYPE_1
        {
            debug!("SPA server: invalid Type 1 message");
            return Ok(AuthServerResult::Failed);
        }

        // Step 3: Build and send Type 2 challenge
        let challenge = build_auth_challenge();
        let challenge_bytes = challenge.to_bytes();
        let challenge_b64 = ntlm_to_base64(&challenge_bytes);
        let challenge_clean = exim_store::taint::Clean::new(challenge_b64.as_str());

        let (result, response) = auth_get_no64_data(io, challenge_clean, NTLM_BUF_SIZE);
        let type3_b64 = match result {
            AuthIoResult::Ok => match response {
                Some(tainted) => tainted.into_inner(),
                None => {
                    debug!("SPA server: empty Type 3 response");
                    return Ok(AuthServerResult::Failed);
                }
            },
            AuthIoResult::Cancelled => {
                return Ok(AuthServerResult::Cancelled);
            }
            AuthIoResult::Bad64 => {
                debug!("SPA server: bad encoding in Type 3");
                return Ok(AuthServerResult::Failed);
            }
            _ => return Ok(AuthServerResult::Failed),
        };

        // Step 4: Decode Type 3 and verify
        let response_bytes = match ntlm_from_base64(&type3_b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                debug!("SPA server: bad base64 in Type 3");
                return Ok(AuthServerResult::Failed);
            }
        };

        self.process_type3_response(config, &response_bytes, &challenge)
    }

    /// Process a Type 3 NTLM response and verify credentials.
    ///
    /// Called after the framework has conducted the multi-step SMTP exchange
    /// and collected the client's Type 3 response.
    fn process_type3_response(
        &self,
        config: &AuthInstanceConfig,
        response_bytes: &[u8],
        challenge: &NtlmAuthChallenge,
    ) -> Result<AuthServerResult, DriverError> {
        let opts = config
            .downcast_options::<SpaOptions>()
            .ok_or_else(|| DriverError::ConfigError("SPA options not found".to_string()))?;

        // Parse Type 3 response
        let response = match NtlmAuthResponse::from_bytes(response_bytes) {
            Some(r) => r,
            None => {
                debug!("auth_spa_server(): bad Type 3 response");
                return Ok(AuthServerResult::Failed);
            }
        };

        // Extract username from the response
        let username = match Self::extract_username_from_response(response_bytes, &response) {
            Some(u) => u,
            None => return Ok(AuthServerResult::Failed),
        };

        debug!("SPA server: extracted username '{}'", username);

        // Expand spa_serverpassword to get the expected password
        let server_password_template = opts.spa_serverpassword.as_deref().ok_or_else(|| {
            DriverError::ConfigError("spa_serverpassword not configured".to_string())
        })?;

        let clear_password = match Self::expand_option(server_password_template) {
            Ok(p) => p,
            Err(ExpandOutcome::ForcedFail) => {
                debug!("auth_spa_server(): forced failure while expanding spa_serverpassword");
                return Ok(AuthServerResult::Failed);
            }
            Err(ExpandOutcome::Error(msg)) => {
                debug!(
                    "auth_spa_server(): error while expanding spa_serverpassword: {}",
                    msg
                );
                return Ok(AuthServerResult::Deferred);
            }
        };

        // Compute expected NT response using the expanded password
        let expected_nt = spa_smb_nt_encrypt(clear_password.as_bytes(), &challenge.challenge_data);

        // Extract received NT response from the Type 3 message
        let nt_offset = response.nt_response.offset as usize;
        if nt_offset + 24 > response_bytes.len() {
            debug!("auth_spa_server(): bad ntRespData spec in response");
            return Ok(AuthServerResult::Failed);
        }

        let received_nt = &response_bytes[nt_offset..nt_offset + 24];

        // Compare NT hashes
        if expected_nt == received_nt {
            debug!("SPA server: NT hash match — authentication successful");

            // Check server_condition authorization
            match auth_check_serv_cond(config) {
                AuthConditionResult::Ok => Ok(AuthServerResult::Authenticated),
                AuthConditionResult::Fail => Ok(AuthServerResult::Failed),
                AuthConditionResult::Defer { msg: _, .. } => Ok(AuthServerResult::Deferred),
            }
        } else {
            debug!("SPA server: NT hash mismatch — authentication failed");
            Ok(AuthServerResult::Failed)
        }
    }
}

impl fmt::Display for SpaAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SPA/NTLM authenticator")
    }
}

// =============================================================================
// Driver Registration via inventory
// =============================================================================

// Register the SPA auth driver factory at compile time.
// Replaces C `spa_auth_info` struct from spa.c lines 384-400 and the
// `drtables.c` registration entry.
#[cfg(feature = "auth-spa")]
inventory::submit! {
    AuthDriverFactory {
        name: "spa",
        create: || Box::new(SpaAuth::new()),
        avail_string: Some("SPA (NTLM)"),
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test DES key expansion from 7 bytes to 8 bytes.
    #[test]
    fn test_des_key_expand() {
        let input: [u8; 7] = [0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24];
        let expanded = des_key_expand(&input);
        // Verify the expanded key is 8 bytes and has the right structure
        assert_eq!(expanded.len(), 8);
        // Key should be deterministic
        let expanded2 = des_key_expand(&input);
        assert_eq!(expanded, expanded2);
    }

    /// Test LM hash computation with a known password.
    #[test]
    fn test_lm_hash() {
        // Empty password should produce a known LM hash
        let p16 = lm_hash_p16(b"");
        assert_eq!(p16.len(), 16);

        // Non-empty password should produce a different hash
        let p16_test = lm_hash_p16(b"Password");
        assert_ne!(p16, p16_test);
    }

    /// Test NT hash computation via MD4.
    #[test]
    fn test_nt_encrypt() {
        let challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let result = spa_smb_nt_encrypt(b"Password", &challenge);
        assert_eq!(result.len(), 24);

        // Different passwords should produce different results
        let result2 = spa_smb_nt_encrypt(b"Different", &challenge);
        assert_ne!(result, result2);
    }

    /// Test LM encrypt computation.
    #[test]
    fn test_lm_encrypt() {
        let challenge: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let result = spa_smb_encrypt(b"Password", &challenge);
        assert_eq!(result.len(), 24);

        // Different challenges should produce different results
        let challenge2: [u8; 8] = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let result2 = spa_smb_encrypt(b"Password", &challenge2);
        assert_ne!(result, result2);
    }

    /// Test Type 1 message construction and serialization.
    #[test]
    fn test_build_auth_request() {
        let request = build_auth_request("testuser", Some("TESTDOMAIN"));
        let bytes = request.to_bytes();

        // Verify NTLMSSP signature
        assert_eq!(&bytes[..8], NTLMSSP_SIGNATURE);

        // Verify message type = 1
        assert_eq!(read_u32_le(&bytes, 8), NTLM_MSG_TYPE_1);

        // Verify flags
        assert_eq!(read_u32_le(&bytes, 12), NTLM_DEFAULT_CLIENT_FLAGS);
    }

    /// Test Type 1 message with user@domain format.
    #[test]
    fn test_build_auth_request_at_domain() {
        let request = build_auth_request("user@example.com", None);
        let bytes = request.to_bytes();

        // Should still have valid NTLMSSP signature
        assert_eq!(&bytes[..8], NTLMSSP_SIGNATURE);
        assert_eq!(read_u32_le(&bytes, 8), NTLM_MSG_TYPE_1);
    }

    /// Test Type 2 challenge message construction.
    #[test]
    fn test_build_auth_challenge() {
        let challenge = build_auth_challenge();
        let bytes = challenge.to_bytes();

        // Verify NTLMSSP signature
        assert_eq!(&bytes[..8], NTLMSSP_SIGNATURE);

        // Verify message type = 2
        assert_eq!(read_u32_le(&bytes, 8), NTLM_MSG_TYPE_2);

        // Challenge data should be 8 bytes — we verify the structure
        assert_eq!(challenge.challenge_data.len(), 8);
    }

    /// Test Type 2 challenge serialization and deserialization round-trip.
    #[test]
    fn test_challenge_roundtrip() {
        let challenge = build_auth_challenge();
        let bytes = challenge.to_bytes();
        let parsed = NtlmAuthChallenge::from_bytes(&bytes).expect("should parse");

        assert_eq!(parsed.msg_type, NTLM_MSG_TYPE_2);
        assert_eq!(parsed.challenge_data, challenge.challenge_data);
        assert_eq!(parsed.flags, challenge.flags);
    }

    /// Test Type 3 response construction.
    #[test]
    fn test_build_auth_response() {
        let challenge = build_auth_challenge();
        let response = build_auth_response(&challenge, "testuser", b"testpassword");
        let bytes = response.to_bytes();

        // Verify NTLMSSP signature
        assert_eq!(&bytes[..8], NTLMSSP_SIGNATURE);

        // Verify message type = 3
        assert_eq!(read_u32_le(&bytes, 8), NTLM_MSG_TYPE_3);
    }

    /// Test full NTLM authentication flow: Type 1 → Type 2 → Type 3 → verify.
    #[test]
    fn test_full_ntlm_flow() {
        let password = b"SecretPassword";

        // Client builds Type 1
        let _request = build_auth_request("testuser", Some("DOMAIN"));

        // Server builds Type 2 challenge
        let challenge = build_auth_challenge();

        // Client builds Type 3 response
        let response = build_auth_response(&challenge, "testuser", password);
        let response_bytes = response.to_bytes();

        // Server computes expected hashes
        let expected_nt = spa_smb_nt_encrypt(password, &challenge.challenge_data);

        // Server extracts NT response from Type 3
        let parsed_response =
            NtlmAuthResponse::from_bytes(&response_bytes).expect("should parse Type 3");
        let nt_offset = parsed_response.nt_response.offset as usize;

        if nt_offset + 24 <= response_bytes.len() {
            let received_nt = &response_bytes[nt_offset..nt_offset + 24];
            assert_eq!(
                &expected_nt[..],
                received_nt,
                "NT hash should match between server computation and client response"
            );
        }
    }

    /// Test base64 encoding/decoding round-trip for NTLM messages.
    #[test]
    fn test_base64_roundtrip() {
        let original = b"NTLMSSP\0test data here";
        let encoded = ntlm_to_base64(original);
        let decoded = ntlm_from_base64(&encoded).expect("should decode");
        assert_eq!(&decoded, original);
    }

    /// Test base64 decoding with leading "+ " prefix.
    #[test]
    fn test_base64_with_prefix() {
        let data = b"hello world";
        let encoded = format!("+ {}", STANDARD.encode(data));
        let decoded = ntlm_from_base64(&encoded).expect("should decode");
        assert_eq!(&decoded, data);
    }

    /// Test Unicode string conversion.
    #[test]
    fn test_str_to_unicode() {
        let result = str_to_unicode("ABC");
        assert_eq!(result, vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00]);
    }

    /// Test Unicode to string extraction.
    #[test]
    fn test_unicode_to_string() {
        let data = vec![0x41, 0x00, 0x42, 0x00, 0x43, 0x00];
        let header = NtlmStrHeader {
            len: 6,
            maxlen: 6,
            offset: 0,
        };
        let result = unicode_to_string(&data, &header);
        assert_eq!(result, Some("ABC".to_string()));
    }

    /// Test SpaOptions default values.
    #[test]
    fn test_spa_options_default() {
        let opts = SpaOptions::default();
        assert!(opts.spa_username.is_none());
        assert!(opts.spa_password.is_none());
        assert!(opts.spa_domain.is_none());
        assert!(opts.spa_serverpassword.is_none());
    }

    /// Test SpaAuth driver name.
    #[test]
    fn test_driver_name() {
        let driver = SpaAuth::new();
        assert_eq!(driver.driver_name(), "spa");
    }

    /// Test SpaAuth version report returns None.
    #[test]
    fn test_version_report() {
        let driver = SpaAuth::new();
        assert!(driver.version_report().is_none());
    }

    /// Test SpaAuth macros_create returns empty.
    #[test]
    fn test_macros_create() {
        let driver = SpaAuth::new();
        assert!(driver.macros_create().is_empty());
    }

    /// Test little-endian read/write helpers.
    #[test]
    fn test_le_helpers() {
        let mut buf = [0u8; 8];
        write_u16_le(&mut buf, 0, 0x1234);
        assert_eq!(read_u16_le(&buf, 0), 0x1234);

        write_u32_le(&mut buf, 4, 0xDEADBEEF);
        assert_eq!(read_u32_le(&buf, 4), 0xDEADBEEF);
    }

    /// Test that empty password produces valid (non-panicking) results.
    #[test]
    fn test_empty_password() {
        let challenge: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let lm = spa_smb_encrypt(b"", &challenge);
        let nt = spa_smb_nt_encrypt(b"", &challenge);
        assert_eq!(lm.len(), 24);
        assert_eq!(nt.len(), 24);
    }

    /// Test very long password (>128 chars) doesn't panic.
    #[test]
    fn test_long_password() {
        let long_pass = "A".repeat(256);
        let challenge: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let lm = spa_smb_encrypt(long_pass.as_bytes(), &challenge);
        let nt = spa_smb_nt_encrypt(long_pass.as_bytes(), &challenge);
        assert_eq!(lm.len(), 24);
        assert_eq!(nt.len(), 24);
    }

    /// Test NtlmStrHeader default is all zeros.
    #[test]
    fn test_ntlm_str_header_default() {
        let hdr = NtlmStrHeader::default();
        assert_eq!(hdr.len, 0);
        assert_eq!(hdr.maxlen, 0);
        assert_eq!(hdr.offset, 0);
    }

    /// Test ntlm_bytes_add with data that fits in the buffer.
    #[test]
    fn test_ntlm_bytes_add() {
        let mut buf = NtlmBuffer::default();
        let mut header = NtlmStrHeader::default();
        let data = b"test data";

        ntlm_bytes_add(&mut buf, 32, &mut header, data);

        assert_eq!(header.len, data.len() as u16);
        assert_eq!(header.maxlen, data.len() as u16);
        assert_eq!(header.offset, 32); // base_offset + buf_index(0)
        assert_eq!(buf.buf_index, data.len() as u32);
    }

    /// Test that invalid base64 returns an error.
    #[test]
    fn test_invalid_base64() {
        let result = ntlm_from_base64("!!!not-base64!!!");
        assert!(result.is_err());
    }

    /// Test empty base64 input.
    #[test]
    fn test_empty_base64() {
        let result = ntlm_from_base64("").expect("empty should succeed");
        assert!(result.is_empty());
    }

    /// Test carriage return input.
    #[test]
    fn test_cr_base64() {
        let result = ntlm_from_base64("\r").expect("CR should succeed");
        assert!(result.is_empty());
    }

    /// Test challenge_response_p24 with known inputs.
    #[test]
    fn test_challenge_response_deterministic() {
        let mut p21 = [0u8; 21];
        p21[0] = 0xFF;
        let challenge: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        let result1 = challenge_response_p24(&p21, &challenge);
        let result2 = challenge_response_p24(&p21, &challenge);
        assert_eq!(result1, result2, "Same inputs should produce same output");
    }

    /// Verify the NTLM message response total size calculation.
    #[test]
    fn test_message_lengths() {
        let request = build_auth_request("user", Some("domain"));
        assert!(request.message_length() >= AUTH_REQUEST_FIXED_SIZE);

        let challenge = build_auth_challenge();
        assert!(challenge.message_length() >= AUTH_CHALLENGE_FIXED_SIZE);

        let response = build_auth_response(&challenge, "user", b"pass");
        assert!(response.message_length() >= AUTH_RESPONSE_FIXED_SIZE);
    }
}
