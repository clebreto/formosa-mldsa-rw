//! What the Jasmin ML-DSA computes on a Cortex-M33, and what it costs.
//!
//! The assembly comes from formosa-mldsa's Cortex-M4 sources, compiled by jasminc for
//! Armv8-M (`-arch armv8m`). Every value here is a function of the seed, the message and
//! the signing randomness, so an independent implementation of FIPS 204 must produce the
//! same bytes. The expected digests were taken from the `fips204` crate on the host, with
//! the inputs pqm4-mldsa's test firmware used, so the two backends are checked against
//! the same numbers.
//!
//! It also reports what each operation costs: SysTick ticks and the deepest the stack
//! went. It goes through the crate's in-place functions (`keygen_into`, `sign_into`,
//! `verify_bytes`) on static buffers, so that the stack figure is what the Jasmin code
//! needed; the by-value API, which returns keys in 8 KB buffers, is measured once at the
//! end.

#![no_std]
#![no_main]

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m::peripheral::syst::SystClkSource;
use cortex_m::peripheral::SYST;
use cortex_m_rt::{entry, exception};
use defmt_rtt as _;
use formosa_ml_dsa::{MlDsa, MlDsa44, MlDsa65, MlDsaParams};
use panic_probe as _;

/// The inputs the host generator used.
const SEED: [u8; 32] = [7u8; 32];
const MESSAGE: [u8; 32] = [0x5au8; 32];
const RANDOMNESS: [u8; 32] = [0x17u8; 32];

/// What the `fips204` crate makes of them.
mod expected {
    pub mod mldsa44 {
        pub const PUBLIC_KEY: u64 = 0x3265_4028_9870_5365;
        pub const SECRET_KEY: u64 = 0x89cc_1668_bda5_8aed;
        pub const SIGNATURE: u64 = 0x16cf_6a5e_2719_8c18;
    }
    pub mod mldsa65 {
        pub const PUBLIC_KEY: u64 = 0x5eda_22b9_96d4_1cf2;
        pub const SECRET_KEY: u64 = 0xc383_cccc_4725_17e7;
        pub const SIGNATURE: u64 = 0x2ab4_e296_4ead_991b;
    }
}

// --- The crate's in-place functions ---------------------------------------------------

type Keygen = fn(&[u8; 32], &mut [u8], &mut [u8]) -> formosa_ml_dsa::Result<()>;
type Sign = fn(&[u8], &[u8], &[u8], &[u8; 32], &mut [u8]) -> formosa_ml_dsa::Result<()>;
type Verify = fn(&[u8], &[u8], &[u8], &[u8]) -> formosa_ml_dsa::Result<()>;

/// One parameter set: its sizes, its three functions and what fips204 says.
struct Set {
    name: &'static str,
    keygen: Keygen,
    sign: Sign,
    verify: Verify,
    public_key: u64,
    secret_key: u64,
    signature: u64,
}

const SETS: [(Set, usize, usize, usize); 2] = [
    (Set { name: "ML-DSA-44", keygen: MlDsa44::keygen_into, sign: MlDsa44::sign_into,
           verify: MlDsa44::verify_bytes, public_key: expected::mldsa44::PUBLIC_KEY,
           secret_key: expected::mldsa44::SECRET_KEY, signature: expected::mldsa44::SIGNATURE },
     MlDsa44::VERIFICATION_KEY_SIZE, MlDsa44::SIGNING_KEY_SIZE, MlDsa44::SIGNATURE_SIZE),
    (Set { name: "ML-DSA-65", keygen: MlDsa65::keygen_into, sign: MlDsa65::sign_into,
           verify: MlDsa65::verify_bytes, public_key: expected::mldsa65::PUBLIC_KEY,
           secret_key: expected::mldsa65::SECRET_KEY, signature: expected::mldsa65::SIGNATURE },
     MlDsa65::VERIFICATION_KEY_SIZE, MlDsa65::SIGNING_KEY_SIZE, MlDsa65::SIGNATURE_SIZE),
];

/// Keys and signatures live here rather than on the stack, so that what the stack
/// measurement reports is what the implementation itself needed. Sized for ML-DSA-65.
struct Buffers {
    public_key: [u8; 1952],
    secret_key: [u8; 4032],
    signature: [u8; 3309],
}

static mut BUFFERS: Buffers = Buffers {
    public_key: [0; 1952],
    secret_key: [0; 4032],
    signature: [0; 3309],
};

fn sign(set: &Set, sk: &[u8], message: &[u8], randomness: &[u8; 32], sig: &mut [u8]) -> bool {
    (set.sign)(sk, message, &[], randomness, sig).is_ok()
}

fn verify(set: &Set, pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    (set.verify)(pk, sig, message, &[]).is_ok()
}

fn fnv(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Whether every digest matched; the run fails loudly rather than reporting timings for
/// a computation that was not ML-DSA.
static FAILURES: AtomicU32 = AtomicU32::new(0);

fn check(set: &str, what: &str, digest: u64, want: u64) {
    if digest == want {
        defmt::info!("{} {}: matches fips204 (0x{:016x})", set, what, digest);
    } else {
        FAILURES.fetch_add(1, Ordering::Relaxed);
        defmt::error!("{} {}: 0x{:016x}, fips204 says 0x{:016x}", set, what, digest, want);
    }
}

// --- SysTick, extended past its 24 bits by counting its wraps ------------------------

static OVERFLOWS: AtomicU32 = AtomicU32::new(0);
const RELOAD: u32 = 0x00FF_FFFF;

#[exception]
fn SysTick() {
    OVERFLOWS.fetch_add(1, Ordering::Relaxed);
}

fn ticks() -> u64 {
    loop {
        let before = OVERFLOWS.load(Ordering::Relaxed);
        let current = SYST::get_current();
        let after = OVERFLOWS.load(Ordering::Relaxed);
        if before == after {
            // SysTick counts down, so the elapsed part of a period is RELOAD - current.
            return before as u64 * (RELOAD as u64 + 1) + (RELOAD - current) as u64;
        }
    }
}

// --- How deep the stack went ---------------------------------------------------------

const PAINT: u32 = 0xC0DE_C0DE;

extern "C" {
    /// The lowest address the stack may reach. cortex-m-rt 0.7.7 puts the stack below
    /// the statics, from `_stack_start` down to this; painting from the heap start
    /// instead, as with earlier versions, paints nothing and reports 0 bytes.
    static mut _stack_end: u32;
    static mut _stack_start: u32;
}

fn paint_from() -> usize {
    (addr_of_mut!(_stack_end) as usize + 3) & !3
}

fn stack_top() -> usize {
    addr_of_mut!(_stack_start) as usize
}

/// Fills the unused stack with a pattern, up to a safe distance below the stack pointer.
fn paint() {
    let to = (cortex_m::register::msp::read() as usize - 256) & !3;
    let mut address = paint_from();
    while address < to {
        unsafe { core::ptr::write_volatile(address as *mut u32, PAINT) };
        address += 4;
    }
}

/// How far down the painted region something wrote.
fn deepest() -> usize {
    let top = stack_top();
    let mut address = paint_from();
    let to = (cortex_m::register::msp::read() as usize - 256) & !3;
    while address < to {
        if unsafe { core::ptr::read_volatile(address as *const u32) } != PAINT {
            return top - address;
        }
        address += 4;
    }
    0
}

/// Runs one operation, reporting what it cost.
fn measure<R>(set: &str, what: &str, operation: impl FnOnce() -> R) -> R {
    paint();
    let start = ticks();
    let result = operation();
    let elapsed = ticks() - start;
    defmt::info!("{} {}: {} ticks, {} bytes of stack", set, what, elapsed, deepest());
    result
}

#[entry]
fn main() -> ! {
    let mut core = cortex_m::Peripherals::take().unwrap();
    // The processor clock: ticks are cycles. The LPC55S69 gates SysTick's reference
    // clock off at reset, so on the silicon the default source never counts.
    core.SYST.set_clock_source(SystClkSource::Core);
    core.SYST.set_reload(RELOAD);
    core.SYST.clear_current();
    core.SYST.enable_counter();
    core.SYST.enable_interrupt();

    defmt::info!("formosa-ml-dsa (Jasmin, armv8m, {}) on a Cortex-M33",
                 if cfg!(feature = "lowram") { "lowram" } else { "ref" });

    // SAFETY: single-threaded, and this is the only reference taken.
    let buffers = unsafe { &mut *addr_of_mut!(BUFFERS) };

    for (set, pk_len, sk_len, sig_len) in SETS.iter() {
        let pk = &mut buffers.public_key[..*pk_len];
        let sk = &mut buffers.secret_key[..*sk_len];
        let sig = &mut buffers.signature[..*sig_len];
        let name = set.name;

        if measure(name, "keygen", || (set.keygen)(&SEED, pk, sk)).is_err() {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            defmt::error!("{} keygen: returned an error", name);
        }
        check(name, "public key", fnv(pk), set.public_key);
        check(name, "secret key", fnv(sk), set.secret_key);

        let signed = measure(name, "sign", || sign(set, sk, &MESSAGE, &RANDOMNESS, sig));
        if !signed {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            defmt::error!("{} sign: returned an error", name);
        }
        check(name, "signature", fnv(sig), set.signature);

        let good = measure(name, "verify", || verify(set, pk, &MESSAGE, sig));
        sig[0] ^= 1;
        let tampered = verify(set, pk, &MESSAGE, sig);
        sig[0] ^= 1;
        let wrong_message = verify(set, pk, b"another message", sig);
        report_verification(name, good, tampered, wrong_message);
    }

    // Deterministic signing is the same signature with all-zero randomness, and it has
    // to be reproducible: two calls, same bytes.
    {
        let set = &SETS[0].0;
        let sk = &buffers.secret_key[..2560];
        let sig = &mut buffers.signature[..2420];
        sign(set, sk, &MESSAGE, &[0; 32], sig);
        let once = fnv(sig);
        sign(set, sk, &MESSAGE, &[0; 32], sig);
        if once == fnv(sig) {
            defmt::info!("ML-DSA-44 deterministic signing: reproducible");
        } else {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            defmt::error!("ML-DSA-44 deterministic signing: two different signatures");
        }
    }

    // The by-value API: the same key and signature, and what its buffers cost
    let crate_api = measure("ML-DSA-44", "keygen, sign and verify through the by-value API", || {
        let (signing_key, verifying_key) = MlDsa44::generate_keypair_with_seed(&SEED).unwrap();
        let signature = signing_key.sign_with_seed(&MESSAGE, &[], &RANDOMNESS).unwrap();
        let verified = verifying_key.verify(&signature, &MESSAGE, &[]).is_ok();
        (fnv(signature.as_slice()), verified)
    });
    check("ML-DSA-44", "signature through the by-value API", crate_api.0,
          expected::mldsa44::SIGNATURE);
    if !crate_api.1 {
        FAILURES.fetch_add(1, Ordering::Relaxed);
        defmt::error!("ML-DSA-44 verify through the by-value API: rejected its own signature");
    }

    let failures = FAILURES.load(Ordering::Relaxed);
    if failures == 0 {
        defmt::info!("test firmware done: everything matched");
    } else {
        defmt::error!("test firmware done: {} check(s) failed", failures);
    }
    loop {
        cortex_m::asm::wfi();
    }
}

fn report_verification(set: &str, good: bool, tampered: bool, wrong_message: bool) {
    if good && !tampered && !wrong_message {
        defmt::info!("{} verify: accepts its own signature, rejects a tampered one and \
                      another message", set);
    } else {
        FAILURES.fetch_add(1, Ordering::Relaxed);
        defmt::error!("{} verify: good={} tampered={} wrong message={}",
                      set, good, tampered, wrong_message);
    }
}
