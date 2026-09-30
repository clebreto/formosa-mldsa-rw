# Checking the crate on a Cortex-M33

This firmware runs the crate's ML-DSA-44 and ML-DSA-65 on an NXP LPC55S69 (the
LPCXpresso55S69 board, or its emulated counterpart) and reports two things: what it
computed, and what that cost.

The assembly is formosa-mldsa's Cortex-M4 sources compiled by `jasminc -arch armv8m`.
Every value ML-DSA produces here is a function of the seed, the message and the signing
randomness, all of which the caller supplies. So an independent implementation of FIPS 204
must produce the same bytes, and the firmware compares against one rather than against
itself: the digests in `src/main.rs` come from the `fips204` crate on the host. They are
the ones pqm4-mldsa's test firmware checks, with the same inputs.

The crate's in-place functions (`keygen_into`, `sign_into`, `verify_bytes`) run on static
buffers, so that the stack figure is what the Jasmin code needs. The by-value API is then
checked once: it returns keys and signatures by value, which costs stack of its own.

## Running it

```console
$ export JASMINC=path/to/jasmin/compiler/jasminc   # a jasminc with -arch armv8m
$ cargo build                                     # the reference implementation
$ cargo build --features lowram --target-dir target-lowram
```

`arm-none-eabi-as` must be on the PATH. On the board, with probe-rs (patched for the
LPC55S69: see the firmware's `scripts/probe-rs/`):

```console
$ probe-rs download --chip LPC55S69JBD100 target/thumbv8m.main-none-eabihf/debug/formosa-ml-dsa-testfw
$ probe-rs reset --chip LPC55S69JBD100
$ probe-rs attach --chip LPC55S69JBD100 target/thumbv8m.main-none-eabihf/debug/formosa-ml-dsa-testfw
```

On the emulated board, the `lpc55s69evk` machine of the firmware's emulator
(`emu/qemu/overlay`), through `nrf52840_emu.qemu.Emulator(elf, machine="lpc55s69evk",
usbip=False)`.

## What it reported

On the LPCXpresso55S69 (rev A3, chip revision 1B), 2026-09-30, formosa-mldsa 912fa3b,
Jasmin branch `armv8m-hw-semantics` (2da2c182e). Ticks are SysTick on the processor
clock, so cycles. pqm4-mldsa (pqm4 5e5cc76, C at `-O3`) ran on the same board with the
same inputs for comparison. Every digest matched `fips204` in every column.

| Cycles, stack      | pqm4 m4fstack   | Jasmin lowram    | Jasmin ref        |
|--------------------|-----------------|------------------|-------------------|
| ML-DSA-44 keygen   | 3.20 M, 4.6 KB  | 4.81 M, 4.0 KB   | 3.72 M, 34 KB     |
| ML-DSA-44 sign     | 9.91 M, 5.2 KB  | 13.70 M, 6.2 KB  | 6.53 M, 52 KB     |
| ML-DSA-44 verify   | 4.41 M, 2.8 KB  | 6.73 M, 2.8 KB   | 3.70 M, 36 KB     |
| ML-DSA-65 keygen   | 5.91 M, 4.7 KB  | 8.94 M, 4.0 KB   | 6.51 M, 61 KB     |
| ML-DSA-65 sign     | 9.57 M, 6.8 KB  | 14.78 M, 7.8 KB  | 7.74 M, 80 KB     |
| ML-DSA-65 verify   | 7.71 M, 2.8 KB  | 11.78 M, 2.8 KB  | 6.30 M, 58 KB     |

Through the by-value API (keygen, sign and verify with ML-DSA-44 in one go) the stack
reaches 65 KB with `lowram` and 100 KB with `ref`: the keys and signatures it returns
live in `heapless::Vec<u8, 8192>`, and the functions copy them around. The in-place
functions are what the figures of the table measure: use them on a microcontroller.

Under QEMU the stack figures are the same and the cycle counts come within 20% (QEMU
counts instructions, not cycles).

## Two things the silicon taught

- The LPC55S69 gates SysTick's reference clock off at reset: with the default clock
  source the counter never moves, and every measurement reads 0. The firmware selects
  the processor clock.
- cortex-m-rt 0.7.7 places the stack below the statics, from `_stack_start` down to
  `_stack_end`. The paint that measures the stack starts at `_stack_end`; started at the
  heap, as with earlier cortex-m-rt, it paints nothing and reports 0 bytes.
