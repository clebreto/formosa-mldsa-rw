/* The LPC55S69 as the emulated EVK presents it: 640 KB of flash and 256 KB of
   contiguous SRAM. This firmware only needs the start of each. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
