#ifndef CHICKADEE_K_VGA_HH
#define CHICKADEE_K_VGA_HH
#include "kernel.hh"

#define COLOR_PURPLE 0xf

#define	VGA_AC_INDEX		0x3C0
#define	VGA_AC_WRITE		0x3C0
#define	VGA_AC_READ		0x3C1
#define	VGA_MISC_WRITE		0x3C2
#define VGA_SEQ_INDEX		0x3C4
#define VGA_SEQ_DATA		0x3C5
#define	VGA_DAC_READ_INDEX	0x3C7
#define	VGA_DAC_WRITE_INDEX	0x3C8
#define	VGA_DAC_DATA		0x3C9
#define	VGA_MISC_READ		0x3CC
#define VGA_GC_INDEX 		0x3CE
#define VGA_GC_DATA 		0x3CF
/*			COLOR emulation		MONO emulation */
#define VGA_CRTC_INDEX		0x3D4		/* 0x3B4 */
#define VGA_CRTC_DATA		0x3D5		/* 0x3B5 */
#define	VGA_INSTAT_READ		0x3DA

#define	VGA_NUM_SEQ_REGS	5
#define	VGA_NUM_CRTC_REGS	25
#define	VGA_NUM_GC_REGS		9
#define	VGA_NUM_AC_REGS		21
#define	VGA_NUM_REGS		(1 + VGA_NUM_SEQ_REGS + VGA_NUM_CRTC_REGS + \
				VGA_NUM_GC_REGS + VGA_NUM_AC_REGS)

#define vpeekb(O)       *(unsigned char *)(16uL * 0xA000 + (O))
#define vpokeb(O,V)     *(unsigned char *)(16uL * 0xA000 + (O)) = (V)
#define vpokew(O,V)     *(unsigned short *)(16uL * 0xA000 + (O)) = (V)
#define vpokel(O,V)     *(unsigned long *)(16uL * 0xA000 + (O)) = (V)
#define vmemwr(DO,S,N)  memcpy((char *)(0xA000 * 16 + (DO)), S, N)

#define set_vga_plane(p) \
    outb(VGA_GC_INDEX, 4); \
    outb(VGA_GC_DATA, (p) ); \
    outb(VGA_SEQ_INDEX, 2); \
    outb(VGA_SEQ_DATA, 1 << (p) );
/*****************************************************************************
VGA REGISTER DUMPS FOR VARIOUS TEXT MODES

()=to do
	40x25	(40x30)	40x50	(40x60)
	(45x25)	(45x30)	(45x50)	(45x60)
	80x25	(80x30)	80x50	(80x60)
	(90x25)	90x30	(90x50)	90x60
*****************************************************************************/
void vga_set_mode(unsigned char* mode);

#endif