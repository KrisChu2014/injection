/* ApiHook Header layout */

OFFSET_DST		= 5
OFFSET_SRC		= OFFSET_DST + 4
OFFSET_LENGTH 		= OFFSET_SRC + 4
OFFSET_HOOKER		= OFFSET_LENGTH + 4
OFFSET_HOOKER_LENGTH 	= OFFSET_HOOKER + 4
OFFSET_NAME		= OFFSET_HOOKER_LENGTH + 4

/* System call id */

CONST_SEEK_SET	= 0
CONST_O_RDONLY 	= 0
CONST_SYS_OPEN	= 5
CONST_SYS_WRITE = 4
CONST_SYS_READ  = 3
CONST_SYS_CLOSE = 6
CONST_SYS_EXIT  = 1
CONST_SYS_LSEEK = 19
CONST_SYS_MPROT = 125
CONST_SYS_CREAT	= 8
CONST_SYS_MMAP	= 90
CONST_SYS_FLOCK	= 143

/* constant value */

CONST_MPROT	= 7	/* PROT_READ | PROT_WRITE | PROT_EXEC */
CONST_MRDPROT	= 1	/* PROT_READ */
CONST_PSIZE 	= 0x1000
CONST_PMASK	= 0xfffff000
CONST_PGMASK	= 0x00000fff
CONST_CREAT	= 0x241
CONST_ACCESS 	= 0x1ff
CONST_MPRIVATE	= 2
CONST_MERROR	= 0xffffffff
CONST_LOG_APPEND = 0x474f4c5f	/* _LOG */
CONST_RELO_SZ	= 0x04
CONST_FLOCK_EX	= 0x02	
CONST_FLOCK_UN	= 0x08
CONST_TAG_MALLOC = 0x4c4c414d	/*'MALL'*/
CONST_TAG_FREE = 0x45455246	/*'FREE'*/

.text
	
.globl	__ApiHookStart
__ApiHookStart:
	
	xchgl	(%esp), %edi
		
	/*
	adjust for the first jmp instruction, 
	which is 5-byte long, 
	*/
	
	subl	$0x05, %edi	
	
	pushl	%edx
	pushl	%eax
	pushl	%ecx
	pushl	%ebx
	pushl	%esi
	pushl	%ebp
	
	movl	%esp, %ebp
	
	/*
	
	(%ebp)	= %ebp
	4(%ebp)	= %esi
	8(%ebp)	= %ebx
	0x0c(%ebp) = %ecx
	0x10(%ebp) = %eax
	0x14(%ebp) = %edx
	0x18(%ebp) = %edi
	
	%edi = struct *__ApiHookHdr
	
	*/
	
	call __ApiHookInit__
	
	/* Open disk image, at the end of which is 
	   the original entry point code */
	
	movl	$CONST_O_RDONLY, %ecx
	leal	OFFSET_NAME(%edi), %ebx
	movl	$CONST_SYS_OPEN, %eax
	int	$0x80
	movl	%eax, %ebx
	incl	%eax
	jz	__ApiHookStart_Abort
	
	/* Locate the original entry point code	*/
	
	pushl	%ebx
	movl	$CONST_SEEK_SET, %edx
	movl	OFFSET_SRC(%edi), %ecx
	movl	$CONST_SYS_LSEEK, %eax
	int	$0x80
	popl	%ebx
	incl	%eax
	jz	__ApiHookStart_Abort

	/* Read onto stack the original point code */	
		
	movl	OFFSET_LENGTH(%edi), %edx
	subl	%edx, %esp
	movl	%esp, %ecx
	pushl	%ebx
	movl	$CONST_SYS_READ, %eax
	pushl	%edx
	int	$0x80
	popl	%edx
	popl	%ebx
	cmpl	%eax, %edx
	jnz	__ApiHookStart_Abort

	/* Close disk image descriptor,
	here, we dont check if close successes,	*/	

	movl	$CONST_SYS_CLOSE, %eax
	int	$0x80
	
	/*
	After read original entry point code,
	need to restore relocation address,
	Here, for the sake of simplicity,
	we skip any code involving relocation.
	*/
	
	movl	%esp, %esi	/* save the read-in data in esi */
	
	movl	%esi, %ebx	/* save esi in ebx */
	movl	%edi, %edx	/* save edi in edx */

	/*
	relocate to get the actual absolute memory address
	*/
	
	call	__ApiHookStart_Relocate
__ApiHookStart_Relocate:

	popl	%esi
	addl	$__ApiHookStart_Restore, %esi
	subl	$__ApiHookStart_Relocate, %esi
	
	movl	$__ApiHookStart_Restore_sz, %ecx
	subl	%ecx, %esp
	movl	%esp, %edi
	
	/*
	esi = memory address of __ApiHookStart_Restore
	edi = stack 
	ecx = length of __ApiHookStart_Restore
	*/
	rep	movsb
	
	/* restore edi, esi */
	movl	%edx, %edi
	movl	%ebx, %esi

	
	/*
	
	Before jmp onto stack,
	we need to setup segment attribute, 
	PROT_EXEC on stack and PROT_WRITE on code.
	
	For the sake of simplicity, we use 
	PROT_EXEC | PROT_WRITE | PROT_READ
	for both segments
	
	*/
	
	movl	%esp, %ebx
	andl	$CONST_PMASK, %ebx

	movl	%esp, %ecx
	andl	$CONST_PGMASK, %ecx
	addl	$__ApiHookStart_Restore_sz, %ecx
	
	movl	$CONST_MPROT, %edx
	movl	$CONST_SYS_MPROT, %eax
	
	int	$0x80
	incl	%eax
	jz	__ApiHookStart_Abort
	
	movl	%edi, %ebx
	andl	$CONST_PMASK, %ebx
	
	movl	%edi, %ecx
	andl	$CONST_PGMASK, %ecx
	addl	OFFSET_LENGTH(%edi), %ecx
	
	movl	$CONST_MPROT, %edx
	movl	$CONST_SYS_MPROT, %eax
	
	int	$0x80
	incl	%eax
	jz	__ApiHookStart_Abort
	
	movl	OFFSET_LENGTH(%edi), %ecx
	
	/*

	Code writeable attirbute and 
	stack executable attribute are switched on	

	The stack layout:
		
	Starting from esp, which is currently
	the lowest addressable stack address
		
	1) code of self-restore and register-restore;
	2) the original code starting from entry point, 
	   used for self-restore;
	3) original value of register,
	   used for register-restore; 

	
	edi = memory address of entry point
	esi = stack address of read in data
	ecx = mov length
	ebp = base address of register original vaule

	Everything has been setup.

	*/
		
	jmp	*%esp

	/* API's Hook Installation */
	
__ApiHookInit__:

	pushl	%edi
	
	leal	OFFSET_NAME(%edi), %esi
	
	pushl	%edi	/* save %edi for stosb */
	
	subl	$0x100, %esp
	movl	%esp, %edi
	movl	%esp, %ebx
	
__ApiHookInit_1:	
	lodsb	
	orb	%al, %al
	jz	__ApiHookInit_2
	stosb
	jmp	__ApiHookInit_1

__ApiHookInit_2:
	movl	$CONST_LOG_APPEND, (%edi)
	movb	%al, 4(%edi)
	
	movl	$CONST_ACCESS, %ecx
	movl	$CONST_SYS_CREAT, %eax
	int	$0x80
	
	addl	$0x100, %esp
	
	popl	%edi	/* restore %edi */
	
	
	/* save log file handle in %esi */
	movl	%eax, %esi 
	
	incl	%eax
	jz	__ApiHookInit_3	/* if fails, restore %edi and return */ 

	/* open Elf file */
	leal	OFFSET_NAME(%edi), %ebx	/* Elf file name */
	movl	$CONST_O_RDONLY, %ecx	/* O_RDONLY */
	movl	$CONST_SYS_OPEN, %eax	
	int	$0x80
	
	/* save Elf fie handle in %ebx */
	movl	%eax, %ebx
	
	incl	%eax
	jz	__ApiHookInit_3	/* if fails, restore %edi and return */ 

	/* After successfully open Elf file with O_RDONLY,
	   we mmap the hooker file image into memory with PROT_READ
	   and change the hooker memory image to PROT_READ | PROT_WRITE | PROT_EXEC */
	
	
	/* 1) mmap( addr, length, PROT_READ, MAP_PRIVATE, Elf file handle, offset ) */
	
	pushl	%ebx	/* save %ebx */
	
	/* save mmap paramters on stack */
	
	movl	OFFSET_HOOKER(%edi), %eax
	andl	$CONST_PMASK, %eax
	pushl	%eax			/* offset of where to map, 
					   aligned to page size */	
					   
	pushl	%ebx			/* file descriptor */
	pushl	$CONST_MPRIVATE		/* MAP_PRIVATE */
	pushl	$CONST_MRDPROT		/* PROT_READ */
	
	movl	OFFSET_HOOKER(%edi), %eax
	andl	$CONST_PGMASK, %eax
	addl	OFFSET_HOOKER_LENGTH(%edi), %eax
	pushl	%eax			/* mapping length, 
					   including alignment */	

	pushl	$0x00			/* addr */
	
	movl	%esp, %ebx
	movl	$CONST_SYS_MMAP, %eax
	int	$0x80
	
	addl	$(4 * 6), %esp	/* adjust %esp for mmap paramters */	
	
	/* restore ebx, ebx = open Elf file handle */
	popl	%ebx
	
	pushl	%eax 	/* save eax on stack before closing Elf file */
	
	/* close open Elf file handle */
	movl	$CONST_SYS_CLOSE, %eax
	int	$0x80

	popl	%eax 	/* restore %eax, check the mmap result */
	
	cmpl	$CONST_MERROR, %eax
	jz	__ApiHookInit_3		/* if mmap fails ...*/
	
	movl	%eax, %ebx	
	
	/* 2) mprotect( addr, length, PROT_READ | PROT_WRITE | PROT_EXEC ) */
	
	movl	OFFSET_HOOKER(%edi), %ecx
	andl	$CONST_PGMASK, %ecx
	addl	OFFSET_HOOKER_LENGTH(%edi), %ecx	/* length, plus alignment */
	
	movl	$CONST_MPROT, %edx	/* PROT_READ | PROT_WRITE | PROT_EXEC */

	movl	$CONST_SYS_MPROT, %eax
	int	$0x80
	
	incl	%eax
	jz	__ApiHookInit_4	/* if mprotect fails, munmap */

	movl	OFFSET_HOOKER(%edi), %eax
	andl	$CONST_PGMASK, %eax
	addl	%eax, %ebx		

	/*
	Start installing hookers, 
	patching process address space.
	
	%edi = globl hdr
	%esi = log file handle
	%ebx = address of hookers
	*/	
	
	movl	(%ebx), %ecx
	
	/* if there is not hooker to install,
	   munmap the memory and return */
	
	andl	%ecx, %ecx
	jz	__ApiHookInit_4		
	
	movl	4(%ebx), %eax

__ApiHookInit_5:
	orl	%eax, %eax
	
	jz	__ApiHookInit_3	/* if next entry offset is zero, return */
	addl	%eax, %ebx	/* adjust esi to point to the next hooker */
	
	/*
	(%ebx)		= log file handle, saved in 
	4(%ebx) 	= api address
	8(%ebx) 	= calling address
	0x0c(%ebx) 	= relocate address 
	0x10(%ebx) 	= offset of next entry 
	0x14(%ebx)	= offset of hooker entry point
	*/
	
	/* Before patching process memory, 
	   change memory protect attributes first */
	
	movl	0x0c(%ebx), %ecx

	orl	%ecx, %ecx
	jz	__ApiHookInit_6		/* if relo is zero, there is no such symbol, 
					   jmp to next hooker */
	andl	$CONST_PGMASK, %ecx
	addl	$CONST_RELO_SZ, %ecx	/* %ecx = length, plus alignment */
	
	pushl	%ebx	/* save %ebx */
	
	movl	0x0c(%ebx), %ebx
	and 	$CONST_PMASK, %ebx	/* addr, aligned to 0x1000 */
	
	movl	$CONST_MPROT, %edx	/* PROT_READ | PROT_WRITE | PROT_EXEC */
	movl	$CONST_SYS_MPROT, %eax
	int	$0x80
	
	popl	%ebx	/* restore %ebx */
	
	incl	%eax
	jz	__ApiHookInit_4	/* if mprotect fails, goto mnumap */
	
	/* save api address */
	movl	0x0c(%ebx), %edx
	movl	(%edx), %eax
	movl	%eax, 4(%ebx)
	
	/* install hooker */
	movl	0x14(%ebx), %eax
	addl	%ebx, %eax	/* hooker addr saved in %eax */
	
	movl	0x0c(%ebx), %edx
	movl	%eax, (%edx)	/* hooker installed */
	
	movl	%esi, (%ebx)	/* log file handle saved */
	
	/* next hooker */
__ApiHookInit_6:	
	movl	0x10(%ebx), %eax
	
	jmp	__ApiHookInit_5
		
	/* munmap */	
__ApiHookInit_4:
	nop	
	
	/* restore %edi and return */	
__ApiHookInit_3:	
	pop	%edi	

	ret

	/* self-restore	*/

__ApiHookStart_Restore:
	
	pushl	%edi
	
	rep movsb
	
	popl	%edi
	
	movl	%ebp, %esp
	
	popl	%ebp
	popl	%esi
	popl	%ebx
	popl	%ecx
	popl	%eax
	popl	%edx
	
	xchgl	%edi, (%esp)
	ret
		
__ApiHookStart_Abort:
__ApiHookStart_Restore_sz = __ApiHookStart_Abort - __ApiHookStart_Restore

	movl	$CONST_SYS_EXIT, %eax
	int	$0x80


.globl	__ApiHookStart_sz
__ApiHookStart_sz:
	.long 	__ApiHookStart_sz - __ApiHookStart


.globl	__ApiHookerSym__
__ApiHookerSym__:
	.long	0x02
	.string "malloc"
	.string "free"
	.byte 0x00


.globl	__ApiHookerHdr__
__ApiHookerHdr__:
	
	.long	0x00	/* number of hookers,
			   filled by ApiHook_Install */
			   
	.long	__ApiHooker_malloc__ - __ApiHookerHdr__	/* offset of the first hooker	
			  				 to __ApiHookerHer__,
			  				 which is hardcoded */
			  				 
	.long	0x01	/* lock to sync access of log file */		  				 
			  				 

/* hooker of malloc */

.globl	__ApiHooker_malloc__
__ApiHooker_malloc__:

	.long	0x00	/* log file handle 
			   filled by __ApiHookInit__ */
			   
	.long	0x00	/* malloc base address 
			   filled by __ApiHookInit__ */
	
	.long	0x00	/* return address,
			   filled by __ApiHookerStart_malloc__,
			   
			   everytime malloc is called, 
			   this field will be filled with 
			   a return address.
			   
			   A WRITEABLE VARIABLE,
			   NEEDS SYNC ACCESS */
			   
	.long	0x00	/* relocate address 
			   hardcoded by ApiHook_Install 
			   during ELF file modification */
	
	/* offset of next hooker, hardcoded */		   
	.long	__ApiHooker_free__ - __ApiHooker_malloc__		
		
	/* offset of hooker entry point */		
	.long	__ApiHookerStart_malloc__ - __ApiHooker_malloc__		   		   
	
	/* offset to the __ApiHookerHdr__ */
	.long   __ApiHooker_malloc__ - __ApiHookerHdr__
	
__ApiHookerStart_malloc__:
	call __ApiHookerRelocate_malloc__
__ApiHookerRelocate_malloc__:
	xchgl	%edi, (%esp)
		
	/* adjust edi to __ApiHooker_malloc__*/	
	addl	$__ApiHooker_malloc__, %edi
	subl	$__ApiHookerRelocate_malloc__, %edi
	
	/*
	
	%edi = absolute physical memory address of __ApiHooker_malloc__,
	
	(%edi) 	= log file handle
	4(%edi) = malloc base address
	8(%edi) = return address, 
	0x0c(%edi) = relocate address,
	
	(%esp) = old %edi vaule for restore
	4(%esp) = calling address
	8(%esp) = number of byte to allocate
	
	*/
	
	pushl	%ecx	/* save %ecx */
	pushl	%edx	/* save %edx */
	
	movl	%edi, %edx
	subl	0x18(%edi), %edx
	xorl	%ecx, %ecx
	
__ApiHookerRelocate_malloc_lock:
	xchgl	%ecx, 0x08(%edx)
	orl	%ecx, %ecx
	jz	__ApiHookerRelocate_malloc_lock
	
	pushl	(4 + 4 + 8)(%esp)	/* number of bytes to alloc */
	pushl	(4 + 4 + 4 + 4)(%esp)	/* calling address */
	pushl	$CONST_TAG_MALLOC /* malloc tag */	
	movl	%esp, %ecx
	
	pushl	%ebx
	pushl	%eax
	
	movl	$0x0c, %edx	
	movl	(%edi), %ebx
	movl	$CONST_SYS_WRITE, %eax
	int	$0x80
	
	popl	%eax
	popl	%ebx
	
	popl	%ecx
	popl	%ecx
	popl	%ecx
	
	popl	%edx	/* restore %edx */
	popl	%ecx	/* restore %ecx */
	
	pushl	%eax
	movl	(4 + 4)(%esp), %eax
	movl	%eax, 8(%edi)
	
	movl	%edi, %eax
	addl	$__ApiHookerPost_malloc__, %eax
	subl	$__ApiHooker_malloc__, %eax
	movl	%eax, (4 + 4)(%esp)
	popl	%eax
	
	movl	4(%edi), %edi
	xchgl	%edi, (%esp)
	
	ret
	
__ApiHookerPost_malloc__:
	call	__ApiHookerPostRelocate_malloc__
__ApiHookerPostRelocate_malloc__:
	xchgl	%edi, (%esp)
	
	addl	$__ApiHooker_malloc__, %edi
	subl	$__ApiHookerPostRelocate_malloc__, %edi
	
	/* edi = absolute physical memory address of __ApiHooker_malloc__ */
	
	pushl	%ecx
	
	pushl	$0x00
	pushl	%eax
	movl	%esp, %ecx
	pushl	%edx
	pushl	%ebx
	movl	$0x08, %edx
	movl	(%edi), %ebx
	movl	$CONST_SYS_WRITE, %eax
	int	$0x80
	
	/* release lock */
	
	movl	%edi, %ecx
	subl	0x18(%edi), %ecx
	movl	$0x01, 0x08(%ecx)
	
	
	movl	0x14(%edi), %eax
	addl	%edi, %eax
	movl	0x0c(%edi), %edx
	movl	%eax, (%edx)	
	
	popl	%ebx
	popl	%edx
	popl	%eax
	popl	%ecx
	popl	%ecx
	
	movl	8(%edi), %edi
	xchgl	%edi, (%esp)
	
	ret
	

/* hooker of free */

.globl	__ApiHooker_free__
__ApiHooker_free__:

	.long	0x00	/* log file handle 
			   filled by __ApiHookInit__ */
			   
	.long	0x00	/* free base address 
			   filled by __ApiHookInit__ */
	
	.long	0x00	/* return address,
			   filled by __ApiHookerStart_free__,
			   
			   everytime free is called, 
			   this field will be filled with 
			   a return address.
			   
			   A WRITEABLE VARIABLE,
			   NEEDS SYNC ACCESS */
			   
	.long	0x00	/* relocate address 
			   hardcoded by ApiHook_Install 
			   during ELF file modification */

	.long	0x00	/* offset of next hooker, 
			   the last entry will always be zero,
			   hardcoded */
			   
	/* offset of hooker entry point */		
	.long	__ApiHookerStart_free__ - __ApiHooker_free__				   

	/* offset to the __ApiHookerHdr__ */
	.long   __ApiHooker_free__ - __ApiHookerHdr__
			   
__ApiHookerStart_free__:
	call __ApiHookerRelocate_free__
__ApiHookerRelocate_free__:
	xchgl	%edi, (%esp)
		
	/* adjust edi to __ApiHooker_free__*/	
	addl	$__ApiHooker_free__, %edi
	subl	$__ApiHookerRelocate_free__, %edi
	
	/*
	
	%edi = absolute physical memory address of __ApiHooker_free__,
	
	(%edi) 	= log file handle
	4(%edi) = free base address
	8(%edi) = return address, 
	0x0c(%edi) = relocate address,
	
	(%esp) = old %edi vaule for restore
	4(%esp) = calling address
	8(%esp) = address of buffer which to be freed
	
	*/
	
	pushl	%ecx	/* save %ecx */
	pushl	%edx	/* save %edx */
	
	movl	%edi, %edx
	subl	0x18(%edi), %edx	/* %edx = * __ApiHookerHdr__*/
	xorl	%ecx, %ecx
	
__ApiHookerStart_free_lock:
	xchgl	%ecx, 0x08(%edx)
	orl	%ecx, %ecx
	jz	__ApiHookerStart_free_lock
	
	pushl	(4 + 4 + 8)(%esp)	/* memory addr to be freed */
	pushl	(4 + 4 + 4 + 4)(%esp) 	/* calling addr */
	pushl	$CONST_TAG_FREE 	/* free tag */
	movl	%esp, %ecx
	
	pushl	%ebx
	pushl	%eax
	
	movl	$0x0c, %edx
	movl	(%edi), %ebx
	movl	$CONST_SYS_WRITE, %eax
	int	$0x80
	
	popl	%eax
	popl	%ebx
	
	popl	%ecx
	popl	%ecx
	popl	%ecx
	
	popl	%edx	/* restore %edx */
	popl	%ecx	/* restore %ecx */
	
	pushl	%eax
	movl	(4 + 4)(%esp), %eax
	movl	%eax, 8(%edi)
	
	movl	%edi, %eax
	addl	$__ApiHookerPost_free__, %eax
	subl	$__ApiHooker_free__, %eax
	movl	%eax, (4 + 4)(%esp)
	popl	%eax
	
	movl	4(%edi), %edi
	xchgl	%edi, (%esp)
	
	ret
	
__ApiHookerPost_free__:
	call	__ApiHookerPostRelocate_free__
__ApiHookerPostRelocate_free__:
	xchgl	%edi, (%esp)
	
	addl	$__ApiHooker_free__, %edi
	subl	$__ApiHookerPostRelocate_free__, %edi
	
	/* edi = absolute physical memory address of __ApiHooker_free__ */
	
	pushl	%ecx
	
	pushl	$0x00
	pushl	%eax
	movl	%esp, %ecx
	pushl	%edx
	pushl	%ebx
	movl	$0x08, %edx
	movl	(%edi), %ebx
	movl	$CONST_SYS_WRITE, %eax
	int	$0x80

	/* release lock */
	
	movl	%edi, %ecx
	subl	0x18(%edi), %ecx
	movl	$0x01, 0x08(%ecx)

	movl	0x14(%edi), %eax
	addl	%edi, %eax
	movl	0x0c(%edi), %edx
	movl	%eax, (%edx)
	
	popl	%ebx
	popl	%edx
	popl	%eax
	popl	%ecx
	popl	%ecx
	
	movl	8(%edi), %edi
	xchgl	%edi, (%esp)
	
	ret
	
.globl	__ApiHooker_sz
__ApiHooker_sz:
	.long	__ApiHooker_sz - __ApiHookerHdr__
