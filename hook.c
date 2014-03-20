#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#define ApiHook_DgMsg printf
#define LOG_APPENDIX "_log"

#pragma pack(1)

struct ApiHookHdr
{
	char jmp;
	int  disp;

	unsigned int dst;
	unsigned int src;
	unsigned int length;

	unsigned int hooker;
	unsigned int hooker_length;

	char name[];
};

struct ApiHooker
{
	unsigned int nhooker;
	unsigned int first;
};

struct ApiHookerHdr
{
	unsigned int fd;
	unsigned int api;
	unsigned int ret;
	unsigned int relo;
	unsigned int next;
	unsigned int entry;
	unsigned int hdr_offset;
};

struct ApiHookerSym
{
	unsigned int nhooker;
	char symname[];
};

int fd = -1;
Elf32_Ehdr Elf32Hdr;
Elf32_Shdr *SectionHdrEntry;
Elf32_Off  EntryOffset;
off_t	EndOfFile;
void *EntryBuffer;
struct ApiHooker *Hooker;
unsigned int __ApiHook_Buffer_sz;
int __ApiHook_Displacement;

extern void *__ApiHookStart(void);
extern unsigned int __ApiHookStart_sz;
extern void *__ApiHookerSym__(void);
extern void *__ApiHookerHdr__(void);
extern unsigned int __ApiHooker_sz;

int ApiHook_doWriteFile(int fd, int foffset, int size, void *buf)
{
	int retval = -1;

	retval = lseek(fd, foffset, SEEK_SET);
	if(retval == -1)
		goto __return;

	retval = write(fd, buf, size);
	if(retval != size)
	{
		retval = -1;
	}
	else
	{
		retval = 0;
	}

__return:
	return retval;
}


int ApiHook_doReadFile(int fd, int foffset, int size, void *buf)
{
	int retval = -1;

	retval = lseek(fd, foffset, SEEK_SET);
	if(retval == -1)
		goto __return;

	retval = read(fd, buf, size);
	if(retval != size)
	{
		retval = -1;
	}
	else
	{
		retval = 0;
	}

__return:
	return retval;
}

void *ApiHook_ReadFile(int fd, int foffset, int size)
{
	void *buf = NULL;
	int retval = -1;

	buf = malloc(size);
	if(buf == NULL)
		goto __return;

	retval = ApiHook_doReadFile(fd, foffset, size, buf);
	if(retval == 0)
		goto __return;

__free:
	free(buf);
	buf = NULL;

__return:
	return buf;
}


/* synname: symbal name,
   return physical memory address */

Elf32_Addr ApiHook_SymbolRelo(char *symname)
{
	Elf32_Addr addr = 0;
	int i, j;
	Elf32_Rel *entry = NULL;
	Elf32_Sym *symtab = NULL;
	char *strtab = NULL;
	Elf32_Off sym_off, str_off;
	Elf32_Word sym_size, str_size;
	int sym_ndx, str_ndx;

	ApiHook_DgMsg("sym to relocate: %s\n", symname);

	for(i = 0; i < Elf32Hdr.e_shnum; ++ i)
	{
		if(SectionHdrEntry[i].sh_type == SHT_REL)
		{
			if(! SectionHdrEntry[i].sh_link || SectionHdrEntry[i].sh_link >= Elf32Hdr.e_shnum )
			{
				ApiHook_DgMsg("Relo Section has invalid symtab, sect ndx = 0x%x\n", i);
				goto __next;
			}

			if(! SectionHdrEntry[SectionHdrEntry[i].sh_link].sh_link ||
				SectionHdrEntry[SectionHdrEntry[i].sh_link].sh_link >= Elf32Hdr.e_shnum)
			{
				ApiHook_DgMsg("Relo Section has invalid strtab, sect ndx = 0x%x\n", i);
				goto __next;
			}

			/* Read Relocation Table */
			entry = (Elf32_Rel *)ApiHook_ReadFile(
						fd,
						(int)SectionHdrEntry[i].sh_offset,
						(int)SectionHdrEntry[i].sh_size
						);

			if(! entry)
			{
				ApiHook_DgMsg("Read relo table failed, errno = %d\n", errno);
				addr = 0;

				goto __return;
			}

			/* Read Symbol Table */
			sym_ndx = SectionHdrEntry[i].sh_link;
			sym_off = SectionHdrEntry[sym_ndx].sh_offset;
			sym_size = SectionHdrEntry[sym_ndx].sh_size;

			symtab = (Elf32_Sym *)ApiHook_ReadFile(	fd, sym_off, sym_size );
			if(! symtab)
			{
				ApiHook_DgMsg("Read symtable failed, sect ndx = 0x%x\n", i);
				goto __return;
			}

			/* Read String Table */
			str_ndx = SectionHdrEntry[sym_ndx].sh_link;
			str_off = SectionHdrEntry[str_ndx].sh_offset;
			str_size = SectionHdrEntry[str_ndx].sh_size;

			strtab = (char *)ApiHook_ReadFile(fd, str_off, str_size);
			if(! strtab)
			{
				ApiHook_DgMsg("Read strtab failed, sect ndx = 0x%x\n", i);
				goto __return;
			}


			ApiHook_DgMsg("Relo Section 0x%x\n", i);
			ApiHook_DgMsg("SymTab ndx = 0x%x off = 0x%x size = 0x%x\n", sym_ndx, sym_off, sym_size);
			ApiHook_DgMsg("StrTab ndx = 0x%x off = 0x%x size = 0x%x\n", str_ndx, str_off, str_size);

			j = 0;
			while(j < SectionHdrEntry[i].sh_size / sizeof(Elf32_Rel))
			{
				if(! strcmp(
					symname,
					strtab + symtab[ELF32_R_SYM(entry[j].r_info)].st_name
					))
				{
					ApiHook_DgMsg(
						"%s@0x%x\n",
						strtab + symtab[ELF32_R_SYM(entry[j].r_info)].st_name,
						entry[j].r_offset
						);

					addr = entry[j].r_offset;
					goto __return;
				}

				++j;
			}

		__next:

			free(symtab);
			symtab = NULL;

			free(strtab);
			strtab = NULL;

			free(entry);
			entry = NULL;
		}
	}

__return:

	if(entry)
	{
		free(entry);
		entry = NULL;
	}

	if(symtab)
	{
		free(symtab);
		symtab = NULL;
	}

	if(strtab)
	{
		free(strtab);
		strtab = NULL;
	}

	return addr;
}

int ApiHook_InstallHooker(void)
{
	int n;
	struct ApiHookerHdr *hdr;
	Elf32_Addr addr;
	char *symname;

	memcpy(Hooker, (struct ApiHooker *)__ApiHookerHdr__, __ApiHooker_sz);
	Hooker->nhooker = ((struct ApiHookerSym *)__ApiHookerSym__)->nhooker;
	symname = ((struct ApiHookerSym *)__ApiHookerSym__)->symname;

	ApiHook_DgMsg("Hooker, nhook = 0x%x\n", Hooker->nhooker);

	hdr = (struct ApiHookerHdr *)(((char *)Hooker) + Hooker->first);

	for(n = 0; n < Hooker->nhooker; ++ n)
	{
		//	hdr->fd, to be filled by __ApiHookInit__
		//	hdr->api, to be filled by __ApiHookInit__
		//	hdr->ret, to be filled every time api is called
		// 	hdr->relo, is filled by ApiHook_InstallHooker right here
		//	hdr->next, hardcoded
		//  hdr->entry, hardcoded
		//  hdr->hdr_offset, hardcoded

		hdr->relo = ApiHook_SymbolRelo(symname);
		hdr = (struct ApiHookerHdr *)(((char *)hdr) + hdr->next);
		symname += (strlen(symname) + 1);
	}

	return 0;

}


int ApiHook_ElfHdrCheck(void)
{
	int retval = -1;
	int i;

	// Elf signature
	if( Elf32Hdr.e_ident[EI_MAG0] != ELFMAG0 ||
		Elf32Hdr.e_ident[EI_MAG1] != ELFMAG1 ||
		Elf32Hdr.e_ident[EI_MAG2] != ELFMAG2 ||
		Elf32Hdr.e_ident[EI_MAG3] != ELFMAG3 )
	{
		ApiHook_DgMsg("Elf signature doesnt match\n");

		printf("%x %x %x %x\n",
			(unsigned int)Elf32Hdr.e_ident[EI_MAG0],
			(unsigned int)Elf32Hdr.e_ident[EI_MAG1],
			(unsigned int)Elf32Hdr.e_ident[EI_MAG2],
			(unsigned int)Elf32Hdr.e_ident[EI_MAG3]
			);
		goto __return;
	}

	// start point
	if(Elf32Hdr.e_entry == 0)
	{
		ApiHook_DgMsg("Null entry point\n");
		goto __return;
	}

	// section entry table
	if(Elf32Hdr.e_shoff == 0)
	{
		ApiHook_DgMsg("Null section table\n");
		goto __return;
	}

	// section entry size
	if(Elf32Hdr.e_shentsize != sizeof(Elf32_Shdr))
	{
		ApiHook_DgMsg("Section entry size doesnt match\n");
		goto __return;
	}

	// section entry number
	if(Elf32Hdr.e_shnum == 0)
	{
		ApiHook_DgMsg("Zero section entry number\n");
		goto __return;
	}

	retval = 0;

__return:
	return retval;
}


int ApiHook_Init(char *filename)
{
	int retval = -1;
	int shsize = 0, phsize = 0;
	int i, j;

	retval = chmod(filename, 0777);

	fd = open(filename, O_RDWR);
	if(fd == -1)
	{
		ApiHook_DgMsg("Failed to open %s, errno = %d\n", filename, errno);
		retval = -1;
		goto __return;
	}

	ApiHook_DgMsg("File Descriptor  = %x\n",fd);

	retval = ApiHook_doReadFile(fd, 0, sizeof(Elf32_Ehdr), &Elf32Hdr);
	if(retval != 0)
	{
		ApiHook_DgMsg("Elf File Header read fails\n");
		goto __return;
	}

	retval = ApiHook_ElfHdrCheck();
	if(retval)
	{
		ApiHook_DgMsg("Elf file format doesnt match Elf\n");
		goto __return;
	}

	if(Elf32Hdr.e_shoff != 0)
	{
		SectionHdrEntry = ApiHook_ReadFile(
				fd,
				Elf32Hdr.e_shoff,
				Elf32Hdr.e_shentsize * Elf32Hdr.e_shnum
				);

		if(SectionHdrEntry == NULL)
		{
			ApiHook_DgMsg("section table read fails\n");

			retval = -1;
			goto __return;
		}
	}

	Hooker = (struct ApiHooker *)malloc(__ApiHooker_sz);
	if(! Hooker)
	{
		ApiHook_DgMsg("alloc mem for ApiHooker failed, errno = %d\n", errno );
		retval = -1;
		goto __return;
	}

	ApiHook_DgMsg(
		"addr = 0x%x\tlength = 0x%x\n",
		((unsigned int)__ApiHookerHdr__) & 0xfffff000,
		(((unsigned int)__ApiHookerHdr__) & 0x0fff) + __ApiHooker_sz
		);

	retval = mprotect(
		(void *)(((unsigned int)__ApiHookerHdr__) & 0xfffff000),
		(((unsigned int)__ApiHookerHdr__) & 0x0fff) + __ApiHooker_sz,
		PROT_READ | PROT_WRITE
		);

	if(retval == -1)
	{
		ApiHook_DgMsg("__ApiHookerHdr__ mprotect failed, errno = %d\n", errno);
		goto __return;
	}

	__ApiHook_Buffer_sz =
		sizeof(struct ApiHookHdr)	// ApiHook header
		+ strlen(filename) + 1 		// file name
		+ __ApiHookStart_sz 		// ApiHookStart
		+ __ApiHooker_sz;			// ApiHooker

	__ApiHook_Displacement = sizeof(struct ApiHookHdr) + strlen(filename) + 1 - 5;

__return:
	return retval;
}


int ApiHook_Cleanup(void)
{
	if(Hooker)
	{
		free(Hooker);
		Hooker = NULL;
	}

	if(SectionHdrEntry)
	{
		free(SectionHdrEntry);
		SectionHdrEntry = NULL;
	}

	if(fd != -1)
	{
		close(fd);
		fd = -1;
	}

	if(EntryBuffer)
	{
		free(EntryBuffer);
		EntryBuffer = NULL;
	}

	return 0;
}

int ApiHook_Install(char *filename)
{
	int retval = -1;
	int i, j;

	off_t foffset;
	struct ApiHookHdr *phdr;
	void *ApiHookBuf;
	Elf32_Addr relo;

	for(i = 0; i < Elf32Hdr.e_shnum; ++ i)
	{
		if( SectionHdrEntry[i].sh_addr != 0 &&
			Elf32Hdr.e_entry >= SectionHdrEntry[i].sh_addr &&
			Elf32Hdr.e_entry < SectionHdrEntry[i].sh_addr + SectionHdrEntry[i].sh_size
			)
		{
			// Check section flags and type

			if(SectionHdrEntry[i].sh_type != SHT_PROGBITS)
			{
				ApiHook_DgMsg("entry section type error\n");
				goto __return;
			}

			if(!(SectionHdrEntry[i].sh_flags & SHF_EXECINSTR))
			{
				ApiHook_DgMsg("entry section flags error_1\n");
				goto __return;
			}

			if(!(SectionHdrEntry[i].sh_flags & SHF_ALLOC))
			{
				ApiHook_DgMsg("entry section flags error_2\n");
				goto __return;
			}

			// Check Relocation
			for(j = 0; j < Elf32Hdr.e_shnum; ++ j)
			{
				if( SectionHdrEntry[j].sh_type == SHT_RELA ||
					SectionHdrEntry[j].sh_type == SHT_REL
					)
				{
					if( SectionHdrEntry[j].sh_offset
						>= SectionHdrEntry[i].sh_offset &&
						SectionHdrEntry[j].sh_offset
						<= SectionHdrEntry[i].sh_offset + SectionHdrEntry[i].sh_size )
					{
						ApiHook_DgMsg("relocation overlapped\n");
						retval = -1;
						goto __return;
					}

					if( SectionHdrEntry[j].sh_offset + SectionHdrEntry[j].sh_size
						>= SectionHdrEntry[i].sh_offset &&
						SectionHdrEntry[j].sh_offset + SectionHdrEntry[j].sh_size
						<= SectionHdrEntry[i].sh_offset + SectionHdrEntry[i].sh_size)
					{
						ApiHook_DgMsg("relocation overlapped\n");
						retval = -1;
						goto __return;
					}
				}
			}

			ApiHook_DgMsg("0x%x Section Entry\n", i);

			// Convert virtual address of entry point to
			// the offset in file

			EntryOffset =
				SectionHdrEntry[i].sh_offset
				+ Elf32Hdr.e_entry
				- SectionHdrEntry[i].sh_addr;

			ApiHook_DgMsg("Entry point offset = 0x%x\n", EntryOffset);

			// read out ApiHook_Hooker_sz byte data starting from e_entry
			// and append them to the end of the file

			EntryBuffer = ApiHook_ReadFile(
						fd,
						EntryOffset,
						sizeof(struct ApiHookHdr) + strlen(filename) + 1 + __ApiHookStart_sz
						);


			if(EntryBuffer == NULL)
			{
				ApiHook_DgMsg("Entry Point read fails\n");
				retval = -1;
				goto __return;
			}

			// adjust file pointer to the end of Elf image

			retval = lseek(fd, 0, SEEK_END);
			if(retval == -1)
				goto __return;

			EndOfFile = retval;
			ApiHook_DgMsg("Original file length = 0x%x\n", (unsigned int)EndOfFile);

			// lseek after the end of Elf image, __ApiHook_Buffer_sz long byte

			retval = lseek(fd, __ApiHook_Buffer_sz, SEEK_END);

			if(retval == -1)
				goto __return;

			ApiHook_DgMsg("Extend file with 0x%x more bytes\n", __ApiHook_Buffer_sz);

			retval = lseek(fd, EndOfFile, SEEK_SET);

			if(retval == -1)
				goto __return;

			retval = ApiHook_doWriteFile(
					fd,
					EndOfFile,
					sizeof(struct ApiHookHdr) + strlen(filename) + 1 + __ApiHookStart_sz,
					EntryBuffer
					);

			if(retval == -1)
			{
				ApiHook_DgMsg("Append failed, errno = %d\n", errno);
				goto __return;
			}

			ApiHook_DgMsg("Appended 0x%x bytes\n",
				sizeof(struct ApiHookHdr) + strlen(filename) + 1 + __ApiHookStart_sz);


			// Install __ApiHooker__

			ApiHook_InstallHooker();

			retval = ApiHook_doWriteFile(
					fd,
					EndOfFile + sizeof(struct ApiHookHdr) + strlen(filename) + 1 + __ApiHookStart_sz,
					__ApiHooker_sz,
					Hooker
					);

			if(retval == -1)
			{
				ApiHook_DgMsg("Install __ApiHooker__ failed, errno = %d\n", errno);
				goto __return;
			}

			ApiHook_DgMsg("Appended 0x%x bytes\n",	__ApiHooker_sz);


			// Install __ApiHookStart

			ApiHookBuf = EntryBuffer;

			phdr = (struct ApiHookHdr *)EntryBuffer;

			phdr->jmp 	= 0xe8;
			phdr->disp 	= __ApiHook_Displacement;

			phdr->dst 	= Elf32Hdr.e_entry;
			phdr->src 	= EndOfFile;

			phdr->length = sizeof(struct ApiHookHdr) + strlen(filename) + 1 + __ApiHookStart_sz;

			phdr->hooker = EndOfFile + phdr->length;
			phdr->hooker_length = __ApiHooker_sz;

			ApiHookBuf = ((char *)ApiHookBuf) + sizeof(struct ApiHookHdr);
			memcpy(ApiHookBuf, filename, strlen(filename) + 1);

			ApiHookBuf = ((char *)ApiHookBuf) + strlen(filename) + 1;
			memcpy(ApiHookBuf, __ApiHookStart, __ApiHookStart_sz);

			retval = ApiHook_doWriteFile(
				fd,
				EntryOffset,
				//__ApiHook_Buffer_sz,
				sizeof(struct ApiHookHdr) + strlen(filename) + 1 + __ApiHookStart_sz,
				EntryBuffer
				);

			if(retval == -1)
			{
				ApiHook_DgMsg("New entry point fails\n");
				goto __return;
			}


			ApiHook_DgMsg("Hooker Successfully Installed\n");

			retval = 0;
			goto __return;
		}
	}

__return:
	return retval;
}


int main(int argc, char *argv[])
{
	int retval;

	if(argc != 2)
	{
		goto __return;
	}

	retval = ApiHook_Init(argv[1]);
	if(retval == -1)
	{
		ApiHook_DgMsg("ApiHook_Init fails %s\n", argv[1]);
		goto __return;
	}

	ApiHook_Install(argv[1]);

__cleanup:
	ApiHook_Cleanup();

__return:
	return 0;
}
