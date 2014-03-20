#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#define TAG_MALLOC 0x4c4c414d /* malloc tag */
#define TAG_FREE 0x45455246 /* free tag */
#define TAG_ELF  0x464c457f /* ELF */

#pragma pack(1)

struct ApiHook_FileEntry
{
	unsigned int tag;
	unsigned int call;
	unsigned int para;
	unsigned int ret;
	unsigned int pad;
};

unsigned int nmalloc = 0;
unsigned int nfree = 0;
unsigned int mem_alloc = 0;

void ApiHookRead_print(void *p, unsigned int length)
{
	struct ApiHook_FileEntry *entry = p, *fentry = p;
	int i = 0, j;

	if(p == NULL)
		return;

	if(length == 0)
		return;

	while(length >= sizeof(*entry))
	{
		if(entry->tag == TAG_MALLOC)
		{
			printf("malloc@0x%x, nbytes = 0x%x, ", entry->call, entry->para);
			if(entry->ret != 0)
			{
				printf("success 0x%x", entry->ret);
				mem_alloc += entry->para;
				nmalloc ++;
			}
			else
				printf("failed");

			printf(" mem_alloc = 0x%x\n", mem_alloc);
		}

		else if(entry->tag == TAG_FREE)
		{
			if(entry->para == 0)
			{
				printf("free null pointer, 0x%x\n", entry->call);
				goto __next;
			}

			fentry = entry - 1;

			while((char *)fentry >= (char *)p)
			{
				if(fentry->tag != TAG_MALLOC)
				{
					if(fentry->tag == TAG_FREE)
						fentry --;
					else
						fentry =
							(struct ApiHook_FileEntry *)(((char *)fentry) - sizeof(unsigned int));

					continue;

				}
				else if(fentry->ret != entry->para)
				{
					fentry --;
					continue;
				}
				else if(fentry->pad != 0)
				{
					fentry --;
					continue;
				}
				else
				{
					fentry->pad = entry->call;
					mem_alloc -= fentry->para;
					nfree ++;

					printf("free@0x%x addr = 0x%x nbytes = 0x%x success mem_alloc = 0x%x\n",
						entry->call, entry->para, fentry->para, mem_alloc );

					goto __next;
				}
			}

			printf("free@0x%x addr = 0x%x invalid\n", entry->call, entry->para);
			goto __next;

		}

		else
		{
			printf("invalid entry\n");
			entry = (struct ApiHook_FileEntry *)(((char *)entry) + sizeof(unsigned int));
			length -= sizeof(unsigned int);

			continue;
		}

	__next:

		entry ++;
		length -= sizeof(*entry);

	}

	printf("\nPossible memory leak 0x%x nmalloc = 0x%x nfree = 0x%x\n", mem_alloc, nmalloc, nfree );

	return;
}

int ApiHookRead_symbol(
	void *p,		// mapping image of output file
	int length,		// length of mapped output file
	Elf32_Sym *sym,	// mapping image of obj file symtable
	int nsym,		// the number of symtab entry
	char *strtab,	// mapping image of obj file symtable string table
	int strlen		// the length of string table
	)
{
	int i = 0;
	struct ApiHook_FileEntry *entry = p;

	while(length >= sizeof(*entry))
	{
		if(entry->tag == TAG_MALLOC)
		{
			if(entry->ret != 0 && entry->pad == 0)
			{
				printf("%d\tmalloc@0x%x nbytes = 0x%x, not freed\n",
					i, entry->call, entry->para);
			}

			entry ++;
			length -= sizeof(*entry);
			i ++;
		}
		else if(entry->tag == TAG_FREE)
		{
			entry ++;
			length -= sizeof(*entry);
			i ++;
		}
		else
		{
			entry =
				(struct ApiHook_FileEntry *)(((char *)entry) + sizeof(unsigned int));

			length -= sizeof(unsigned int);
		}
	}

	return 0;
}

int ApiHookRead_read(char *filename, char *objname)
{
	int retval = -1;
	int fd, obj_fd;
	void *p = NULL, *obj_p = NULL;
	int file_size, obj_size;
	int i;

	Elf32_Ehdr *ehdr = NULL;

	Elf32_Sym *sym = NULL;
	int nsym;

	Elf32_Shdr *shdr = NULL;
	int nshdr;

	char *strtab = NULL;
	int strlen;
	int strndx;

	fd = open(filename, O_RDWR);

	if(fd == -1)
	{
		goto __return;
	}

	file_size = lseek(fd, 0, SEEK_END);
	if(file_size == -1)
	{
		goto __close;
	}

	p = mmap((void *)0,  file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if(p == NULL)
	{
		printf("mmap failed errno = d\n",errno);
		goto __close;
	}

	ApiHookRead_print(p, file_size);
	ApiHookRead_symbol(p, file_size, NULL, 0, NULL, 0);

	obj_fd = open(objname, O_RDONLY);
	if(obj_fd == -1)
	{
		printf("Open obj file failed, errno = %d\n", errno);
		goto __munmap;
	}

	obj_size = lseek(obj_fd, 0, SEEK_END);
	if(obj_size == -1)
	{
		printf("Seek obj file failed, errno = %d\n", errno);
		goto __obj_close;
	}

	obj_p = mmap(0, obj_size, PROT_READ, MAP_PRIVATE, obj_fd, 0);
	if(obj_p == NULL)
	{
		printf("Map obj file failed, errno = %d\n", errno);
		goto __obj_close;
	}

	if(*((unsigned int *)obj_p) != TAG_ELF)
	{
		printf("obj file is not Elf file\n");
		goto __obj_munmap;
	}

	ehdr = (Elf32_Ehdr *)obj_p;
	if(ehdr->e_shentsize != sizeof(Elf32_Shdr))
	{
		printf("Elf32 section hdr size not correct, 0x%x\n", ehdr->e_shentsize);
		goto __obj_munmap;
	}

	shdr = (Elf32_Shdr *)(((char *)obj_p) + ehdr->e_shoff);
	nshdr = ehdr->e_shnum;

	for(i = 0; i < nshdr; ++ i)
	{
		if(shdr[i].sh_type == SHT_SYMTAB)
		{
			goto __obj_sym;
		}
	}

	printf("Failed to find symtab in obj file\n");
	goto __obj_munmap;

__obj_sym:

	// i -> sym section ndx;

	if(shdr[i].sh_entsize != sizeof(Elf32_Sym))
	{
		printf("Symbol table entsize not correct, entsize = 0x%x\n", shdr[i].sh_entsize);
		goto __obj_munmap;
	}

	strndx = shdr[i].sh_link;

	// strndx -> str section ndx;

	sym = (Elf32_Sym *)(((char *)obj_p) + shdr[i].sh_offset);
	nsym = shdr[i].sh_size / sizeof(Elf32_Sym);

	strtab = ((char *)obj_p) + shdr[strndx].sh_offset;
	strlen = shdr[strndx].sh_size;

	retval = 0;

__obj_munmap:
	munmap(obj_p, obj_size);

__obj_close:
	close(obj_fd);

__munmap:
	munmap(p, file_size);

__close:
	close(fd);

__return:

	return retval;
}

int main(int argc, char *argv[])
{
	if(argc > 1)
	{
		printf("output file: %s\n", argv[1]);
		printf("obj file: %s\n", argv[2]);

		printf("ApiHook_read\n");
		ApiHookRead_read(argv[1], argv[2]);
	}

	return 0;
}
