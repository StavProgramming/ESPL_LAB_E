

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>      // for open()
#include <unistd.h>     // for close(), write(), lseek()
#include <sys/mman.h>   // for mmap(), munmap()
#include <sys/stat.h>   // for fstat()
#include <elf.h>        // ELF structures (Elf32_Ehdr, Elf32_Shdr, etc.)
#include <errno.h>      // for errno

/* Maximum number of ELF files we can have open at once */
#define MAX_ELF_FILES 2

/* Debug mode flag - when on, prints extra info */
int debug_mode = 0;

/* Structure to hold information about an open ELF file */
typedef struct {
    int fd;                 // file descriptor (-1 if not open)
    void *map_start;        // pointer to start of mapped file in memory
    size_t file_size;       // size of the file in bytes
    char filename[256];     // name of the file
} ElfFile;

/* Array to store our open ELF files */
ElfFile elf_files[MAX_ELF_FILES];

/* Function pointer type for menu actions */
typedef void (*MenuFunc)();

/* Structure for menu items - array of function pointers like in lab 1 */
typedef struct {
    char *name;         // name to display in menu
    MenuFunc func;      // function to call when selected
} MenuItem;

/* Forward declarations of our menu functions */
void toggle_debug_mode();
void examine_elf_file();
void print_section_names();
void print_symbols();
void print_relocations();
void check_files_for_merge();
void merge_elf_files();
void quit_program();

/* Our menu items array */
MenuItem menu[] = {
    {"Toggle Debug Mode", toggle_debug_mode},
    {"Examine ELF File", examine_elf_file},
    {"Print Section Names", print_section_names},
    {"Print Symbols", print_symbols},
    {"Print Relocations", print_relocations},
    {"Check Files for Merge", check_files_for_merge},
    {"Merge ELF Files", merge_elf_files},
    {"Quit", quit_program}
};

/* Number of menu items */
#define MENU_SIZE (sizeof(menu) / sizeof(menu[0]))

/* Initialize all ELF file slots to empty state */
void init_elf_files() {
    int i;
    for (i = 0; i < MAX_ELF_FILES; i++) {
        elf_files[i].fd = -1;           // -1 means no file open
        elf_files[i].map_start = NULL;  // NULL means not mapped
        elf_files[i].file_size = 0;
        elf_files[i].filename[0] = '\0';
    }
}

/* Close and unmap a single ELF file by index */
void close_elf_file(int index) {
    if (index < 0 || index >= MAX_ELF_FILES) return;
    
    // if file is mapped, unmap it first
    if (elf_files[index].map_start != NULL) {
        munmap(elf_files[index].map_start, elf_files[index].file_size);
        elf_files[index].map_start = NULL;
    }
    
    // if file is open, close it
    if (elf_files[index].fd != -1) {
        close(elf_files[index].fd);
        elf_files[index].fd = -1;
    }
    
    elf_files[index].file_size = 0;
    elf_files[index].filename[0] = '\0';
}

/* Close all open ELF files */
void close_all_elf_files() {
    int i;
    for (i = 0; i < MAX_ELF_FILES; i++) {
        close_elf_file(i);
    }
}

/* Find an empty slot for a new ELF file, returns -1 if all slots full */
int find_empty_slot() {
    int i;
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (elf_files[i].fd == -1) {
            return i;
        }
    }
    return -1;  // no empty slot
}

/* Toggle debug mode on/off */
void toggle_debug_mode() {
    debug_mode = !debug_mode;
    printf("Debug mode is now %s\n", debug_mode ? "ON" : "OFF");
}

/* * Print ELF header information for a file
 * This is the core of Part 0 - parsing the ELF header using mmap
 */
void print_elf_header(ElfFile *elf) {
    // cast the mapped memory to an ELF header pointer
    Elf32_Ehdr *header = (Elf32_Ehdr *)elf->map_start;
    
    printf("\nELF Header for: %s\n", elf->filename);
    printf("============================================\n");
    
    // print magic number bytes 1,2,3 (bytes 0 is 0x7f, 1-3 are 'E','L','F')
    printf("  Magic:                         %c%c%c\n", 
           header->e_ident[EI_MAG1],   // should be 'E'
           header->e_ident[EI_MAG2],   // should be 'L'
           header->e_ident[EI_MAG3]);  // should be 'F'
    
    // print data encoding (little endian or big endian)
    printf("  Data encoding:                 ");
    if (header->e_ident[EI_DATA] == ELFDATA2LSB) {
        printf("2's complement, little endian\n");
    } else if (header->e_ident[EI_DATA] == ELFDATA2MSB) {
        printf("2's complement, big endian\n");
    } else {
        printf("Unknown\n");
    }
    
    // print entry point address in hex
    printf("  Entry point address:           0x%x\n", header->e_entry);
    
    // print section header table offset
    printf("  Section header table offset:   %d (bytes into file)\n", header->e_shoff);
    
    // print number of section headers
    printf("  Number of section headers:     %d\n", header->e_shnum);
    
    // print size of each section header entry
    printf("  Size of section headers:       %d (bytes)\n", header->e_shentsize);
    
    // print program header table offset
    printf("  Program header table offset:   %d (bytes into file)\n", header->e_phoff);
    
    // print number of program headers
    printf("  Number of program headers:     %d\n", header->e_phnum);
    
    // print size of each program header entry
    printf("  Size of program headers:       %d (bytes)\n", header->e_phentsize);
    
    // debug mode: print extra info like shstrndx
    if (debug_mode) {
        printf("\n  [DEBUG] Section header string table index: %d\n", header->e_shstrndx);
        printf("  [DEBUG] File size: %zu bytes\n", elf->file_size);
    }
}

/*
 * Examine ELF File - Part 0
 * Opens a file, maps it with mmap, verifies it's an ELF file, prints header info
 */
void examine_elf_file() {
    char filename[256];
    int slot;
    int fd;
    off_t fsize; // Changed from using struct stat to off_t
    void *map;
    Elf32_Ehdr *header;
    
    // find an empty slot for the new file
    slot = find_empty_slot();
    if (slot == -1) {
        printf("Error: Maximum number of ELF files (%d) already open.\n", MAX_ELF_FILES);
        printf("Close some files or quit and restart.\n");
        return;
    }
    
    // ask user for filename
    printf("Enter ELF file name: ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
        printf("Error reading filename\n");
        return;
    }
    
    // remove newline character from filename
    filename[strcspn(filename, "\n")] = '\0';
    
    // open the file for reading
    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        printf("Error: Cannot open file '%s'\n", filename);
        return;
    }
    
    // FIX: Use lseek instead of fstat to determine file size.
    // This avoids EOVERFLOW errors on 64-bit filesystems when using -m32
    fsize = lseek(fd, 0, SEEK_END);
    if (fsize == -1) {
        printf("Error: Cannot get file size\n");
        close(fd);
        return;
    }
    // Rewind back to the beginning so the file descriptor is clean (optional for mmap but good practice)
    lseek(fd, 0, SEEK_SET);

    
    // map the entire file into memory using mmap
    // PROT_READ = we only need to read it
    // MAP_PRIVATE = changes won't affect original file
    map = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        printf("Error: Cannot map file to memory\n");
        close(fd);
        return;
    }
    
    // check if this is a valid ELF file by checking magic number
    header = (Elf32_Ehdr *)map;
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||   // 0x7f
        header->e_ident[EI_MAG1] != ELFMAG1 ||   // 'E'
        header->e_ident[EI_MAG2] != ELFMAG2 ||   // 'L'
        header->e_ident[EI_MAG3] != ELFMAG3) {   // 'F'
        printf("Error: '%s' is not a valid ELF file (bad magic number)\n", filename);
        munmap(map, fsize);
        close(fd);
        return;
    }
    
    // check if it's a 32-bit ELF file (we only support 32-bit)
    if (header->e_ident[EI_CLASS] != ELFCLASS32) {
        printf("Error: '%s' is not a 32-bit ELF file\n", filename);
        munmap(map, fsize);
        close(fd);
        return;
    }
    
    // all good! save the file info in our array
    elf_files[slot].fd = fd;
    elf_files[slot].map_start = map;
    elf_files[slot].file_size = fsize;
    strncpy(elf_files[slot].filename, filename, sizeof(elf_files[slot].filename) - 1);
    elf_files[slot].filename[sizeof(elf_files[slot].filename) - 1] = '\0';
    
    printf("File '%s' opened successfully (slot %d)\n", filename, slot);
    
    // print the ELF header information
    print_elf_header(&elf_files[slot]);
}

/*
 * Get section name from section header string table
 * shstrtab_offset: offset in file where .shstrtab section data starts
 * name_offset: offset within .shstrtab where our string starts
 */
char* get_section_name(void *map_start, Elf32_Ehdr *header, int name_offset) {
    // find section header string table section
    Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)map_start + header->e_shoff);
    Elf32_Shdr *shstrtab = &shdr_table[header->e_shstrndx];
    
    // return pointer to the name string
    return (char *)map_start + shstrtab->sh_offset + name_offset;
}

/*
 * Print Section Names - Part 1
 * For each open ELF file, print all section headers info
 */
void print_section_names() {
    int i, j;
    int found_any = 0;
    
    // loop through all possible ELF file slots
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (elf_files[i].fd == -1) continue;  // skip empty slots
        
        found_any = 1;
        
        // get pointers to header and section header table
        Elf32_Ehdr *header = (Elf32_Ehdr *)elf_files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf_files[i].map_start + header->e_shoff);
        
        printf("\nFile %s\n", elf_files[i].filename);
        
        // debug: print shstrndx
        if (debug_mode) {
            printf("[DEBUG] shstrndx = %d\n", header->e_shstrndx);
            printf("[DEBUG] Section header table offset = %d\n", header->e_shoff);
        }
        
        // print header for the table
        printf("[index] %-20s %-10s %-10s %-10s %-10s\n", 
               "section_name", "address", "offset", "size", "type");
        
        // loop through all section headers
        for (j = 0; j < header->e_shnum; j++) {
            Elf32_Shdr *shdr = &shdr_table[j];
            
            // get section name from .shstrtab
            char *name = get_section_name(elf_files[i].map_start, header, shdr->sh_name);
            
            // debug: print name offset
            if (debug_mode) {
                printf("[DEBUG] Section %d name offset: %d\n", j, shdr->sh_name);
            }
            
            // print section info
            printf("[%2d]   %-20s %08x   %06x     %06x     %d\n",
                   j,
                   name,
                   shdr->sh_addr,      // virtual address
                   shdr->sh_offset,    // file offset
                   shdr->sh_size,      // section size
                   shdr->sh_type);     // section type
        }
    }
    
    if (!found_any) {
        printf("Error: No ELF files are currently open.\n");
        printf("Use 'Examine ELF File' to open a file first.\n");
    }
}

/*
 * Find a section by name in an ELF file
 * Returns pointer to section header, or NULL if not found
 */
Elf32_Shdr* find_section_by_name(ElfFile *elf, const char *name) {
    Elf32_Ehdr *header = (Elf32_Ehdr *)elf->map_start;
    Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf->map_start + header->e_shoff);
    int i;
    
    for (i = 0; i < header->e_shnum; i++) {
        char *sec_name = get_section_name(elf->map_start, header, shdr_table[i].sh_name);
        if (strcmp(sec_name, name) == 0) {
            return &shdr_table[i];
        }
    }
    return NULL;  // not found
}

/*
 * Find a section by type in an ELF file
 * Returns pointer to section header, or NULL if not found
 */
Elf32_Shdr* find_section_by_type(ElfFile *elf, Elf32_Word type) {
    Elf32_Ehdr *header = (Elf32_Ehdr *)elf->map_start;
    Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf->map_start + header->e_shoff);
    int i;
    
    for (i = 0; i < header->e_shnum; i++) {
        if (shdr_table[i].sh_type == type) {
            return &shdr_table[i];
        }
    }
    return NULL;
}

/*
 * Get symbol name from symbol string table (.strtab)
 */
char* get_symbol_name(ElfFile *elf, Elf32_Shdr *symtab, int name_offset) {
    // find the string table linked to this symbol table
    Elf32_Ehdr *header = (Elf32_Ehdr *)elf->map_start;
    Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf->map_start + header->e_shoff);
    
    // sh_link in symtab points to the string table section index
    Elf32_Shdr *strtab = &shdr_table[symtab->sh_link];
    
    return (char *)elf->map_start + strtab->sh_offset + name_offset;
}

/*
 * Print Symbols - Part 2a
 * For each open ELF file, print all symbols from symbol table
 */
void print_symbols() {
    int i, j;
    int found_any = 0;
    
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (elf_files[i].fd == -1) continue;
        
        found_any = 1;
        
        Elf32_Ehdr *header = (Elf32_Ehdr *)elf_files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf_files[i].map_start + header->e_shoff);
        
        printf("\nFile %s\n", elf_files[i].filename);
        
        // find symbol table section (type SHT_SYMTAB)
        Elf32_Shdr *symtab = find_section_by_type(&elf_files[i], SHT_SYMTAB);
        if (symtab == NULL) {
            printf("No symbol table found in this file.\n");
            continue;
        }
        
        // get pointer to symbol table data
        Elf32_Sym *symbols = (Elf32_Sym *)((char *)elf_files[i].map_start + symtab->sh_offset);
        
        // calculate number of symbols
        int num_symbols = symtab->sh_size / symtab->sh_entsize;
        
        if (debug_mode) {
            printf("[DEBUG] Symbol table size: %d bytes\n", symtab->sh_size);
            printf("[DEBUG] Symbol entry size: %d bytes\n", symtab->sh_entsize);
            printf("[DEBUG] Number of symbols: %d\n", num_symbols);
        }
        
        // print header
        printf("[index] %-10s %-15s %-20s %-20s\n", 
               "value", "section_index", "section_name", "symbol_name");
        
        // loop through all symbols
        for (j = 0; j < num_symbols; j++) {
            Elf32_Sym *sym = &symbols[j];
            
            // get symbol name
            char *sym_name = get_symbol_name(&elf_files[i], symtab, sym->st_name);
            
            // get section name where symbol is defined
            char *sec_name = "";
            if (sym->st_shndx == SHN_UNDEF) {
                sec_name = "UND";  // undefined
            } else if (sym->st_shndx == SHN_ABS) {
                sec_name = "ABS";  // absolute
            } else if (sym->st_shndx < header->e_shnum) {
                sec_name = get_section_name(elf_files[i].map_start, header, 
                                            shdr_table[sym->st_shndx].sh_name);
            }
            
            printf("[%2d]   %08x   %-15d %-20s %s\n",
                   j,
                   sym->st_value,
                   sym->st_shndx,
                   sec_name,
                   sym_name);
        }
    }
    
    if (!found_any) {
        printf("Error: No ELF files are currently open.\n");
    }
}

/*
 * Print Relocations - Part 2b
 * For each open ELF file, print all relocation entries
 */
void print_relocations() {
    int i, j, k;
    int found_any = 0;
    
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (elf_files[i].fd == -1) continue;
        
        found_any = 1;
        
        Elf32_Ehdr *header = (Elf32_Ehdr *)elf_files[i].map_start;
        Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf_files[i].map_start + header->e_shoff);
        
        printf("\nFile %s relocations\n", elf_files[i].filename);
        
        // first find the symbol table (needed to get symbol names)
        Elf32_Shdr *symtab = find_section_by_type(&elf_files[i], SHT_SYMTAB);
        if (symtab == NULL) {
            printf("No symbol table found.\n");
            continue;
        }
        Elf32_Sym *symbols = (Elf32_Sym *)((char *)elf_files[i].map_start + symtab->sh_offset);
        
        int found_relocs = 0;
        
        // loop through all sections looking for relocation sections
        for (j = 0; j < header->e_shnum; j++) {
            Elf32_Shdr *shdr = &shdr_table[j];
            
            // check if this is a relocation section (SHT_REL or SHT_RELA)
            if (shdr->sh_type != SHT_REL && shdr->sh_type != SHT_RELA) {
                continue;
            }
            
            found_relocs = 1;
            
            char *sec_name = get_section_name(elf_files[i].map_start, header, shdr->sh_name);
            printf("\nRelocation section '%s':\n", sec_name);
            
            if (debug_mode) {
                printf("[DEBUG] Relocation section size: %d bytes\n", shdr->sh_size);
                printf("[DEBUG] Relocation entry size: %d bytes\n", shdr->sh_entsize);
            }
            
            // handle SHT_REL type (no addend)
            if (shdr->sh_type == SHT_REL) {
                Elf32_Rel *relocs = (Elf32_Rel *)((char *)elf_files[i].map_start + shdr->sh_offset);
                int num_relocs = shdr->sh_size / shdr->sh_entsize;
                
                printf("[index] %-10s %-20s %-6s %-10s\n", "location", "symbol_name", "size", "type");
                
                for (k = 0; k < num_relocs; k++) {
                    Elf32_Rel *rel = &relocs[k];
                    
                    // extract symbol index and relocation type from r_info
                    int sym_idx = ELF32_R_SYM(rel->r_info);
                    int rel_type = ELF32_R_TYPE(rel->r_info);
                    
                    // get symbol name
                    char *sym_name = get_symbol_name(&elf_files[i], symtab, symbols[sym_idx].st_name);
                    
                    // determine size based on relocation type (for x86)
                    int size = 4;  // most x86 relocations are 4 bytes
                    if (rel_type == R_386_8 || rel_type == R_386_PC8) {
                        size = 1;
                    } else if (rel_type == R_386_16 || rel_type == R_386_PC16) {
                        size = 2;
                    }
                    
                    printf("[%2d]   %08x   %-20s %-6d %d\n",
                           k,
                           rel->r_offset,
                           sym_name,
                           size,
                           rel_type);
                }
            }
            // handle SHT_RELA type (with addend)
            else if (shdr->sh_type == SHT_RELA) {
                Elf32_Rela *relocs = (Elf32_Rela *)((char *)elf_files[i].map_start + shdr->sh_offset);
                int num_relocs = shdr->sh_size / shdr->sh_entsize;
                
                printf("[index] %-10s %-20s %-6s %-10s\n", "location", "symbol_name", "size", "type");
                
                for (k = 0; k < num_relocs; k++) {
                    Elf32_Rela *rel = &relocs[k];
                    
                    int sym_idx = ELF32_R_SYM(rel->r_info);
                    int rel_type = ELF32_R_TYPE(rel->r_info);
                    
                    char *sym_name = get_symbol_name(&elf_files[i], symtab, symbols[sym_idx].st_name);
                    
                    int size = 4;
                    
                    printf("[%2d]   %08x   %-20s %-6d %d\n",
                           k,
                           rel->r_offset,
                           sym_name,
                           size,
                           rel_type);
                }
            }
        }
        
        if (!found_relocs) {
            printf("No relocations in this file.\n");
        }
    }
    
    if (!found_any) {
        printf("Error: No ELF files are currently open.\n");
    }
}

/*
 * Find a symbol by name in a symbol table
 * Returns pointer to symbol, or NULL if not found
 */
Elf32_Sym* find_symbol_by_name(ElfFile *elf, Elf32_Shdr *symtab, const char *name) {
    Elf32_Sym *symbols = (Elf32_Sym *)((char *)elf->map_start + symtab->sh_offset);
    int num_symbols = symtab->sh_size / symtab->sh_entsize;
    int i;
    
    for (i = 0; i < num_symbols; i++) {
        char *sym_name = get_symbol_name(elf, symtab, symbols[i].st_name);
        if (strcmp(sym_name, name) == 0) {
            return &symbols[i];
        }
    }
    return NULL;
}

/*
 * Count symbol tables in an ELF file
 */
int count_symbol_tables(ElfFile *elf) {
    Elf32_Ehdr *header = (Elf32_Ehdr *)elf->map_start;
    Elf32_Shdr *shdr_table = (Elf32_Shdr *)((char *)elf->map_start + header->e_shoff);
    int count = 0;
    int i;
    
    for (i = 0; i < header->e_shnum; i++) {
        if (shdr_table[i].sh_type == SHT_SYMTAB) {
            count++;
        }
    }
    return count;
}

/*
 * Check Files for Merge - Part 3.1
 * Verifies that two ELF files can be merged:
 * - Checks for undefined symbols
 * - Checks for multiply defined symbols
 */
void check_files_for_merge() {
    int i;
    int error_count = 0;
    
    // check that we have exactly 2 ELF files open
    int open_count = 0;
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (elf_files[i].fd != -1) open_count++;
    }
    
    if (open_count != 2) {
        printf("Error: Need exactly 2 ELF files open for merge check.\n");
        printf("Currently have %d file(s) open.\n", open_count);
        return;
    }
    
    // check that each file has exactly one symbol table
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (elf_files[i].fd == -1) continue;
        int symtab_count = count_symbol_tables(&elf_files[i]);
        if (symtab_count != 1) {
            printf("Error: Feature not supported - file %s has %d symbol tables (expected 1)\n",
                   elf_files[i].filename, symtab_count);
            return;
        }
    }
    
    printf("\nChecking files for merge compatibility...\n");
    
    // get references to both files
    ElfFile *file1 = &elf_files[0];
    ElfFile *file2 = &elf_files[1];
    
    // get symbol tables for both files
    Elf32_Shdr *symtab1 = find_section_by_type(file1, SHT_SYMTAB);
    Elf32_Shdr *symtab2 = find_section_by_type(file2, SHT_SYMTAB);
    
    Elf32_Sym *symbols1 = (Elf32_Sym *)((char *)file1->map_start + symtab1->sh_offset);
    Elf32_Sym *symbols2 = (Elf32_Sym *)((char *)file2->map_start + symtab2->sh_offset);
    
    int num_symbols1 = symtab1->sh_size / symtab1->sh_entsize;
    int num_symbols2 = symtab2->sh_size / symtab2->sh_entsize;
    
    if (debug_mode) {
        printf("[DEBUG] File 1 has %d symbols\n", num_symbols1);
        printf("[DEBUG] File 2 has %d symbols\n", num_symbols2);
    }
    
    // check symbols in file 1 against file 2
    printf("\nChecking symbols from %s:\n", file1->filename);
    for (i = 1; i < num_symbols1; i++) {  // skip symbol 0 (null symbol)
        Elf32_Sym *sym1 = &symbols1[i];
        char *sym_name = get_symbol_name(file1, symtab1, sym1->st_name);
        
        // skip empty names and section/file symbols
        if (strlen(sym_name) == 0) continue;
        if (ELF32_ST_TYPE(sym1->st_info) == STT_SECTION) continue;
        if (ELF32_ST_TYPE(sym1->st_info) == STT_FILE) continue;
        
        // look for this symbol in file 2
        Elf32_Sym *sym2 = find_symbol_by_name(file2, symtab2, sym_name);
        
        // case 1: symbol undefined in file 1
        if (sym1->st_shndx == SHN_UNDEF) {
            // check if also undefined or not found in file 2
            if (sym2 == NULL || sym2->st_shndx == SHN_UNDEF) {
                printf("Symbol %s undefined\n", sym_name);
                error_count++;
            }
        }
        // case 2: symbol defined in file 1
        else {
            // check if also defined in file 2
            if (sym2 != NULL && sym2->st_shndx != SHN_UNDEF) {
                printf("Symbol %s multiply defined\n", sym_name);
                error_count++;
            }
        }
    }
    
    // check symbols in file 2 against file 1
    printf("\nChecking symbols from %s:\n", file2->filename);
    for (i = 1; i < num_symbols2; i++) {
        Elf32_Sym *sym2 = &symbols2[i];
        char *sym_name = get_symbol_name(file2, symtab2, sym2->st_name);
        
        if (strlen(sym_name) == 0) continue;
        if (ELF32_ST_TYPE(sym2->st_info) == STT_SECTION) continue;
        if (ELF32_ST_TYPE(sym2->st_info) == STT_FILE) continue;
        
        Elf32_Sym *sym1 = find_symbol_by_name(file1, symtab1, sym_name);
        
        if (sym2->st_shndx == SHN_UNDEF) {
            if (sym1 == NULL || sym1->st_shndx == SHN_UNDEF) {
                printf("Symbol %s undefined\n", sym_name);
                error_count++;
            }
        }
        else {
            if (sym1 != NULL && sym1->st_shndx != SHN_UNDEF) {
                printf("Symbol %s multiply defined\n", sym_name);
                error_count++;
            }
        }
    }
    
    if (error_count == 0) {
        printf("\nMerge check passed! No errors found.\n");
    } else {
        printf("\nMerge check completed with %d error(s).\n", error_count);
    }
}

/*
 * Helper function to check if a section should be merged (concatenated)
 */
int is_mergeable_section(const char *name) {
    return (strcmp(name, ".text") == 0 ||
            strcmp(name, ".data") == 0 ||
            strcmp(name, ".rodata") == 0);
}

/*
 * Merge ELF Files - Part 3.2
 * Creates a new ELF file "out.ro" by merging two open ELF files
 */
void merge_elf_files() {
    int i;
    int out_fd;
    Elf32_Off current_offset;
    
    // check that we have exactly 2 files open
    int open_count = 0;
    for (i = 0; i < MAX_ELF_FILES; i++) {
        if (elf_files[i].fd != -1) open_count++;
    }
    
    if (open_count != 2) {
        printf("Error: Need exactly 2 ELF files open for merge.\n");
        return;
    }
    
    ElfFile *file1 = &elf_files[0];
    ElfFile *file2 = &elf_files[1];
    
    Elf32_Ehdr *header1 = (Elf32_Ehdr *)file1->map_start;
    
    Elf32_Shdr *shdr_table1 = (Elf32_Shdr *)((char *)file1->map_start + header1->e_shoff);
    
    printf("Merging %s and %s into out.ro...\n", file1->filename, file2->filename);
    
    // create output file
    out_fd = open("out.ro", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd == -1) {
        printf("Error: Cannot create output file 'out.ro'\n");
        return;
    }
    
    // step 1: copy ELF header from file 1 (will update e_shoff later)
    Elf32_Ehdr out_header;
    memcpy(&out_header, header1, sizeof(Elf32_Ehdr));
    write(out_fd, &out_header, sizeof(Elf32_Ehdr));
    current_offset = sizeof(Elf32_Ehdr);
    
    if (debug_mode) {
        printf("[DEBUG] Wrote ELF header, offset now: %d\n", current_offset);
    }
    
    // step 2: create a copy of section header table from file 1
    // we'll modify offsets and sizes as we go
    int num_sections = header1->e_shnum;
    Elf32_Shdr *new_shdr_table = malloc(num_sections * sizeof(Elf32_Shdr));
    memcpy(new_shdr_table, shdr_table1, num_sections * sizeof(Elf32_Shdr));
    
    // step 3: loop through sections and write them, updating headers
    for (i = 0; i < num_sections; i++) {
        Elf32_Shdr *shdr = &new_shdr_table[i];
        char *sec_name = get_section_name(file1->map_start, header1, shdr->sh_name);
        
        // skip null section (section 0)
        if (shdr->sh_type == SHT_NULL) {
            continue;
        }
        
        // skip NOBITS sections (like .bss) - they have no data
        if (shdr->sh_type == SHT_NOBITS) {
            // for .bss, we might need to merge sizes
            if (is_mergeable_section(sec_name)) {
                Elf32_Shdr *sec2 = find_section_by_name(file2, sec_name);
                if (sec2 != NULL) {
                    shdr->sh_size += sec2->sh_size;
                }
            }
            continue;
        }
        
        // update offset to current position
        shdr->sh_offset = current_offset;
        
        // get pointer to section data in file 1
        void *sec_data1 = (char *)file1->map_start + shdr_table1[i].sh_offset;
        Elf32_Word sec_size1 = shdr_table1[i].sh_size;
        
        // check if this section should be merged (concatenated)
        if (is_mergeable_section(sec_name)) {
            // write section data from file 1
            write(out_fd, sec_data1, sec_size1);
            current_offset += sec_size1;
            
            if (debug_mode) {
                printf("[DEBUG] Wrote %s from file1, size: %d\n", sec_name, sec_size1);
            }
            
            // find same section in file 2 and append its data
            Elf32_Shdr *sec2 = find_section_by_name(file2, sec_name);
            if (sec2 != NULL && sec2->sh_size > 0) {
                void *sec_data2 = (char *)file2->map_start + sec2->sh_offset;
                write(out_fd, sec_data2, sec2->sh_size);
                current_offset += sec2->sh_size;
                
                // update size in section header to combined size
                shdr->sh_size = sec_size1 + sec2->sh_size;
                
                if (debug_mode) {
                    printf("[DEBUG] Appended %s from file2, size: %d, total: %d\n", 
                           sec_name, sec2->sh_size, shdr->sh_size);
                }
            }
        }
        else {
            // non-mergeable section: just copy from file 1
            write(out_fd, sec_data1, sec_size1);
            current_offset += sec_size1;
            
            if (debug_mode) {
                printf("[DEBUG] Copied %s as-is, size: %d\n", sec_name, sec_size1);
            }
        }
    }
    
    // step 4: write the section header table
    Elf32_Off shoff = current_offset;  // save offset where we write section headers
    write(out_fd, new_shdr_table, num_sections * sizeof(Elf32_Shdr));
    
    if (debug_mode) {
        printf("[DEBUG] Wrote section header table at offset: %d\n", shoff);
    }
    
    // step 5: go back and fix e_shoff in ELF header
    lseek(out_fd, 0, SEEK_SET);
    out_header.e_shoff = shoff;
    write(out_fd, &out_header, sizeof(Elf32_Ehdr));
    
    // cleanup
    free(new_shdr_table);
    close(out_fd);
    
    printf("Merge complete! Output written to 'out.ro'\n");
    printf("You can verify with: readelf -S out.ro\n");
    printf("To create executable: ld -m elf_i386 out.ro -o out\n");
}

/*
 * Quit program - cleanup and exit
 */
void quit_program() {
    printf("Cleaning up and exiting...\n");
    close_all_elf_files();
    exit(0);
}

/*
 * Display the menu and get user choice
 */
int display_menu() {
    int i;
    int choice;
    char input[16];
    
    printf("\n");
    printf("Choose action:\n");
    for (i = 0; i < MENU_SIZE; i++) {
        printf("%d-%s\n", i, menu[i].name);
    }
    printf("> ");
    
    // read user input
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return -1;
    }
    
    // parse the choice
    if (sscanf(input, "%d", &choice) != 1) {
        return -1;
    }
    
    return choice;
}

/*
 * Main function - program entry point
 */
int main(int argc, char *argv[]) {
    int choice;
    
    // initialize our ELF file tracking array
    init_elf_files();
    
    printf("=================================\n");
    printf("  myELF - ELF File Linker Tool\n");
    printf("  Lab E: Linking ELF Object Files\n");
    printf("=================================\n");
    
    // main program loop
    while (1) {
        choice = display_menu();
        
        // check for valid choice
        if (choice < 0 || choice >= MENU_SIZE) {
            printf("Invalid option. Please try again.\n");
            continue;
        }
        
        // call the selected function
        menu[choice].func();
    }
    
    return 0;
}