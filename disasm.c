#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <capstone.h>

#include "gbadisasm.h"

#define ROM_LOAD_ADDR 0x08000000
#define UNKNOWN_SIZE (uint32_t)-1

struct LabelName
{
    uint32_t addr;
    char *name;
};

enum BranchType
{
    BRANCH_TYPE_UNKNOWN,
    BRANCH_TYPE_B,
    BRANCH_TYPE_BL,
};

struct Label
{
    uint32_t addr;
    uint8_t type;
    uint8_t branchType;
    uint32_t size;
    bool processed;
};

static struct LabelName *sLabelNames = NULL;
static int sLabelNamesCount = 0;
struct Label *gLabels = NULL;
int gLabelsCount = 0;
static csh sCapstone;

const bool gOptionShowAddrComments = false;
const int gOptionDataColumnWidth = 16;

void disasm_add_name(uint32_t addr, const char *name)
{
    int i;
    int namelen;
    char *name_;

    namelen = strlen(name);
    name_ = malloc(namelen + 1);
    name_[namelen] = '\0';

    // Search for label
    for (i = 0; i < sLabelNamesCount; i++)
    {
        if (sLabelNames[i].addr == addr)
        {
            free(sLabelNames[i].name);
            sLabelNames[i].name = name_;
            return;
        }
    }
    
    i = sLabelNamesCount++;
    sLabelNames = realloc(sLabelNames, sLabelNamesCount * sizeof(*sLabelNames));
    sLabelNames[i].addr = addr;
    sLabelNames[i].name = name_;
}

int disasm_add_label(uint32_t addr, uint8_t type)
{
    int i;

    //printf("adding label 0x%08X\n", addr);
    // Search for label
    //assert(addr >= ROM_LOAD_ADDR && addr < ROM_LOAD_ADDR + gInputFileBufferSize);
    for (i = 0; i < gLabelsCount; i++)
    {
        if (gLabels[i].addr == addr)
        {
            gLabels[i].type = type;
            return i;
        }
    }

    i = gLabelsCount++;
    gLabels = realloc(gLabels, gLabelsCount * sizeof(*gLabels));
    gLabels[i].addr = addr;
    gLabels[i].type = type;
    gLabels[i].branchType = BRANCH_TYPE_UNKNOWN;
    gLabels[i].processed = false;
    gLabels[i].size = UNKNOWN_SIZE;
    return i;
}

static uint8_t byte_at(uint32_t addr)
{
    return gInputFileBuffer[addr - ROM_LOAD_ADDR];
}

static uint32_t word_at(uint32_t addr)
{
    return (byte_at(addr + 0) << 0)
         | (byte_at(addr + 1) << 8)
         | (byte_at(addr + 2) << 16)
         | (byte_at(addr + 3) << 24);
}

static int get_unprocessed_label_index(void)
{
    int i;

    for (i = 0; i < gLabelsCount; i++)
    {
        if (!gLabels[i].processed)
            return i;
    }
    return -1;
}

static bool is_branch(const struct cs_insn *insn)
{
    switch (insn->id)
    {
    case ARM_INS_B:
    case ARM_INS_BX:
    case ARM_INS_BL:
        return true;
    }
    return false;
}

static bool is_func_return(const struct cs_insn *insn)
{
    const struct cs_arm *arminsn = &insn->detail->arm;

    if (insn->id == ARM_INS_BX)
        return true;
    if (insn->id == ARM_INS_MOV
     && arminsn->operands[0].type == ARM_OP_REG
     && arminsn->operands[0].reg == ARM_REG_PC)
        return true;
    if (insn->id == ARM_INS_POP)
    {
        int i;

        assert(arminsn->op_count > 0);
        for (i = 0; i < arminsn->op_count; i++)
        {
            if (arminsn->operands[i].type == ARM_OP_REG
             && arminsn->operands[i].reg == ARM_REG_PC)
                return true;
        }
    }
    return false;
}

static uint32_t get_pool_load(const struct cs_insn *insn, uint32_t currAddr, int mode)
{
    const struct cs_arm *arminsn = &insn->detail->arm;

    if (insn->id == ARM_INS_LDR)
    {
        assert(arminsn->operands[0].type == ARM_OP_REG);
        if (arminsn->operands[1].type == ARM_OP_MEM
         && !arminsn->operands[1].subtracted
         && arminsn->operands[1].mem.base == ARM_REG_PC
         && arminsn->operands[1].mem.index == ARM_REG_INVALID)
        {
            return (currAddr & ~3) + arminsn->operands[1].mem.disp + ((mode == LABEL_ARM_CODE) ? 8 : 4);
        }
    }
    return 0;
}

static void analyze(void)
{
    while (1)
    {
        int li;
        int i;
        uint32_t addr;
        int type;
        struct cs_insn *insn;
        const int dismAllocSize = 0x1000;
        int count;

        if ((li = get_unprocessed_label_index()) == -1)
            return;
        addr = gLabels[li].addr;
        type = gLabels[li].type;

        if (type == LABEL_ARM_CODE || type == LABEL_THUMB_CODE)
        {
            cs_option(sCapstone, CS_OPT_MODE, (type == LABEL_ARM_CODE) ? CS_MODE_ARM : CS_MODE_THUMB);
            //printf("analyzing label at 0x%08X\n", addr);
            do
            {
                count = cs_disasm(sCapstone, gInputFileBuffer + addr - ROM_LOAD_ADDR, 0x1000, addr, 0, &insn);
                for (i = 0; i < count; i++)
                {
                    //printf("/*0x%08X*/ %s %s\n", addr, insn[i].mnemonic, insn[i].op_str);
                    if (is_branch(&insn[i]))
                    {
                        uint32_t target;
                        uint32_t currAddr = addr;

                        addr += insn[i].size;

                        if (is_func_return(&insn[i]))
                            break;

                        assert(insn[i].detail != NULL);
                        target = insn[i].detail->arm.operands[0].imm;
                        assert(target != 0);
                        //printf("branch target = 0x%08X\n", target);

                        if (!(target >= gLabels[li].addr && target <= currAddr))
                        {
                            int lbl = disasm_add_label(target, type);
                            
                            if (insn[i].id == ARM_INS_BL)
                            {
                                if (gLabels[lbl].branchType != BRANCH_TYPE_B)
                                    gLabels[lbl].branchType = BRANCH_TYPE_BL;
                            }
                            else
                            {
                                gLabels[lbl].branchType = BRANCH_TYPE_B;
                            }
                        }

                        // unconditional jump and not a function call
                        if (insn[i].detail->arm.cc == ARM_CC_AL && insn[i].id != ARM_INS_BL)
                            break;
                    }
                    else
                    {
                        uint32_t poolAddr;

                        addr += insn[i].size;

                        if (is_func_return(&insn[i]))
                            break;

                        assert(insn[i].detail != NULL);
                        poolAddr = get_pool_load(&insn[i], addr - insn[i].size, type);
                        if (poolAddr)
                        {
                            assert((poolAddr & 3) == 0);
                            disasm_add_label(poolAddr, LABEL_POOL);
                        }
                    }
                }
                cs_free(insn, count);
            } while (count == dismAllocSize);
            gLabels[li].processed = true;
            gLabels[li].size = addr - gLabels[li].addr;
        }
        gLabels[li].processed = true;
    }
}

static int qsort_label_compare(const void *a, const void *b)
{
    return ((struct Label *)a)->addr - ((struct Label *)b)->addr;
}

static void print_gap(uint32_t addr, uint32_t nextaddr)
{
    //uint32_t diff == nextaddr - addr;

    if (addr == nextaddr)
        return;
    
    assert(addr < nextaddr);
    if (addr % gOptionDataColumnWidth != 0)
        fputs("\t.byte", stdout);
    while (addr < nextaddr)
    {
        if (addr % gOptionDataColumnWidth == 0)
            fputs("\t.byte", stdout);
        if (addr % gOptionDataColumnWidth == (unsigned int)(gOptionDataColumnWidth - 1)
         || addr == nextaddr - 1)
            printf(" 0x%02X\n", byte_at(addr));
        else
            printf(" 0x%02X,", byte_at(addr));
        addr++;
    }
}

static void print_disassembly(void)
{
    uint32_t addr = ROM_LOAD_ADDR;
    int i = 0;

    qsort(gLabels, gLabelsCount, sizeof(*gLabels), qsort_label_compare);

    for (i = 0; i < gLabelsCount - 1; i++)
        assert(gLabels[i].addr < gLabels[i + 1].addr);
    for (i = 0; i < gLabelsCount; i++)
    {
        if (gLabels[i].type == LABEL_ARM_CODE || gLabels[i].type == LABEL_THUMB_CODE)
        {
            assert(gLabels[i].processed);
            //assert(gLabels[i].size != UNKNOWN_SIZE);
        }
    }

    i = 0;
    while (addr < ROM_LOAD_ADDR + gInputFileBufferSize)
    {
        uint32_t nextAddr;

        // TODO: compute actual size during analysis phase
        if (i + 1 < gLabelsCount)
        {
            if (gLabels[i].size == UNKNOWN_SIZE
             || gLabels[i].addr + gLabels[i].size > gLabels[i + 1].addr)
                gLabels[i].size = gLabels[i + 1].addr - gLabels[i].addr;
        }

        switch (gLabels[i].type)
        {
        case LABEL_ARM_CODE:
        case LABEL_THUMB_CODE:
            {
                struct cs_insn *insn;
                int count;
                int j;
                int mode = (gLabels[i].type == LABEL_ARM_CODE) ? CS_MODE_ARM : CS_MODE_THUMB;

                if (gLabels[i].branchType == BRANCH_TYPE_BL)
                {
                    if (addr & 3)
                    {
                        printf("error: function at 0x%08X is not aligned\n", addr);
                        return;
                    }
                    printf("\n\t%s sub_%08X\n",
                      (gLabels[i].type == LABEL_ARM_CODE) ? "ARM_FUNC_START" : "THUMB_FUNC_START", addr);
                    printf("sub_%08X: @ 0x%08X\n", addr, addr);
                }
                else
                {
                    printf("_%08X:\n", addr);
                }

                assert(gLabels[i].size != UNKNOWN_SIZE);
                cs_option(sCapstone, CS_OPT_MODE, mode);
                count = cs_disasm(sCapstone, gInputFileBuffer + addr - ROM_LOAD_ADDR, gLabels[i].size, addr, 0, &insn);
                for (j = 0; j < count; j++)
                {
                    if (gOptionShowAddrComments)
                        printf("\t/*0x%08X*/ %s %s\n", addr, insn[j].mnemonic, insn[j].op_str);
                    else
                        printf("\t%s %s\n", insn[j].mnemonic, insn[j].op_str);
                    addr += insn[j].size;
                }
                cs_free(insn, count);
                
                // align pool if it comes next
                if (i + 1 < gLabelsCount && gLabels[i + 1].type == LABEL_POOL)
                {
                    const uint8_t zeros[3] = {0};
                    int diff = gLabels[i + 1].addr - addr;
                    if (diff == 0
                     || (diff > 0 && diff < 4 && memcmp(gInputFileBuffer + addr - ROM_LOAD_ADDR, zeros, diff) == 0))
                    {
                        puts("\t.align 2, 0");
                        addr += diff;
                    }
                }
            }
            break;
        case LABEL_POOL:
            assert(gLabels[i].size = 4);
            printf("_%08X: .4byte %08X @ pool\n", addr, word_at(addr));
            addr += 4;
            break;
        }

        i++;
        if (i >= gLabelsCount)
            break;
        nextAddr = gLabels[i].addr;
        assert(addr <= nextAddr);

        print_gap(addr, nextAddr);
        addr = nextAddr;
    }
}

void disasm_disassemble(void)
{
    // initialize capstone
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &sCapstone) != CS_ERR_OK)
    {
        puts("cs_open failed");
        return;
    }
    cs_option(sCapstone, CS_OPT_DETAIL, CS_OPT_ON);

/*
    // custom labels
    disasm_add_label(0x0800D42C, LABEL_THUMB_CODE);
    disasm_add_label(0x0800D684, LABEL_THUMB_CODE);
    disasm_add_label(0x081018A0, LABEL_THUMB_CODE);
    disasm_add_label(0x0800024c, LABEL_THUMB_CODE);
*/

    // entry point
    disasm_add_label(0x08000000, LABEL_ARM_CODE);

    // rom header
    disasm_add_label(0x08000004, LABEL_DATA);

    analyze();
    print_disassembly();
    free(gLabels);
}
