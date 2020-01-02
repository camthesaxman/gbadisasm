#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <capstone.h>

#include "gbadisasm.h"

uint32_t ROM_LOAD_ADDR;
#define UNKNOWN_SIZE (uint32_t)-1

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
    char *name;
};

struct Label *gLabels = NULL;
int gLabelsCount = 0;
static csh sCapstone;

const bool gOptionShowAddrComments = false;
const int gOptionDataColumnWidth = 16;

int disasm_add_label(uint32_t addr, uint8_t type, char *name)
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
    if (type == LABEL_ARM_CODE || type == LABEL_THUMB_CODE)
        gLabels[i].branchType = BRANCH_TYPE_BL;  // assume it's the start of a function
    else
        gLabels[i].branchType = BRANCH_TYPE_UNKNOWN;
    gLabels[i].size = UNKNOWN_SIZE;
    gLabels[i].processed = false;
    gLabels[i].name = name;
    return i;
}

// Utility Functions

static struct Label *lookup_label(uint32_t addr)
{
    int i;

    for (i = 0; i < gLabelsCount; i++)
    {
        if (gLabels[i].addr == addr)
            return &gLabels[i];
    }
    return NULL;
}

static uint8_t byte_at(uint32_t addr)
{
    return gInputFileBuffer[addr - ROM_LOAD_ADDR];
}

static uint16_t hword_at(uint32_t addr)
{
    return (byte_at(addr + 0) << 0)
         | (byte_at(addr + 1) << 8);
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

    // 'bx' instruction
    if (insn->id == ARM_INS_BX)
        return arminsn->cc == ARM_CC_AL;
    // 'mov' with pc as the destination
    if (insn->id == ARM_INS_MOV
     && arminsn->operands[0].type == ARM_OP_REG
     && arminsn->operands[0].reg == ARM_REG_PC)
        return true;
    // 'pop' with pc in the register list
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

static bool is_pool_load(const struct cs_insn *insn)
{
    const struct cs_arm *arminsn = &insn->detail->arm;

    if (insn->id == ARM_INS_LDR
     && arminsn->operands[0].type == ARM_OP_REG
     && arminsn->operands[1].type == ARM_OP_MEM
     && !arminsn->operands[1].subtracted
     && arminsn->operands[1].mem.base == ARM_REG_PC
     && arminsn->operands[1].mem.index == ARM_REG_INVALID)
        return true;
    else
        return false;
}

static uint32_t get_pool_load(const struct cs_insn *insn, uint32_t currAddr, int mode)
{
    assert(is_pool_load(insn));

    return (currAddr & ~3) + insn->detail->arm.operands[1].mem.disp + ((mode == LABEL_ARM_CODE) ? 8 : 4);
}

static uint32_t get_branch_target(const struct cs_insn *insn)
{
    assert(is_branch(insn));
    assert(insn->detail != NULL);

    return insn->detail->arm.operands[0].imm;
}

// Code Analysis

static int sJumpTableState = 0;

static void jump_table_state_machine(const struct cs_insn *insn, uint32_t addr)
{
    static uint32_t jumpTableBegin;
    // sometimes another instruction (like a mov) can interrupt
    static bool gracePeriod;
    static uint32_t poolAddr;

    switch (sJumpTableState)
    {
      case 0:
        // "lsl rX, rX, 2"
        gracePeriod = false;
        if (insn->id == ARM_INS_LSL)
            goto match;
        break;
      case 1:
        // "ldr rX, [pc, ?]"
        if (is_pool_load(insn))
        {
            poolAddr = get_pool_load(insn, addr, LABEL_THUMB_CODE);
            jumpTableBegin = word_at(poolAddr);
            goto match;
        }
        break;
      case 2:
        // "add rX, rX, rX"
        if (insn->id == ARM_INS_ADD)
            goto match;
        break;
      case 3:
        // "ldr rX, [rX]"
        if (insn->id == ARM_INS_LDR)
            goto match;
        break;
      case 4:
        // "mov pc, rX"
        if (insn->id == ARM_INS_MOV
         && insn->detail->arm.operands[0].type == ARM_OP_REG
         && insn->detail->arm.operands[0].reg == ARM_REG_PC)
            goto match;
        break;
    }

    // didn't match
    if (gracePeriod)
        sJumpTableState = 0;
    else
        gracePeriod = true;
    return;

  match:
    if (sJumpTableState == 4)  // all checks passed
    {
        uint32_t target;
        uint32_t firstTarget = -1u;

        // jump table is not in ROM, indicating it's from a library loaded into RAM
        if (!(jumpTableBegin & ROM_LOAD_ADDR))
        {
            uint32_t offset = poolAddr + 4 - jumpTableBegin;

            disasm_add_label(poolAddr + 4, LABEL_JUMP_TABLE, NULL);
            addr = poolAddr + 4; // start of jump table
            while (addr < word_at(poolAddr + 4) + offset)
            {
                int label;

                label = disasm_add_label(word_at(addr) + offset, LABEL_THUMB_CODE, NULL);
                gLabels[label].branchType = BRANCH_TYPE_B;
                addr += 4;
            }
            return;
        }

        disasm_add_label(jumpTableBegin, LABEL_JUMP_TABLE, NULL);
        sJumpTableState = 0;
        // add code labels from jump table
        addr = jumpTableBegin;
        while (addr < firstTarget)
        {
            int label;

            target = word_at(addr);
            if (target - ROM_LOAD_ADDR >= 0x02000000)
                break;
            if (target < firstTarget && target > jumpTableBegin)
                firstTarget = target;
            label = disasm_add_label(target, LABEL_THUMB_CODE, NULL);
            gLabels[label].branchType = BRANCH_TYPE_B;
            addr += 4;
        }

        return;
    }
    sJumpTableState++;
}

static bool IsValidInstruction(cs_insn * insn, int type)
{
    if (cs_insn_group(sCapstone, insn, ARM_GRP_V4T))
        return true;
    if (type == LABEL_ARM_CODE) {
        return cs_insn_group(sCapstone, insn, ARM_GRP_ARM);
    } else {
        return cs_insn_group(sCapstone, insn, ARM_GRP_THUMB);
    }
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
            sJumpTableState = 0;
            //fprintf(stderr, "analyzing label at 0x%08X\n", addr);
            do
            {
                count = cs_disasm(sCapstone, gInputFileBuffer + addr - ROM_LOAD_ADDR, 0x1000, addr, 0, &insn);
                for (i = 0; i < count; i++)
                {
                  no_inc:
                    if (!IsValidInstruction(&insn[i], type)) {
                        if (type == LABEL_THUMB_CODE)
                        {
                            int tmp_cnt;
                            cs_insn * tmp;
                            addr += 2;
                            if (insn[i].size == 2) continue;
                            tmp_cnt = cs_disasm(sCapstone, gInputFileBuffer + addr - ROM_LOAD_ADDR, 2, addr, 0, &tmp);
                            assert(tmp_cnt == 1);
                            free(insn[i].detail);
                            insn[i] = *tmp;
                            free(tmp);
                            goto no_inc;
                        }
                        else
                        {
                            addr += 4;
                            continue;
                        }
                    };
                    jump_table_state_machine(&insn[i], addr);

                    // fprintf(stderr, "/*0x%08X*/ %s %s\n", addr, insn[i].mnemonic, insn[i].op_str);
                    if (is_branch(&insn[i]))
                    {
                        uint32_t target;
                        //uint32_t currAddr = addr;

                        addr += insn[i].size;

                        // For BX{COND}, only BXAL can be considered as end of function
                        if (is_func_return(&insn[i]))
                            break;

                        if (insn[i].id == ARM_INS_BX) // BX{COND} when COND != AL
                            continue;

                        target = get_branch_target(&insn[i]);
                        assert(target != 0);

                        // I don't remember why I needed this condition
                        //if (!(target >= gLabels[li].addr && target <= currAddr))
                        if (1)
                        {
                            int lbl = disasm_add_label(target, type, NULL);

                            if (insn[i].id == ARM_INS_BL)
                            {
                                const struct Label *next;

                                if (gLabels[lbl].branchType != BRANCH_TYPE_B)
                                    gLabels[lbl].branchType = BRANCH_TYPE_BL;
                                // if the address right after is a pool, then we know
                                // for sure that this is a far jump and not a function call
                                if (((next = lookup_label(addr)) != NULL && next->type == LABEL_POOL)
                                // if the 2 bytes following are zero, assume it's padding
                                 || hword_at(addr) == 0)
                                {
                                    gLabels[lbl].branchType = BRANCH_TYPE_B;
                                    break;
                                }
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
                        if (is_pool_load(&insn[i]))
                        {
                            poolAddr = get_pool_load(&insn[i], addr - insn[i].size, type);
                            assert(poolAddr != 0);
                            assert((poolAddr & 3) == 0);
                            disasm_add_label(poolAddr, LABEL_POOL, NULL);
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

// Disassembly Output

static void print_gap(uint32_t addr, uint32_t nextaddr)
{
    if (addr == nextaddr)
        return;

    assert(addr < nextaddr);

    if ((addr & 3) == 2) {
        uint16_t next_short = hword_at(addr);
        if (next_short == 0) {
            fputs("\t.align 2, 0\n", stdout);
            addr += 2;
        } else if (next_short == 0x46C0) {
            fputs("\tnop\n", stdout);
            addr += 2;
        }
        if (addr == nextaddr) {
            return;
        }
    }

    printf("_%08X:\n", addr);
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

static void print_insn(const cs_insn *insn, uint32_t addr, int mode)
{
    if (gOptionShowAddrComments)
    {
        printf("\t/*0x%08X*/ %s %s\n", addr, insn->mnemonic, insn->op_str);
    }
    else
    {
        if (is_branch(insn) && insn->id != ARM_INS_BX)
        {
            uint32_t target = get_branch_target(insn);
            struct Label *label = lookup_label(target);

            assert(label != NULL);  // We should have found this label in the analysis phase
            if (label->name != NULL)
                printf("\t%s %s\n", insn->mnemonic, label-> name);
            else
                printf("\t%s %s_%08X\n", insn->mnemonic, label->branchType == BRANCH_TYPE_BL ? "sub" : "", target);
        }
        else if (is_pool_load(insn))
        {
            printf("\t%s %s, _%08X\n", insn->mnemonic, cs_reg_name(sCapstone, insn->detail->arm.operands[0].reg), get_pool_load(insn, addr, mode));
        }
        else
        {
            // fix "add rX, sp, rX"
            if (insn->id == ARM_INS_ADD
             && insn->detail->arm.operands[0].type == ARM_OP_REG
             && insn->detail->arm.operands[1].type == ARM_OP_REG
             && insn->detail->arm.operands[1].reg == ARM_REG_SP
             && insn->detail->arm.operands[2].type == ARM_OP_REG)
            {
                printf("\t%s %s, %s\n",
                  insn->mnemonic,
                  cs_reg_name(sCapstone, insn->detail->arm.operands[0].reg),
                  cs_reg_name(sCapstone, insn->detail->arm.operands[1].reg));
            }
            // fix adr
            else if (insn->id == ARM_INS_ADR)
            {
                printf("\tadd %s, pc, #0x%X\n",
                  cs_reg_name(sCapstone, insn->detail->arm.operands[0].reg),
                  insn->detail->arm.operands[1].imm);
            }
            else
                printf("\t%s %s\n", insn->mnemonic, insn->op_str);
        }
    }
}

static int qsort_label_compare(const void *a, const void *b)
{
    return ((struct Label *)a)->addr - ((struct Label *)b)->addr;
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
            assert(gLabels[i].processed);
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

                // This is a function. Use the 'sub_XXXXXXXX' label
                if (gLabels[i].branchType == BRANCH_TYPE_BL)
                {
                    unsigned int unalignedMask = (mode == CS_MODE_ARM) ? 3 : 1;

                    if (addr & unalignedMask)
                    {
                        printf("error: function at 0x%08X is not aligned\n", addr);
                        return;
                    }
                    if (gLabels[i].name != NULL)
                    {
                        printf("\n\t%s %s\n",
                          (gLabels[i].type == LABEL_ARM_CODE) ? "arm_func_start" : "thumb_func_start",
                          gLabels[i].name);
                        printf("%s: @ 0x%08X\n", gLabels[i].name, addr);
                    }
                    else
                    {
                        printf("\n\t%s sub_%08X\n",
                          (gLabels[i].type == LABEL_ARM_CODE) ? "arm_func_start" : "thumb_func_start",
                          addr);
                        printf("sub_%08X: @ 0x%08X\n", addr, addr);
                    }
                }
                // Just a normal code label. Use the '_XXXXXXXX' label
                else
                {
                    if (gLabels[i].name != NULL)
                        printf("%s:\n", gLabels[i].name);
                    else
                        printf("_%08X:\n", addr);
                }

                assert(gLabels[i].size != UNKNOWN_SIZE);
                cs_option(sCapstone, CS_OPT_MODE, mode);
                count = cs_disasm(sCapstone, gInputFileBuffer + addr - ROM_LOAD_ADDR, gLabels[i].size, addr, 0, &insn);
                for (j = 0; j < count; j++)
                {
                  no_inc:
                    if (!IsValidInstruction(&insn[j], gLabels[i].type)) {
                        if (gLabels[i].type == LABEL_THUMB_CODE)
                        {
                            int tmp_cnt;
                            cs_insn * tmp;
                            printf("\t.hword 0x%04X\n", hword_at(addr));
                            addr += 2;
                            if (insn[j].size == 2) continue;
                            tmp_cnt = cs_disasm(sCapstone, gInputFileBuffer + addr - ROM_LOAD_ADDR, 2, addr, 0, &tmp);
                            assert(tmp_cnt == 1);
                            free(insn[j].detail);
                            insn[j] = *tmp;
                            free(tmp);
                            goto no_inc;
                        }
                        else
                        {
                            printf("\t.word 0x%08X\n", word_at(addr));
                            addr += 4;
                            continue;
                        }
                    }
                    print_insn(&insn[j], addr, gLabels[i].type);
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
            //assert(gLabels[i].size == 4);
            printf("_%08X: .4byte 0x%08X\n", addr, word_at(addr));
            addr += 4;
            break;
        case LABEL_JUMP_TABLE:
            {
                uint32_t end = addr + gLabels[i].size;
                int caseNum = 0;

                printf("_%08X: @ jump table\n", addr);
                while (addr < end)
                {
                    uint32_t word = word_at(addr);
                    
                    if (word & ROM_LOAD_ADDR)
                        printf("\t.4byte %08X @ case %i\n", word, caseNum);
                    else
                        printf("\t.4byte 0x%08X @ case %i\n", word, caseNum);
                    caseNum++;
                    addr += 4;
                }
            }
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

    // entry point
    disasm_add_label(ROM_LOAD_ADDR, LABEL_ARM_CODE, NULL);

    // rom header
    disasm_add_label(ROM_LOAD_ADDR + 4, LABEL_DATA, NULL);

    analyze();
    print_disassembly();
    free(gLabels);
}
