
enum LabelType
{
    LABEL_ARM_CODE,
    LABEL_THUMB_CODE,
    LABEL_DATA,
    LABEL_POOL,
    LABEL_JUMP_TABLE,
};

extern uint8_t *gInputFileBuffer;
extern size_t gInputFileBufferSize;

// disasm.c
int disasm_add_label(uint32_t addr, uint8_t type, char *name);
void disasm_disassemble(void);
