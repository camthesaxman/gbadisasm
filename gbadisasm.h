
enum LabelType
{
    LABEL_ARM_CODE,
    LABEL_THUMB_CODE,
    LABEL_DATA,
    LABEL_POOL,
};

extern uint8_t *gInputFileBuffer;
extern size_t gInputFileBufferSize;

// disasm.c
void disasm_add_name(uint32_t addr, const char *name);
int disasm_add_label(uint32_t addr, uint8_t type);
void disasm_disassemble(void);
