from barf.barf import BARF
import angr
import simuvex
import pyvex
import claripy
import struct
import sys

def get_retn_predispatcher(cfg):
    global main_dispatcher
    for block in cfg.basic_blocks:
        if len(block.branches) == 0 and block.direct_branch == None:
            retn = block.start_address
        elif block.direct_branch == main_dispatcher:
            pre_dispatcher = block.start_address
    return retn, pre_dispatcher
    
def get_relevant_nop_blocks(cfg):
    global pre_dispatcher, prologue, retn
    relevant_blocks = []
    nop_blocks = []
    for block in cfg.basic_blocks:
        if block.direct_branch == pre_dispatcher and len(block.instrs) != 1:
            relevant_blocks.append(block.start_address)
        elif block.start_address != prologue and block.start_address != retn:
            nop_blocks.append(block)
    return relevant_blocks, nop_blocks

def statement_inspect(state):
    global modify_value
    expressions = state.scratch.irsb.statements[state.inspect.statement].expressions
    if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):
        state.scratch.temps[expressions[0].cond.tmp] = modify_value
        state.inspect._breakpoints['statement'] = []

def symbolic_execution(start_addr, hook_addr=None, modify=None, inspect=False):
    global b, relevants, modify_value
    if hook_addr != None:
        b.hook(hook_addr, retn_procedure, length=5)
    if modify != None:
        modify_value = modify
    state = b.factory.blank_state(addr=start_addr, remove_options={simuvex.o.LAZY_SOLVES})
    if inspect:
        state.inspect.b('statement', when=simuvex.BP_BEFORE, action=statement_inspect)
    p = b.factory.path(state)
    succ=p.step()
    while succ.successors[0].addr not in relevants:
        succ=succ.successors[0].step()
    return succ.successors[0].addr

def retn_procedure(state):
    global b
    ip = state.se.eval(state.regs.ip)
    b.unhook(ip)
    return

def fill_nop(data, start, end):
    global opcode
    for i in range(start, end):
        data[i] = opcode['nop']

def fill_jmp_offset(data, start, offset):
    jmp_offset = struct.pack('<i', offset)
    for i in range(4):
        data[start + i] = jmp_offset[i]

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'Usage: python deflat.py filename function_address(hex)'
        exit(0)
    opcode = {'a':'\x87', 'ae': '\x83', 'b':'\x82', 'be':'\x86', 'c':'\x82', 'e':'\x84', 'z':'\x84', 'g':'\x8F', 
              'ge':'\x8D', 'l':'\x8C', 'le':'\x8E', 'na':'\x86', 'nae':'\x82', 'nb':'\x83', 'nbe':'\x87', 'nc':'\x83',
              'ne':'\x85', 'ng':'\x8E', 'nge':'\x8C', 'nl':'\x8D', 'nle':'\x8F', 'no':'\x81', 'np':'\x8B', 'ns':'\x89',
              'nz':'\x85', 'o':'\x80', 'p':'\x8A', 'pe':'\x8A', 'po':'\x8B', 's':'\x88', 'nop':'\x90', 'jmp':'\xE9', 'j':'\x0F'}
    filename = sys.argv[1]
    start = int(sys.argv[2], 16)
    barf = BARF(filename)
    base_addr = barf.binary.entry_point >> 12 << 12
    b = angr.Project(filename, load_options={'auto_load_libs': False, 'main_opts':{'custom_base_addr': 0}})
    cfg = barf.recover_cfg(start=start)
    blocks = cfg.basic_blocks
    prologue = start
    main_dispatcher = cfg.find_basic_block(prologue).direct_branch
    retn, pre_dispatcher = get_retn_predispatcher(cfg)
    relevant_blocks, nop_blocks = get_relevant_nop_blocks(cfg)
    print '*******************relevant blocks************************'
    print 'prologue:%#x' % start
    print 'main_dispatcher:%#x' % main_dispatcher
    print 'pre_dispatcher:%#x' % pre_dispatcher
    print 'retn:%#x' % retn
    print 'relevant_blocks:', [hex(addr) for addr in relevant_blocks]

    print '*******************symbolic execution*********************'
    relevants = relevant_blocks
    relevants.append(prologue)
    relevants_without_retn = list(relevants)
    relevants.append(retn)
    flow = {}
    for parent in relevants:
        flow[parent] = []
    modify_value = None
    patch_instrs = {}
    for relevant in relevants_without_retn:
        print '-------------------dse %#x---------------------' % relevant
        block = cfg.find_basic_block(relevant)
        has_branches = False
        hook_addr = None
        for ins in block.instrs:
            if ins.mnemonic.startswith('cmov'):
                patch_instrs[relevant] = ins
                has_branches = True
            elif ins.mnemonic.startswith('call'):
                hook_addr = ins.address
        if has_branches:
            flow[relevant].append(symbolic_execution(relevant, hook_addr, claripy.BVV(1, 1), True))
            flow[relevant].append(symbolic_execution(relevant, hook_addr, claripy.BVV(0, 1), True))
        else:
            flow[relevant].append(symbolic_execution(relevant, hook_addr))
            
    print '************************flow******************************'
    for (k, v) in flow.items():
        print '%#x:' % k, [hex(child) for child in v]

    print '************************patch*****************************'
    flow.pop(retn)
    origin = open(filename, 'rb')
    origin_data = list(origin.read())
    origin.close()
    recovery = open(filename + '.recovered', 'wb')
    for nop_block in nop_blocks:
        fill_nop(origin_data, nop_block.start_address - base_addr, nop_block.end_address - base_addr + 1)    
    for (parent, childs) in flow.items():
        if len(childs) == 1:
            last_instr = cfg.find_basic_block(parent).instrs[-1]
            file_offset = last_instr.address - base_addr
            origin_data[file_offset] = opcode['jmp']
            file_offset += 1
            fill_nop(origin_data, file_offset, file_offset + last_instr.size - 1)
            fill_jmp_offset(origin_data, file_offset, childs[0] - last_instr.address - 5)
        else:
            instr = patch_instrs[parent]
            file_offset = instr.address - base_addr
            fill_nop(origin_data, file_offset, cfg.find_basic_block(parent).end_address - base_addr + 1)
            origin_data[file_offset] = opcode['j']
            origin_data[file_offset + 1] = opcode[instr.mnemonic[4:]]
            fill_jmp_offset(origin_data, file_offset + 2, childs[0] - instr.address - 6)
            file_offset += 6
            origin_data[file_offset] = opcode['jmp']
            fill_jmp_offset(origin_data, file_offset + 1, childs[1] - (instr.address + 6) - 5)
    recovery.write(''.join(origin_data))
    recovery.close()
    print 'Successful! The recovered file: %s' % (filename + '.recovered')
