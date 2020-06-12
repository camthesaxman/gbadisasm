import argparse
import re
import os

syms = {}
found_syms = set()
found_bls = set()
found_pools = set()
strings_to_replace = []

bl_regex = re.compile(r"^\tbl sub_([0-9A-F]{8})")
pool_num_regex = re.compile(r"^[^@]+@ =0x([0-9A-F]{8})")
pool_func_regex = re.compile(r"^[^@]+@ =sub_([0-9A-F]{8})")

class RegexFind:
    __slots__ = ("regex", "find")

    def __init__(self, regex, find):
        self.regex = regex
        self.find = find

regex_finds = (RegexFind(bl_regex, "sub_{}"), RegexFind(pool_num_regex, "0x{}"), RegexFind(pool_func_regex, "sub_{}"))

class AddrRange:
    __slots__ = ("start", "end")
    
    def __init__(self, start, end):
        self.start = start
        self.end = end

class FindReplace:
    __slots__ = ("find", "replace")

    def __init__(self, find, replace):
        self.find = find
        self.replace = replace

addr_ranges = [
    AddrRange(0x2000000, 0x2040000),
    AddrRange(0x3000000, 0x3008000),
    AddrRange(0x8000000, 0x9000000)
]

def main(input_file):
    with open("pokefirered_syms.dump", "r") as f:
        for line in f:
            split_line = line.split(sep=None, maxsplit=2)
            addr = int(split_line[0], 16)
            for addr_range in addr_ranges:
                if addr_range.start <= addr < addr_range.end:
                    break
            else:
                continue

            syms[addr] = split_line[1]

    # cases: bl, pool
    with open(input_file, "r") as f:
        lines = f.readlines()

    for line in lines:
        for regex_find in regex_finds:
            match_obj = regex_find.regex.match(line)
            if match_obj is not None:
                value_addr = int(match_obj.group(1), 16)
                if value_addr not in found_syms and value_addr in syms:
                    strings_to_replace.append(FindReplace(regex_find.find.format(match_obj.group(1)), syms[value_addr]))
                    found_syms.add(value_addr)
                break

    output = "".join(lines)

    for find_replace in strings_to_replace:
        output = output.replace(find_replace.find, find_replace.replace)

    output_file_components = os.path.splitext(input_file)
    output_file_name = output_file_components[0] + "_out" + output_file_components[1]

    with open(output_file_name, "w+") as f:
        f.write(output)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", dest="input_file")
    args = ap.parse_args()

    if args.input_file is None:
        input_file = "CreateNPCTrainerParty.s"
    else:
        input_file = args.input_file

    main(input_file)
