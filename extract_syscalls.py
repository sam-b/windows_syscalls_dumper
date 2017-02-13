import idautils
import idc
import json
import os

ea = idc.MinEA()
all = {}
while True:
	ea = idc.FindText(ea, idc.SEARCH_DOWN, 0, 0, "syscall")
	if ea == idaapi.BADADDR:
		break
	func_name = idc.GetFunctionName(ea)
	ins = idc.FindText(ea, idc.SEARCH_UP, 0, 0, "mov")
	
	syscall_num = idc.GetOpnd(ins, 1)
	all[func_name] = syscall_num
	ea += len("syscall")

out_path = os.path.join(os.path.expanduser('~'), 'Desktop')
in_file = idc.GetInputFile().replace('.','_')
out_path += "\\" + in_file + '_syscalls.json'
with open(out_path, 'w+') as fp:
	json.dump(all, fp)
	
print "Saved %d system calls to %s" % (len(all), out_path)