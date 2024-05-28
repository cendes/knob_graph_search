import subprocess
import var_search
import parse_func_call

knob = "ip_forward"

#TODO: optimize reading of multiline by saving multiline expression
#TODO: handle weird dereference cases (pointer arithmetic and struct)
#TODO: properly handle function pointers
#TODO: Eliminate references to array index


def main():
    var_name, struct_hierarchy = var_search.find_knob_var(knob)
    funcs, _, _ = var_search.find_func_refs(var_name, struct_hierarchy)
    print(funcs)
    for func in funcs:
        if func not in parse_func_call.generic_funcs:
            build_knob_call_graph(knob, func)


def build_knob_call_graph(knob, func):
    subprocess.run(f"mkdir -p call_graphs/{knob}", shell=True)
    subprocess.run(f"fnplot/fnplot -c linux-5.15.152/cscope.out -x -d 5 -f {func} -o call_graphs/{knob}/{func}.dot",
                   shell=True)
    subprocess.run(f"dot -Tsvg call_graphs/{knob}/{func}.dot > call_graphs/{knob}/{func}.svg", shell=True)


if __name__ == "__main__":
    main()
