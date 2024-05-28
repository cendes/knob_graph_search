import subprocess
import get_call_graph
import check_expression
import parse_var_assignment
import get_token
import var_search
import file_search
import parse_func_call

target_funcs = ['udp_init']
knob_name = "udp_mem"
visited = []

# generic_funcs = ["main", "init", "start", "test", "switch_to", "dump", "__acquires", "io_req_task_queue", "do_exit",
#                  "cifs_net_ns", "smbd_create_id", "seq_file_net", "genlmsg_multicast", "read_pnet", "ax25_kiss_rcv",
#                  "ax25_register_dev_sysctl", "alloc_netdev_mqs", "__skb_flow_dissect", "__register_pernet_operations",
#                  "__unregister_pernet_operations", "nr_dev_first", "nr_dev_get", "ht_dbg", "ps_dbg", "mpath_dbg",
#                  "_sdata_dbg", "boot", "bool"]


def main():
    inv_graph = dict()
    for target_func in target_funcs:
        sub_graph = build_inv_graph(target_func)
        merge_inv_graphs(inv_graph, sub_graph)
    for target_func in target_funcs:
        if target_func not in visited and target_func not in parse_func_call.generic_funcs:
            search_call_graph(target_func, inv_graph)
    save_overall_call_graph(inv_graph)


def build_inv_graph(target_func):
    inv_graph = dict()
    with open(f"call_graphs/{knob_name}/{target_func}.dot") as graph_src:
        for i, line in enumerate(graph_src):
            if i == 200:
                break
            if i > 0:
                line = line.strip()
                if line != "}":
                    edge = line.split("->")
                    parent = edge[0].strip()
                    child = edge[1].strip()
                    if child not in inv_graph:
                        inv_graph[child] = []
                    if parent not in inv_graph[child]:
                        inv_graph[child].append(parent)
    return inv_graph


def search_call_graph(child_func, inv_graph):
    if child_func == "dove_init":
        pass
    print(f"Searching {child_func}")
    grep_result = subprocess.run(f"grep \"{child_func}\" perf_call_graph.txt",
                                 shell=True, capture_output=True, text=True)
    visited.append(child_func)
    if grep_result.returncode != 0:
        expand_call_graph(child_func, inv_graph)
        if child_func not in inv_graph:
            return
        for parent_func in inv_graph[child_func]:
            if parent_func not in visited:
                search_call_graph(parent_func, inv_graph)
    else:
        print(grep_result.stdout)


def expand_call_graph(child_func, inv_graph):
    func_refs = find_func_calls(child_func)
    if len(func_refs) > 1 and child_func not in inv_graph:
        inv_graph[child_func] = []
    for ref in func_refs:
        if ref != child_func and ref not in parse_func_call.generic_funcs and ref not in inv_graph[child_func]:
            inv_graph[child_func].append(ref)
            if ref not in inv_graph:
                get_call_graph.build_knob_call_graph(knob_name, ref)
                ref_graph = build_inv_graph(ref)
                merge_inv_graphs(inv_graph, ref_graph)


def find_func_calls(child_func):
    result = subprocess.run(f"cd linux-5.15.152 && cscope -d -L0 {child_func}",
                            shell=True, capture_output=True, text=True)
    var_refs = result.stdout.split("\n")[:-1]
    funcs = []
    for var_ref in var_refs:
        if var_ref == 'lib/nlattr.c <global> 999 EXPORT_SYMBOL(__nla_put);':
            pass
        var_ref_arr = var_ref.split()
        var_ref = file_search.get_multiline_expr(var_ref, var_ref_arr)
        func_name = var_ref_arr[1]
        is_func_call = False
        func_call_name = get_token.find_func_name(var_ref)
        if func_name != "<global>" and func_name not in funcs and func_call_name == child_func:
            funcs.append(func_name)
            is_func_call = True
        elif func_call_name is not None and not check_expression.is_var_declaration(func_call_name, var_ref):
            # TODO: filter and properly handle function hierarchy
            func_calls, _, func_call_args, var_args_indices, _, _= parse_func_call.get_func_call_args(child_func, [], var_ref, var_ref_arr)
            for i in range(len(func_calls)):
                func_arg_names, func_arg_refs, _ = parse_func_call.get_func_args_refs(func_calls[i], func_call_args[i], var_args_indices[i])
                for arg_index in var_args_indices[i]:
                    additional_funcs, _, _ = var_search.get_func_refs(func_arg_names[arg_index], [], func_arg_refs[arg_index], False, func_calls[i], [])
                    var_search.extend_unique(funcs, additional_funcs)
        else:
            # TODO: filter and properly handle function hierarchy
            additional_funcs, _, _ = (
                parse_var_assignment.handle_var_assignments(func_name, var_ref, var_ref_arr, child_func, [], False, []))
            var_search.extend_unique(funcs, additional_funcs)

        # if not is_func_call and "=" in var_ref:
        #     get_func_ptr_calls(child_func, var_ref, var_ref_arr, funcs)

    return funcs


def get_func_ptr_calls(child_func, var_ref, ref_results, funcs):
    lhs = ref_results[-1]
    if lhs[-1] == ",":
        lhs = lhs[:-1]
    if lhs == child_func:
        rhs = ref_results[-3]
        if rhs.startswith("."):
            struct_field = rhs
            func_ptr = find_struct_name(ref_results[0], int(ref_results[2]))
            if func_ptr is None:
                return
        else:
            first_dot_index = var_ref.find(".")
            first_arrow_index = var_ref.find("->")
            if first_arrow_index == -1 or first_dot_index < first_arrow_index:
                first_segment = first_dot_index
            else:
                first_segment = first_arrow_index
            if first_segment == -1:
                func_ptr = rhs
                struct_field = ""
            else:
                func_ptr = rhs[:first_segment - 1]
                struct_field = rhs[first_segment:]

        full_ptr_name = func_ptr + struct_field
        result = subprocess.run(f"cd linux-5.15.152 && cscope -d -L0 {func_ptr}",
                                shell=True, capture_output=True, text=True)
        func_ptr_refs = result.stdout.split("\n")[:-1]
        for func_ptr_ref in func_ptr_refs:
            func_ptr_ref_results = func_ptr_ref.split()
            func_name = func_ptr_ref_results[1]
            if func_name != "<global>" and not func_name.isupper() and func_name not in funcs:
                if func_ptr_ref.find(full_ptr_name + "(") > 0:
                    funcs.append(func_name)


def find_struct_name(source_file, line_number):
    var_name = None
    with open("linux-5.15.152/" + source_file, "r") as f:
        for i, line in enumerate(f):
            if "struct" in line and "=" in line and "{" in line:
                tokens = line.split()
                for j, token in enumerate(tokens):
                    if token == "struct":
                        var_name = tokens[j+2]
                        break
            elif "#define" in line:
                return None
            if i == line_number - 1:
                return var_name


def merge_inv_graphs(main_graph, sub_graph):
    for sub_parent in sub_graph.keys():
        if sub_parent not in main_graph:
            main_graph[sub_parent] = sub_graph[sub_parent]
        else:
            for sub_grandparent in sub_graph[sub_parent]:
                if sub_grandparent not in main_graph[sub_parent]:
                    main_graph[sub_parent].append(sub_grandparent)


def save_overall_call_graph(inv_graph):
    dot_file = f"digraph \"Call graph of  {knob_name}\" {{\n"
    for target_func in target_funcs:
        dot_file += f"    {target_func} -> {knob_name}\n"
    for func in inv_graph.keys():
        for parent_func in inv_graph[func]:
            dot_file += f"    {parent_func} -> {func}\n"
    dot_file += "}"
    with open(f"call_graphs/{knob_name}/FULL_CALL_GRAPH.dot", "w+") as f:
        f.write(dot_file)
    subprocess.run(f"dot -Tsvg call_graphs/{knob_name}/FULL_CALL_GRAPH.dot > call_graphs/{knob_name}/FULL_CALL_GRAPH.svg",
                   shell=True)


if __name__ == "__main__":
    main()
