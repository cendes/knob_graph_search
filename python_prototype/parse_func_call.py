import subprocess
import re
import parse_struct
import check_expression
import var_search
import parse_var_assignment
import file_search
import sanitize_expression
import get_token

generic_funcs = ["main", "init", "start", "test", "switch_to", "dump", "__acquires", "io_req_task_queue", "do_exit",
                 "cifs_net_ns", "smbd_create_id", "seq_file_net", "genlmsg_multicast", "read_pnet", "ax25_kiss_rcv",
                 "ax25_register_dev_sysctl", "alloc_netdev_mqs", "__skb_flow_dissect", "__register_pernet_operations",
                 "__unregister_pernet_operations", "nr_dev_first", "nr_dev_get", "ht_dbg", "ps_dbg", "mpath_dbg",
                 "_sdata_dbg", "boot", "bool", "seq_con_printf", "printf", "die", "TP_printk", "Dprintk", "EXPORT_SYMBOL",
                 "printk"]

func_args_visited = dict()
visited_func_args_decl = dict()
visited_func_decls = dict()


def handle_function_call(var_name, struct_hierarchy, var_ref, var_ref_arr, func_name, func_ptrs):
    if var_ref == 'tools/tracing/latency/latency-collector.c restore_ftrace 610 restore_file(TR_THRESH, &save_state.thresh, threshold);':
        pass
    funcs = []
    return_struct_hierarchy = None
    output_vars = dict()
    func_calls, funcs_start, func_call_args, var_args_indices, args_struct_matches, args_range = (
        get_func_call_args(var_name, struct_hierarchy, var_ref, var_ref_arr))
    for i in range(len(func_calls)):
        if func_calls[i] not in func_args_visited:
            func_args_visited[func_calls[i]] = []
        func_arg_names, func_arg_refs, func_ptr_args = get_func_args_refs(func_calls[i], func_call_args[i], var_args_indices[i])
        if func_calls[i] == "memcpy":
            additional_funcs, return_struct_hierarchy = (
                handle_memcpy(var_name, var_ref_arr, func_name, func_call_args[i], struct_hierarchy, func_ptrs))
            if additional_funcs is not None:
                var_search.extend_unique(funcs, additional_funcs)
        elif func_calls[i] in generic_funcs:
            continue
        else:
            if func_calls[i] in func_ptrs:
                func_calls[i] = func_ptrs[func_calls[i]]
                func_arg_names, func_arg_refs, func_ptr_args = (
                    get_func_args_refs(func_calls[i], func_call_args[i], var_args_indices[i])) # TODO: eliminate false positives
            if len(func_arg_names) == 0:
                continue
            func_ptrs_passed = handle_func_ptrs_passed(func_call_args[i], func_arg_names, func_ptr_args, func_ptrs)
            for j, arg_index in enumerate(var_args_indices[i]):
                if func_arg_names[arg_index] not in func_args_visited[func_calls[i]]:
                    func_args_visited[func_calls[i]].append(func_arg_names[arg_index])
                    additional_funcs, return_var_hierarchy, output_args = (
                        var_search.get_func_refs(func_arg_names[arg_index], struct_hierarchy[args_struct_matches[i][j]:],
                                                 func_arg_refs[arg_index], False, func_calls[i], func_ptrs_passed))
                    handle_output_args(func_name, func_calls[i], func_call_args[i], output_args, var_ref_arr, func_ptrs)
                    var_search.extend_unique(funcs, additional_funcs)
                    if return_var_hierarchy is not None:
                        additional_funcs, return_struct_hierarchy, additional_output_args = (
                            parse_var_assignment.handle_var_assignments(func_name, var_ref, var_ref_arr, var_name,
                                                                        return_var_hierarchy, True, func_ptrs))
                        var_search.extend_unique(funcs, additional_funcs)
                        output_vars.update(additional_output_args)
                        func_idx, arg_idx = get_func_arg_index(args_range[i + 1:], funcs_start[i])
                        if func_idx is not None:
                            var_args_indices[func_idx + i + 1].append(arg_idx)
                            match_index = 0
                            while (match_index < len(struct_hierarchy) and
                                   struct_hierarchy[match_index] == return_var_hierarchy[match_index]):
                                match_index += 1
                            args_struct_matches[func_idx + i + 1].append(match_index)
    return funcs, return_struct_hierarchy, output_vars


def handle_memcpy(var_name, var_ref_arr, func_name, func_call_args, struct_hierarchy, func_ptrs):
    struct_matches = parse_struct.get_struct_matches(func_call_args[1], var_name, struct_hierarchy)
    if len(struct_matches) > 0:
        if check_expression.is_func(func_call_args[0]):
            dest, assigned_hierarchy = get_ptr_from_func_return(func_call_args[0], var_ref_arr, func_ptrs)
        else:
            dest = func_call_args[0]
            _, assigned_hierarchy = parse_struct.get_struct_hierarchy(func_call_args[0])
            assigned_hierarchy.extend(struct_hierarchy[max(struct_matches):])

        if dest is not None:
            return parse_var_assignment.get_assigned_var_funcs(func_name, dest, assigned_hierarchy, var_ref_arr, func_ptrs)

    return None, None


def handle_func_ptrs_passed(func_call_args, func_arg_names, func_ptr_args, func_ptrs):
    func_ptrs_passed = dict()
    for func_ptr_idx in func_ptr_args:
        func_ptr_var = func_call_args[func_ptr_idx]
        if func_ptr_var in func_ptrs:
            func_ptrs_passed[func_arg_names[func_ptr_idx]] = func_ptrs[func_ptr_var]
        else:
            func_ptrs_passed[func_arg_names[func_ptr_idx]] = func_call_args[func_ptr_idx]
    return func_ptrs_passed


def handle_output_args(func_name, func_call, func_call_args, output_args, var_ref_arr, func_ptrs):
    if func_call not in visited_func_args_decl or len(output_args) == 0:
        return
    func_args_declaration = visited_func_args_decl[func_call]
    output_call_args = []
    for i, func_arg_declaration in enumerate(func_args_declaration):
        tokens = func_arg_declaration.split()
        arg_name = tokens[len(tokens)-1]
        if arg_name[0] == "*":
            arg_name = arg_name[1:]
        for output_arg, output_hierarchy in output_args.items():
            if check_expression.is_func(output_arg):
                arg_arg, arg_hierarchy = get_ptr_from_func_return(output_arg, var_ref_arr, func_ptrs)
                if arg_arg is not None:
                    output_call_args.append((arg_arg, arg_hierarchy))
            elif arg_name == parse_struct.get_root_name(output_arg):
                _, arg_hierarchy = parse_struct.get_struct_hierarchy(func_call_args[i].strip())
                output_hierarchy.extend(arg_hierarchy)
                output_call_args.append((func_call_args[i].strip(), output_hierarchy))

    funcs = []
    for output_arg, output_hierarchy in output_call_args:
        addtional_funcs, _ = (
            parse_var_assignment.get_assigned_var_funcs(func_name, output_arg, output_hierarchy, var_ref_arr, func_ptrs))
        var_search.extend_unique(funcs, addtional_funcs)
    return funcs


def get_ptr_from_func_return(func_call, var_ref_arr, func_ptrs):
    out_func_name = get_token.find_func_name(func_call)
    arg_args, _ = get_func_args(func_call, var_ref_arr, func_call.find("("))
    for arg_arg in arg_args:
        arg_refs = var_search.get_local_var_refs(arg_arg, out_func_name, var_ref_arr, False)
        _, return_hierarchy, _ = (
            var_search.get_func_refs(arg_arg, [], arg_refs, False, out_func_name, func_ptrs)) #TODO: handle function pointers
        if return_hierarchy is not None:
            _, assigned_hierarchy = parse_struct.get_struct_hierarchy(arg_arg.strip())
            assigned_hierarchy.extend(return_hierarchy)
            return arg_arg, return_hierarchy

    return None, None


def get_func_call_args(var_name, struct_hierarchy, var_ref, var_ref_arr):
    args_start_indices = [m.start() for m in re.finditer("\\(", var_ref)]
    funcs = []
    funcs_start = []
    args = []
    var_args_indices = []
    args_struct_matches = []
    args_range = []
    for args_start_index in args_start_indices:
        func_name = get_token.get_func_name(var_ref, args_start_index)
        if func_name is None:
            continue
        args_list, func_args_range = get_func_args(var_ref, var_ref_arr, args_start_index)
        var_arg_indices = []
        arg_struct_matches = []
        for i, arg in enumerate(args_list):
            var_name_index = arg.find(var_name)
            if (var_name_index >= 0 and not check_expression.is_func(arg) and
                    check_expression.is_token_match(arg, var_name_index, len(var_name))):
                struct_matches = parse_struct.get_struct_matches(arg, var_name, struct_hierarchy)
                if len(struct_matches) > 0:
                    var_arg_indices.append(i)
                    arg_struct_matches.append(max(struct_matches))
        funcs.insert(0, func_name)
        funcs_start.insert(0, args_start_index - 1)
        args.insert(0, args_list)
        var_args_indices.insert(0, var_arg_indices)
        args_struct_matches.insert(0, arg_struct_matches)
        args_range.insert(0, func_args_range)
    return funcs, funcs_start, args, var_args_indices, args_struct_matches, args_range


def get_func_args(var_ref, var_ref_arr, args_start_index):
    args_list = []
    args_range = []
    curr_index = args_start_index + 1
    expr_start = args_start_index + 1
    while curr_index < len(var_ref) and var_ref[curr_index] != ")":
        if var_ref[curr_index] == ",":
            args_list.append(var_ref[expr_start:curr_index])
            args_range.append((expr_start, curr_index - 1))
            expr_start = curr_index + 1
        elif var_ref[curr_index] == "(" or var_ref[curr_index] == "[":
            curr_index = check_expression.recur_with_parenthesis(var_ref, curr_index + 1, var_ref[curr_index])
        curr_index += 1
    args_list.append(var_ref[expr_start:curr_index])
    args_range.append((expr_start, curr_index - 1))
    return args_list, args_range


def get_func_args_refs(func_name, func_args, var_args_indices):
    args_declaration, func_declaration_arr = get_func_args_declaration(func_name, func_args)
    if args_declaration is None or func_declaration_arr is None:
        return [], [], []

    visited_func_args_decl[func_name] = args_declaration
    func_ptr_args = []
    for i, arg_declaration in enumerate(args_declaration):
        if check_expression.is_func_ptr(arg_declaration):
            func_ptr_args.append(i)
    func_arg_names, func_arg_refs = (
        get_func_args_name(func_name, args_declaration, var_args_indices, func_declaration_arr, True))
    return func_arg_names, func_arg_refs, func_ptr_args


def get_func_args_declaration(func_name, func_args):
    func_declarations, func_declarations_arr = get_func_declarations(func_name)
    if len(func_declarations) == 0:
        return None, None

    args_declaration = None
    func_declaration_arr = None
    for i, func_declaration in enumerate(func_declarations):
        func_declaration = file_search.get_multiline_expr(func_declaration, func_declarations_arr[i])
        args_start_index = func_declaration.find("(")
        args_declaration, _ = get_func_args(func_declaration, func_declarations_arr[i], args_start_index)
        if len(args_declaration) == 1 and args_declaration[0] == "void":
            args_declaration = []
        if len(args_declaration) == len(func_args) and (
                "#define" in func_declaration or check_expression.has_arg_names(args_declaration)):
            func_declaration_arr = func_declarations_arr[i]
            visited_func_decls[func_name] = func_declaration
            break

    return args_declaration, func_declaration_arr


def get_func_declarations(func_name):
    result = subprocess.run(f"cd linux-5.15.152 && cscope -d -L0 {func_name}",
                            shell=True, capture_output=True, text=True)
    func_refs = result.stdout.split("\n")[:-1]
    extern_declaractions = []
    extern_declaractions_arr = []
    header_declarations = []
    header_declarations_arr = []
    func_declarations = []
    func_declarations_arr = []
    for func_ref in func_refs:
        ref_func_arr = func_ref.split()
        func_ref = file_search.get_multiline_expr(func_ref, ref_func_arr)
        if func_ref == 'return nla_put(skb, CRYPTOCFGA_REPORT_AKCIPHER, sizeof(), &rakcipher);':
            pass
        if check_expression.is_func(func_ref) and check_expression.is_var_declaration(func_name, func_ref):
            if check_expression.is_extern(func_ref):
                extern_declaractions.append(func_ref)
                extern_declaractions_arr.append(ref_func_arr)
            elif ".h" in ref_func_arr[0]:
                header_declarations.append(func_ref)
                header_declarations_arr.append(ref_func_arr)
            else:
                func_declarations.append(func_ref)
                func_declarations_arr.append(ref_func_arr)
                break
    if len(func_declarations) == 0:
        if len(header_declarations) > 0:
            func_declarations = header_declarations
            func_declarations_arr = header_declarations_arr
        elif len(extern_declaractions) > 0:
            func_declarations = extern_declaractions
            func_declarations_arr = extern_declaractions_arr

    return func_declarations, func_declarations_arr


def get_func_args_name(func_name, args_declaration, var_args_indices, statement_arr, is_func_declaration):
    func_arg_refs = []
    func_arg_names = []
    for i, arg_declaration in enumerate(args_declaration):
        arg_declaration = arg_declaration.strip()
        if "#define" in statement_arr or " " not in arg_declaration:
            arg_name = arg_declaration
        else:
            if check_expression.is_func_ptr(arg_declaration):
                arg_name = get_token.get_func_ptr_name(arg_declaration)
            else:
                arg_name = sanitize_expression.extract_varname(arg_declaration.split()[-1])
            if arg_name == "" or not check_expression.is_valid_varname(arg_name):
                return [], []

        if i in var_args_indices:
            arg_refs = var_search.get_local_var_refs(arg_name, func_name, statement_arr, is_func_declaration)
            if arg_refs is None:
                arg_refs = []
        else:
            arg_refs = []
        func_arg_refs.append(arg_refs)
        func_arg_names.append(arg_name)
    return func_arg_names, func_arg_refs


def get_func_arg_index(args_range, func_start):
    for func_idx, func_args_range in enumerate(args_range):
        for arg_idx, arg_range in enumerate(func_args_range):
            arg_start, arg_end = arg_range
            if arg_start <= func_start <= arg_end:
                return func_idx, arg_idx
    return None, None
