import subprocess
import parse_struct
import file_search
import check_expression
import parse_func_call
import parse_var_assignment
import get_token
import sanitize_expression

out_of_scope = dict()


def find_knob_var(knob):
    result = subprocess.run(f"cd linux-5.15.152 && cscope -d -L4 =\\ \\\"{knob}\\\"",
                        shell=True, capture_output=True, text=True)
    search_result = result.stdout.split()
    file_path = search_result[0]
    line_num = int(search_result[2])

    with open("linux-5.15.152/" + file_path) as src_f:
        for i, line in enumerate(src_f):
            if i == line_num:
                var_line = line
                break

    var_name = var_line.split()[2]
    var_name = var_name[:-1]
    if var_name[0] == '&':
        var_name = var_name[1:]
    var_name, struct_hierarchy = parse_struct.get_struct_hierarchy(var_name)
    return var_name, struct_hierarchy


def find_func_refs(var_name, struct_hierarchy):
    result = subprocess.run(f"cd linux-5.15.152 && cscope -d -L0 {var_name}",
                            shell=True, capture_output=True, text=True)
    var_refs = result.stdout.split("\n")[:-1]
    return get_func_refs(var_name, struct_hierarchy, var_refs, True, None, dict())


def get_func_refs(var_name, struct_hierarchy, var_refs, is_global, func_name, func_ptrs):
    if var_refs == 'tools/tracing/latency/latency-collector.c restore_file 595 if (*saved && was_changed(*saved, cur)) {':
        pass
    funcs = []
    output_vars = dict()
    return_struct_hierarchy = None
    if func_name is None:
        get_func_from_ref = True
    else:
        get_func_from_ref = False
    for var_ref in var_refs:
        print(var_ref)
        var_ref_arr = var_ref.split()
        if get_func_from_ref:
            func_name = var_ref_arr[1]
        var_ref = file_search.get_multiline_expr(var_ref, var_ref_arr)
        var_ref = sanitize_expression.remove_casts(var_ref)
        if (func_name != "<global>" and
                (not is_global or func_name not in out_of_scope or var_name not in out_of_scope[func_name]) and
                check_expression.is_ref(var_ref, var_name, func_name, is_global) and not check_expression.is_asm_block(var_ref)):
            print("Function: " + func_name + " Variable: " + var_name)
            #TODO: remove false positives for function calls and assignments
            if check_expression.is_func(var_ref) and not check_expression.is_var_declaration(func_name, var_ref):
                additional_funcs, return_struct_hierarchy, additional_output_args = (
                    parse_func_call.handle_function_call(var_name, struct_hierarchy, var_ref, var_ref_arr, func_name, func_ptrs))
            else:
                additional_funcs, return_struct_hierarchy, additional_output_args = (
                    parse_var_assignment.handle_var_assignments(func_name, var_ref, var_ref_arr, var_name,
                                                                struct_hierarchy, False, func_ptrs))

            extend_unique(funcs, additional_funcs)
            output_vars.update(additional_output_args)

            return_match_idx = get_token.get_return_match_index(var_ref, var_ref_arr, var_name, struct_hierarchy, func_name)
            if return_match_idx >= 0:
                return_struct_hierarchy = struct_hierarchy[return_match_idx:]

            struct_matches = parse_struct.get_struct_matches(var_ref, var_name, struct_hierarchy)
            if func_name not in funcs and len(struct_hierarchy) in struct_matches:
                funcs.append(func_name)
    return funcs, return_struct_hierarchy, output_vars


def get_local_var_refs(var_name, func_name, statement_arr, is_func_declaration):
    var_name = parse_struct.get_root_name(var_name)
    result = subprocess.run(f"cd linux-5.15.152 && cscope -d -L0 {var_name}",
                            shell=True, capture_output=True, text=True)
    var_refs = result.stdout.split("\n")[:-1]
    is_local_var = False
    local_var_refs = []
    src_file_refs = []
    for var_ref in var_refs:
        var_ref_arr = var_ref.split()
        if var_ref_arr[1] == func_name:
            is_local_var = get_local_ref(var_name, var_ref, var_ref_arr, func_name, is_local_var, local_var_refs)

        if is_func_declaration and var_ref_arr[0] == statement_arr[0]:
            src_file_refs.append(var_ref)
    if is_local_var or ("#define" in statement_arr and len(local_var_refs) > 0):
        return local_var_refs
    elif len(local_var_refs) == 0:
        if is_func_declaration:
            func_start_line = int(statement_arr[2])
            func_end_line = file_search.get_func_end_line(statement_arr[0], func_start_line)
        else:
            func_start_line, func_end_line = file_search.get_func_from_src(statement_arr[0], func_name)

        if func_end_line is None:
            return None
        else:
            return get_local_var_refs_from_src(src_file_refs, var_name, func_name, statement_arr[0], func_start_line, func_end_line)
    else:
        return None


def get_local_var_refs_from_src(var_refs, var_name, func_name, src_file, func_start_line, func_end_line):
    local_var_refs = []
    is_local_var = False
    for var_ref in var_refs:
        var_ref_arr = var_ref.split()
        if var_ref_arr[0] == src_file and func_start_line <= int(var_ref_arr[2]) <= func_end_line:
            is_local_var = get_local_ref(var_name, var_ref, var_ref_arr, func_name, is_local_var, local_var_refs)

    if is_local_var:
        return local_var_refs
    else:
        return None


def get_local_ref(var_name, var_ref, var_ref_arr, func_name, is_local_var, local_var_refs):
    full_var_ref = file_search.get_multiline_expr(var_ref, var_ref_arr) #TODO: optimize this
    if not is_local_var:
        is_local_var = check_expression.is_var_declaration(var_name, full_var_ref)
        if is_local_var:
            return True

    if check_expression.is_ref(full_var_ref, var_name, func_name, False):
        local_var_refs.append(var_ref)

    return is_local_var


def extend_unique(funcs, additional_funcs):
    for additional_func in additional_funcs:
        if additional_func not in funcs:
            funcs.append(additional_func)
