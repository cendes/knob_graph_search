import search_call_graph
import parse_struct
import var_search
import check_expression
import parse_func_call
import sanitize_expression
import get_token

func_locals_visited = dict()


def handle_var_assignments(func_name, var_ref, var_ref_arr, var_name, struct_hierarchy, is_return_assignment, func_ptrs):
    if func_name not in func_locals_visited:
        func_locals_visited[func_name] = []
    assigned_var, output_var_refs = get_assignment_var(func_name, var_ref, var_ref_arr, var_name, is_return_assignment)
    if not is_return_assignment:
        struct_matches = parse_struct.get_struct_matches(var_ref, var_name, struct_hierarchy)
        if len(struct_matches) == 0:
            return [], None, []
        struct_match_start = max(struct_matches)
        struct_hierarchy = struct_hierarchy[struct_match_start:]
    _, assigned_struct_hierarchy = parse_struct.get_struct_hierarchy(var_name)
    assigned_struct_hierarchy.extend(struct_hierarchy)
    struct_hierarchy = assigned_struct_hierarchy
    if output_var_refs is None:
        funcs, return_hierarchy = get_assigned_var_funcs(func_name, assigned_var, struct_hierarchy, var_ref_arr, func_ptrs)
        return funcs, return_hierarchy, []
    else:
        funcs = []
        return_hierarchy = None
        output_args = dict()
        if parse_struct.get_root_name(assigned_var) not in func_locals_visited[func_name]:
            func_locals_visited[func_name].append(parse_struct.get_root_name(assigned_var))
            funcs, var_return_hierarchy, output_args = (
                var_search.get_func_refs(parse_struct.get_root_name(assigned_var), struct_hierarchy, output_var_refs,
                                         False, func_name, func_ptrs))
            if var_return_hierarchy is not None:
                return_hierarchy = var_return_hierarchy
            output_args[assigned_var] = struct_hierarchy
        return funcs, return_hierarchy, output_args


def get_assigned_var_funcs(func_name, assigned_var, struct_hierarchy, var_ref_arr, func_ptrs):
    additional_funcs = []
    return_hierarchy = None
    if func_name not in func_locals_visited:
        func_locals_visited[func_name] = []
    if assigned_var is not None and assigned_var not in func_locals_visited[func_name]:
        func_locals_visited[func_name].append(assigned_var)
        assigned_var_refs = var_search.get_local_var_refs(assigned_var, func_name, var_ref_arr, False)
        if assigned_var_refs is None:
            additional_funcs, return_hierarchy, _ = (
                var_search.find_func_refs(parse_struct.get_root_name(assigned_var), struct_hierarchy))
        else:
            additional_funcs, return_hierarchy, _ = (
                var_search.get_func_refs(parse_struct.get_root_name(assigned_var), struct_hierarchy, assigned_var_refs,
                                         False, func_name, func_ptrs))
    return additional_funcs, return_hierarchy


def get_assignment_var(func_name, var_ref, var_ref_arr, var_name, is_return_assignment):
    eq_index = get_token.get_eq_index(var_ref)
    if eq_index is None or (not is_return_assignment and not check_expression.has_var_name(var_ref[eq_index + 1:], var_name)):
        return None, None
    var_end_index = eq_index - 1
    while (not check_expression.is_valid_varname_char(var_ref[var_end_index]) and
           var_ref[var_end_index] != ")" and var_ref[var_end_index] != "]"):
        var_end_index -= 1
    var_start_index = var_end_index
    while (check_expression.is_valid_varname_char(var_ref[var_start_index]) or var_ref[var_start_index] == "*" or
           var_ref[var_start_index] == "." or var_ref[var_start_index] == ">" or var_ref[var_start_index] == "]" or
           var_ref[var_start_index] == "[" or var_ref[var_start_index] == ")" or var_ref[var_start_index] == "("):
        if var_ref[var_start_index] == ">":
            if var_ref[var_start_index-1] == "-":
                var_start_index -= 2
                continue
            else:
                break
        elif var_ref[var_start_index] == ")" or var_ref[var_start_index] == "]":
            var_start_index = check_expression.recur_with_parenthesis(var_ref, var_start_index - 1, var_ref[var_start_index]) #TODO: peel outer parenthesis and handle for loops
            var_start_index -= 1
        elif var_ref[var_start_index] == "(":
            break
        else:
            var_start_index -= 1
    var_name = var_ref[var_start_index + 1:var_end_index + 1]
    output_var_refs = get_out_arg_assignment_refs(var_name, var_ref_arr, func_name)
    var_name = sanitize_expression.extract_varname(var_name)
    if var_name[0] == ".":
        struct_name = search_call_graph.find_struct_name(var_ref_arr[0], int(var_ref_arr[2]))
        if struct_name is None:
            return None, None
        else:
            return struct_name + var_name, output_var_refs
    else:
        return var_name, output_var_refs


def get_out_arg_assignment_refs(var_name, var_ref_arr, func_name):
    output_var_refs = None
    if ("*" in var_name or "->" in var_name or "[" in var_name) and func_name in parse_func_call.visited_func_args_decl: #TODO: remove potential false positives
        var_name = sanitize_expression.extract_varname(var_name)
        args_declaration = parse_func_call.visited_func_args_decl[func_name]
        args_indices = []
        #TODO: make this more efficient
        for i, arg_declaration in enumerate(args_declaration):
            root_var_name = parse_struct.get_root_name(var_name)
            if root_var_name in arg_declaration:
                args_indices.append(i)
        func_args_name, func_arg_refs = parse_func_call.get_func_args_name(func_name, args_declaration, args_indices,
                                                                           var_ref_arr, False)
        for i, func_arg_name in enumerate(func_args_name):
            if i in args_indices and parse_struct.get_root_name(var_name) == func_arg_name:
                output_var_refs = func_arg_refs[i]
                break

    return output_var_refs
