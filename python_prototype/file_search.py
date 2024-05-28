import check_expression
import sanitize_expression
import get_token


def get_multiline_expr(var_ref, var_ref_arr):
    var_ref = sanitize_expression.remove_strings(var_ref).strip()
    if var_ref[-1] == "\\":
        var_ref = var_ref[:-1].strip()

    if ((var_ref[-1] != ";" and var_ref[-1] != "{" and var_ref_arr[3][0] != "." and "#define" not in var_ref) or
            check_expression.has_open_string(var_ref)):
        if ((not check_expression.is_control_flow_expr(var_ref) and not check_expression.is_func(var_ref)) or
                check_expression.has_mismatched_parenthesis(var_ref)):
            return sanitize_expression.clean_var_ref(get_full_expr(var_ref_arr[0], int(var_ref_arr[2])))
    elif "#define" not in var_ref and (not check_expression.is_expression(var_ref, var_ref_arr) or
                                       check_expression.has_mismatched_parenthesis(var_ref)):
        return sanitize_expression.clean_var_ref(get_full_expr(var_ref_arr[0], int(var_ref_arr[2])))

    if (check_expression.is_func(var_ref) and not check_expression.is_control_flow_expr(var_ref) and "=" not in var_ref
            and "\"" not in var_ref and "->" not in var_ref):
        func_name = get_token.find_func_name(var_ref)
        if func_name is not None and not check_expression.is_var_declaration(func_name, var_ref):
            args_start = var_ref.find(func_name + "(") + len(func_name + "(")
            curr_char = args_start
            while curr_char < len(var_ref) and var_ref[curr_char] != "," and var_ref[curr_char] != ")":
                curr_char += 1
            arg_declaration = var_ref[args_start:curr_char]
            if len(arg_declaration) > 0 and "(" not in arg_declaration and check_expression.has_arg_names([arg_declaration]):
                return sanitize_expression.clean_var_ref(get_full_expr(var_ref_arr[0], int(var_ref_arr[2])))
    return sanitize_expression.clean_var_ref(var_ref)


def get_full_expr(source_file, line_number):
    with open(f"linux-5.15.152/{source_file}", "r") as f:
        expr = ""
        open_comments = 0
        prev_define = False
        for i, line in enumerate(f):
            if "/*" in line:
                open_comments += 1
            if "*/" in line:
                open_comments -= 1
            if open_comments > 0:
                continue

            line = sanitize_expression.remove_comments_and_strip(line)
            if len(line) == 0:
                continue

            if line[-1] == "\\":
                curr_define = True
                line = line[:-1].strip()
                if len(line) == 0:
                    prev_define = True
                    continue
            else:
                curr_define = False

            if line[0] == "#":
                expr = ""
            elif len(expr) > 0 and expr[len(expr) - 1] == "(":
                expr += line
            else:
                expr += (" " + line)

            if i + 1 >= line_number:
                if line[-1] == ";" or line[-1] == "{" or line[-1] == "}" or (prev_define and line[-1] == ")"):
                    break
            elif (line[-1] == ";" or line[-1] == "{" or line[-1] == "}" or line[-2:] == "*/" or (prev_define and line[-1] == ")") or
                  (
                          check_expression.is_control_flow_expr(expr) and not check_expression.has_mismatched_parenthesis(expr))):
                expr = ""

            prev_define = curr_define
    print("full expression: " + expr)
    return expr


def get_func_from_src(source_file, func_name):
    with open(f"linux-5.15.152/{source_file}", "r") as f:
        func_start_line = None
        open_brackets = 0
        open_comments = 0
        bracket_found = False
        is_macro = False
        prev_define = False
        expr = ""
        for i, line in enumerate(f):
            if "/*" in line:
                open_comments += 1
            if "*/" in line:
                open_comments -= 1
            if open_comments > 0:
                continue

            line = sanitize_expression.remove_comments_and_strip(line)
            if len(line) == 0:
                continue

            if line[-1] == "\\":
                curr_define = True
                line = line[:-1].strip()
                if len(line) == 0:
                    prev_define = True
                    continue
            else:
                curr_define = False

            expr += " " + line

            if check_expression.is_var_declaration(func_name, expr):
                func_start_line = i + 1
                if "#define" in expr:
                    is_macro = True

            if len(line) > 0 and (line[0] == "#" or line[-1] == "{" or line[-1] == "}" or line[-1] == ";" or
                                  (prev_define and line[-1] == ")")):
                expr = ""

            if func_start_line is not None:
                if "{" in line:
                    open_brackets += 1
                    bracket_found = True
                if "}" in line:
                    open_brackets -= 1
                if (open_brackets == 0 and bracket_found and not is_macro) or (is_macro and not curr_define):
                    return func_start_line, i + 1

            prev_define = curr_define


def get_func_end_line(source_file, func_start_line):
    with open(f"linux-5.15.152/{source_file}", "r") as f:
        open_brackets = 0
        open_comments = 0
        bracket_found = False
        is_macro = False
        for i, line in enumerate(f):
            if "/*" in line:
                open_comments += 1
            if "*/" in line:
                open_comments -= 1
            if open_comments > 0:
                continue

            line = sanitize_expression.remove_comments_and_strip(line)
            if i + 1 == func_start_line and "#define" in line:
                is_macro = True
            if i + 1 >= func_start_line:
                if "{" in line:
                    open_brackets += 1
                    bracket_found = True
                if "}" in line:
                    open_brackets -= 1
                if (open_brackets == 0 and bracket_found and not is_macro) or (is_macro and line[-1] != "\\"):
                    return i + 1
