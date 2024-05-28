import re
import check_expression


def extract_varname(var_name):
    while var_name[0] in check_expression.C_UNARY_OPERANDS:
        var_name = var_name[1:]
    if var_name[-1] == "]":
        # TODO: check if variable is inside the brackets
        var_name = var_name[:var_name.find("[")]
    if "(" in var_name:
        var_name = peel_parenthesis(var_name)
        var_name = remove_casts(var_name)
    while var_name[-1] in check_expression.C_UNARY_OPERANDS or var_name[-1] == "+":
        var_name = var_name[:-1]
    return var_name


def peel_parenthesis(var_ref):
    if var_ref[0] == "(":
        expr_end = check_expression.recur_with_parenthesis(var_ref, 1, "(")
        if expr_end == len(var_ref) - 1:
            return var_ref[1:-1]
    return var_ref


def remove_comments_and_strip(line):
    if "//" in line:
        line = line[:line.find("//")].strip()
    elif "/*" in line:
        line = line[:line.find("/*")].strip()

    return remove_strings(line).strip()


def remove_sizeof(var_ref):
    sizeofs = [m.start() for m in re.finditer("sizeof", var_ref)]
    args_indices = []
    for sizeof in sizeofs:
        arg_start = sizeof + len("sizeof")
        if arg_start < len(var_ref) and var_ref[arg_start] == "(":
            args_end = check_expression.recur_with_parenthesis(var_ref, arg_start + 1, "(")
            args_indices.append((arg_start + 1, args_end))

    return remove_substring(var_ref, args_indices)


def remove_strings(var_ref):
    quotes_indices = [m.start() for m in re.finditer("\"", var_ref)]
    quote_literals = [m.start() for m in re.finditer("'\"'", var_ref)]
    escaped_quotes = [m.start() for m in re.finditer("\\\\\"", var_ref)]
    escaped_slashes = [m.start() for m in re.finditer("\\\\", var_ref)]
    comments_indices = [x for x in quotes_indices if
                        (x - 1 not in quote_literals and (x - 1 not in escaped_quotes or x in escaped_slashes))]

    remainder_quote = None
    if len(comments_indices) % 2 != 0:
        remainder_quote = comments_indices[-1]
        comments_indices = comments_indices[:-1]

    offset = 0
    for i in range(0, len(comments_indices), 2):
        quote_start = quotes_indices[i] - offset
        quote_end = quotes_indices[i+1] - offset
        var_ref = var_ref[:quote_start + 1] + var_ref[quote_end:]
        offset += quote_end - quote_start - 1

    if remainder_quote is not None:
        remainder_quote -= offset
        var_ref = var_ref[:remainder_quote + 1]

    return var_ref


def remove_casts(var_ref):
    cast_list = []
    curr_char = 0
    while curr_char < len(var_ref):
        if var_ref[curr_char] == "(":
            expr_end = check_expression.recur_with_parenthesis(var_ref, curr_char + 1, "(")
            expr = var_ref[curr_char:expr_end + 1]
            has_star = False
            has_operand = False
            for operand in check_expression.C_OPERANDS:
                if operand in expr:
                    if operand == "*":
                        has_star = True
                    else:
                        has_operand = True
            if has_star:
                star_indices = [m.start() for m in re.finditer("\\*", var_ref)]
                if len(star_indices) > 1 or star_indices[0] != expr_end - 1:
                    has_operand = True

            is_cast = False
            next_char = expr_end + 1
            if not has_operand:
                while next_char < len(var_ref) and var_ref[next_char].isspace():
                    next_char += 1
                if next_char >= len(var_ref):
                    break

                if var_ref[next_char] == "*" or var_ref[next_char] == "&":
                    #TODO: check if it really a cast or not
                    pass
                elif var_ref[next_char] == "-" and var_ref[next_char + 1] == ">":
                    next_char += 2
                elif (((var_ref[next_char] in check_expression.C_UNARY_OPERANDS) or
                       (var_ref[next_char] not in check_expression.C_OPERANDS)) and
                      var_ref[next_char] != "[" and var_ref[next_char] != "]"):
                    is_cast = True

            if is_cast:
                cast_list.append((curr_char, expr_end + 1))

        curr_char += 1

    return remove_substring(var_ref, cast_list)


def remove_substring(var_ref, substring_indices):
    offset = 0
    for substring_start, substring_end in substring_indices:
        var_ref = var_ref[:(substring_start + offset)] + var_ref[(substring_end + offset):]
        offset += (substring_end - substring_start) + 1

    return var_ref


def clean_var_ref(var_ref):
    return remove_sizeof(remove_strings(var_ref)).strip()
