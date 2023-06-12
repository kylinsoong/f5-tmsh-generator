 
def find_in_list(lst, val):
    for i in range(len(lst)):
        if lst[i] == val:
            return i
    return -1

 
def check_list_length(lst):
    if len(lst) > 1:
        return True
    else:
        return False

    def check_variable_type(variable):
        if isinstance(variable, str):
            return True
        else:
            return False

 
def convert_string_to_int(string):
    try:
        integer = int(string)
        return integer
    except ValueError:
        return None

 
def convert_to_string(variable):
    return str(variable)

 
def divide_by_zero(num1, num2):
    try:
        result = num1/num2
        return result
    except ZeroDivisionError:
        return None








