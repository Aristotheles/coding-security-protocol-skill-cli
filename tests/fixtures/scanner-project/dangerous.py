"""Deliberately vulnerable fixture; never import or execute."""
fixture_secret = "TEST_ONLY_DO_NOT_USE_FIXTURE"

def unsafe_expression(user_input):
    return eval(user_input)
