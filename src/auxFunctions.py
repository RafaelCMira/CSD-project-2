# region Aux Aux functions
from models import (
    Params,
)


def __is_node_safe(score: float, s_star: float, alpha_params: Params) -> bool:
    return (score >= s_star * alpha_params.safe_upper) and (
        (1 - score) <= (1 - s_star) * alpha_params.safe_lower
    )


def __is_node_acceptable(score: float, s_star: float, alpha_params: Params) -> bool:
    return (score >= s_star * alpha_params.accept_upper) and (
        (1 - score) <= (1 - s_star) * alpha_params.accept_lower
    )
