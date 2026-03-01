"""A simple clean project with no security findings."""


def greet(name: str) -> str:
    return f"Hello, {name}!"


def add(a: int, b: int) -> int:
    return a + b


if __name__ == "__main__":
    print(greet("world"))
